import { describe, it, expect } from "vitest";
import {
  REL_TYPES,
  STRONG_ATTRIBUTION,
  ATTRIBUTION_DEMOTED,
  canonRelType,
  gateAttribution,
  connId,
  buildRelationsPrompt,
  parseSemanticRelations,
  relatableConnections,
} from "../../src/entity/relations.js";
import type { Connection, EntityRef } from "../../src/entity/db.js";

// adr-pass: the semantic typed-relations pass is GATE-FAITHFUL — the model may only re-label an
// EXISTING gated connection (out-of-vocabulary -> linked; unknown cid -> dropped) and a
// strong-attribution label is confidence-gated exactly like analyze.py::gate_attribution.

const owner: EntityRef = { type: "domain", value: "evil.com" };

function conn(otherType: string, otherValue: string, relType: Connection["relType"], direction: Connection["direction"]): Connection {
  return {
    other: { type: otherType, value: otherValue },
    otherLabel: otherValue,
    otherType,
    otherRole: "infra",
    relType,
    direction,
    confidence: "medium",
    runs: ["r1"],
    count: 1,
  };
}

describe("gateAttribution (1:1 port of analyze.py::gate_attribution)", () => {
  it("strong-attribution: low -> drop, medium -> co_listed, high -> keep", () => {
    expect(gateAttribution("same_operator", "low")).toBeNull();
    expect(gateAttribution("same_operator", "medium")).toBe(ATTRIBUTION_DEMOTED);
    expect(gateAttribution("same_operator", "high")).toBe("same_operator");
  });
  it("non-attribution labels pass through at any confidence", () => {
    expect(gateAttribution("hosts", "low")).toBe("hosts");
    expect(gateAttribution("resolves_to", "medium")).toBe("resolves_to");
  });
  it("every STRONG_ATTRIBUTION label is in the allowlist", () => {
    for (const s of STRONG_ATTRIBUTION) expect(REL_TYPES).toContain(s);
  });
});

describe("canonRelType (hard allowlist + synonym folding — codex D1)", () => {
  it("folds an attribution synonym onto the gated canonical label", () => {
    expect(canonRelType("shared_operator")).toBe("same_operator");
    expect(canonRelType("common_control")).toBe("same_operator");
    expect(canonRelType("same_registrant")).toBe("same_operator");
    expect(canonRelType("same_wallet_owner")).toBe("same_operator");
  });
  it("canonicalizes a non-attribution spelling variant", () => {
    expect(canonRelType("hosted_by")).toBe("hosted_on");
    expect(canonRelType("registered")).toBe("registered_by");
  });
  it("normalizes an out-of-vocabulary label to 'linked' (never raw)", () => {
    expect(canonRelType("totally_made_up")).toBe("linked");
    expect(canonRelType("")).toBe("linked");
    expect(canonRelType("OWNS!!")).toBe("owns"); // snake-collapse + allowlisted
  });
});

describe("connId (stable id — codex D2)", () => {
  it("is deterministic and distinguishes endpoints/relTypes/direction", () => {
    const a = conn("ip", "1.1.1.1", "co_occurs", "undirected");
    const b = conn("ip", "1.1.1.1", "linked", "out");
    expect(connId(owner, a)).toBe(connId(owner, a)); // deterministic
    expect(connId(owner, a)).not.toBe(connId(owner, b)); // relType/direction differ
  });
});

describe("buildRelationsPrompt", () => {
  it("lists only entity↔entity connections with their cid, excludes surfaced_in", () => {
    const c1 = conn("ip", "1.1.1.1", "co_occurs", "undirected");
    const seedEdge = conn("objective", "investigate evil.com", "surfaced_in", "in");
    const prompt = buildRelationsPrompt(owner, "evil.com", [c1, seedEdge]);
    // the cid is embedded JSON-escaped inside a JSON line, so check the escaped form
    expect(prompt).toContain(JSON.stringify(connId(owner, c1)));
    expect(prompt).not.toContain(JSON.stringify(connId(owner, seedEdge))); // the objective edge is not relatable
    expect(prompt).toContain("STRICT JSON");
    expect(relatableConnections([c1, seedEdge])).toEqual([c1]);
  });
});

describe("parseSemanticRelations (validation + gate)", () => {
  const c0 = conn("ip", "1.1.1.1", "co_occurs", "undirected"); // will get same_operator (gated)
  const c1 = conn("domain", "host.com", "co_occurs", "undirected"); // will get hosts (kept)
  const conns = [c0, c1];

  it("keeps a non-attribution label, drops a low-confidence attribution, drops an unknown cid", () => {
    const model = JSON.stringify({
      relations: [
        { cid: connId(owner, c0), rel_type: "same_operator", confidence: "low", evidence: "weak" }, // gate -> drop
        { cid: connId(owner, c1), rel_type: "hosts", confidence: "high", evidence: "ns record" }, // keep
        { cid: "[\"domain\",\"evil.com\",\"x\",\"y\",\"linked\",\"out\"]", rel_type: "owns", confidence: "high" }, // unknown cid -> drop
      ],
    });
    const rels = parseSemanticRelations(owner, model, conns);
    expect(rels).toHaveLength(1);
    expect(rels[0].cid).toBe(connId(owner, c1));
    expect(rels[0].relType).toBe("hosts");
  });

  it("a low-confidence SYNONYM (shared_operator) is canon-folded then gate-dropped (D1)", () => {
    const model = JSON.stringify({ relations: [{ cid: connId(owner, c0), rel_type: "shared_operator", confidence: "low" }] });
    expect(parseSemanticRelations(owner, model, conns)).toHaveLength(0);
  });

  it("a medium attribution is demoted to co_listed", () => {
    const model = JSON.stringify({ relations: [{ cid: connId(owner, c0), rel_type: "same_operator", confidence: "medium" }] });
    const rels = parseSemanticRelations(owner, model, conns);
    expect(rels).toHaveLength(1);
    expect(rels[0].relType).toBe(ATTRIBUTION_DEMOTED);
  });

  it("an unknown raw rel_type normalizes to 'linked', never raw", () => {
    const model = JSON.stringify({ relations: [{ cid: connId(owner, c1), rel_type: "frobnicates", confidence: "high" }] });
    const rels = parseSemanticRelations(owner, model, conns);
    expect(rels).toHaveLength(1);
    expect(rels[0].relType).toBe("linked");
  });

  it("dedups a repeated cid and yields zero on non-JSON", () => {
    const dup = JSON.stringify({ relations: [
      { cid: connId(owner, c1), rel_type: "hosts", confidence: "high" },
      { cid: connId(owner, c1), rel_type: "uses", confidence: "high" },
    ] });
    expect(parseSemanticRelations(owner, dup, conns)).toHaveLength(1);
    expect(parseSemanticRelations(owner, "not json at all", conns)).toHaveLength(0);
    expect(parseSemanticRelations(owner, "", conns)).toHaveLength(0);
  });
});
