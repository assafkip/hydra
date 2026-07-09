import { describe, it, expect } from "vitest";
import { canonKey, type EntityStore, type EntityRecord } from "../../src/entity/db.js";
import type { GraphModel } from "../../src/graph/model.js";
import {
  isValidCorrection,
  applyCorrections,
  applyCorrectionsToModel,
  type CorrectionMap,
} from "../../src/entity/corrections.js";

// ca-core (codex D1-D5): the pure corrections projection. A correction re-labels role / (display) type
// of an EXISTING entity by canonKey; it never rekeys identity, never changes grade/promotion, never
// adds a node. New symbols (negative self-test).

const rec = (type: string, value: string, role: string): EntityRecord => ({
  ref: { type, value },
  label: value,
  type,
  role,
  promoted: true,
  grade: "A",
  sourceCount: 2,
  infraSourceCount: 2,
  runs: ["run:x"],
  reasons: [],
});
function store(recs: EntityRecord[]): EntityStore {
  const entities: Record<string, EntityRecord> = {};
  for (const r of recs) entities[canonKey(r.ref.type, r.ref.value)] = r;
  return { entities, connections: {}, cooccurTruncated: false };
}

describe("ca-core — corrections projection", () => {
  it("canonKey aliases + lowercases so the key is uniform (D3)", () => {
    expect(canonKey("ip_address", "1.2.3.4")).toBe(canonKey("ip", "1.2.3.4"));
    expect(canonKey("domain", "Example.COM")).toBe(canonKey("domain", "example.com"));
  });

  it("isValidCorrection enforces the predicate + allowlist", () => {
    expect(isValidCorrection("role", "operator")).toBe(true);
    expect(isValidCorrection("role", "banana")).toBe(false);
    expect(isValidCorrection("type", "url")).toBe(true);
    expect(isValidCorrection("type", "banana")).toBe(false);
    expect(isValidCorrection("foo", "operator")).toBe(false);
  });

  it("a role correction overrides record.role only — ref/grade/promoted untouched (D2)", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const map: CorrectionMap = { [canonKey("domain", "example.com")]: { role: "source" } };
    const out = applyCorrections(s, map);
    const r = out.entities[canonKey("domain", "example.com")];
    expect(r.role).toBe("source");
    expect(r.ref).toEqual({ type: "domain", value: "example.com" }); // identity unchanged
    expect(r.grade).toBe("A");
    expect(r.promoted).toBe(true);
    expect(r.sourceCount).toBe(2);
    // the input store is not mutated (pure)
    expect(s.entities[canonKey("domain", "example.com")].role).toBe("ioc");
  });

  it("a type correction overrides display type but NOT ref (lookup by the original key still resolves, D2)", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const key = canonKey("domain", "example.com");
    const out = applyCorrections(s, { [key]: { type: "url" } });
    const r = out.entities[key]; // SAME key (ref unchanged)
    expect(r).toBeDefined();
    expect(r.type).toBe("url");
    expect(r.ref).toEqual({ type: "domain", value: "example.com" });
  });

  it("an unmatched correction is a no-op", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const out = applyCorrections(s, { [canonKey("ip", "9.9.9.9")]: { role: "infra" } });
    expect(out.entities[canonKey("domain", "example.com")].role).toBe("ioc");
  });

  it("applyCorrectionsToModel overrides node.role / node.entityType by canonKey, adds no node (D1/D2)", () => {
    const model: GraphModel = {
      objective: "dig",
      nodes: [
        { id: "objective", label: "dig", kind: "objective", promoted: false },
        { id: "finding:0:domain:example.com", label: "example.com", kind: "finding", promoted: true, entityType: "domain" },
      ],
      edges: [],
    };
    const out = applyCorrectionsToModel(model, { [canonKey("domain", "example.com")]: { role: "source", type: "url" } });
    expect(out.nodes).toHaveLength(2);
    const n = out.nodes.find((x) => x.label === "example.com")!;
    expect(n.role).toBe("source");
    expect(n.entityType).toBe("url");
    // the objective node is untouched
    expect(out.nodes[0].kind).toBe("objective");
  });
});
