import { describe, it, expect } from "vitest";
import { buildGraphModel, mergeGraphModel } from "../../src/graph/model.js";
import type { Finding, GateVerdict } from "../../src/agent/gate.js";
import type { InvestigateResult } from "../../src/agent/loop.js";

// PRD-8 p8-merge-model: mergeGraphModel grows the graph incrementally and is
// GATE-FAITHFUL (re-gates every addition; never trusts a supplied verdict). Dedup is
// alias-aware; an existing entity gets a cross-edge (not a duplicate node) and is
// upgraded in place when the new evidence is stronger; a missing parent is a no-op.

function result(promoted: Finding[], leads: { finding: Finding; verdict: GateVerdict }[] = []): InvestigateResult {
  return { steps: [], promoted, leads, relationships: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", worked: true };
}
function lead(f: Finding, reason = "held — lead"): { finding: Finding; verdict: GateVerdict } {
  return { finding: f, verdict: { promote: false, grade: "C", reason } };
}
const ip = (v: string, infra = 2): Finding => ({ entity: v, entity_type: "ip", source_count: infra, infra_source_count: infra });
const domain = (v: string, infra = 1): Finding => ({ entity: v, entity_type: "domain", source_count: infra, infra_source_count: infra });

function baseGraph(): InvestigateResult {
  return result([ip("1.1.1.1")]);
}
function parentId(m: ReturnType<typeof buildGraphModel>): string {
  return m.nodes.find((n) => n.entityType === "ip")!.id;
}

describe("mergeGraphModel", () => {
  it("adds new entities as new nodes with an edge from the parent (grow)", () => {
    const base = buildGraphModel("seed", baseGraph());
    const before = base.nodes.length;
    const from = parentId(base);
    const merged = mergeGraphModel(base, from, result([ip("2.2.2.2")]));

    expect(base.nodes).toHaveLength(before); // base not mutated
    const added = merged.nodes.find((n) => n.label === "2.2.2.2")!;
    expect(added.kind).toBe("finding");
    expect(merged.edges.some((e) => e.from === from && e.to === added.id)).toBe(true);
  });

  it("dedup hit: a hop surfacing an existing entity adds a cross-edge, NOT a duplicate node", () => {
    const base = buildGraphModel("seed", result([domain("dup.com")]));
    const from = base.nodes.find((n) => n.kind === "objective")!.id;
    const dupNode = base.nodes.find((n) => n.label === "dup.com")!;
    const merged = mergeGraphModel(base, from, result([domain("dup.com")]));

    expect(merged.nodes.filter((n) => n.label === "dup.com")).toHaveLength(1); // no duplicate
    expect(merged.edges.some((e) => e.from === from && e.to === dupNode.id)).toBe(true);
  });

  it("dedup is alias-aware (ip == ip_address)", () => {
    const base = buildGraphModel("seed", baseGraph()); // 1.1.1.1 as type ip
    const from = base.nodes.find((n) => n.kind === "objective")!.id;
    const merged = mergeGraphModel(base, from, result([{ entity: "1.1.1.1", entity_type: "ip_address", source_count: 2, infra_source_count: 2 }]));
    expect(merged.nodes.filter((n) => n.label === "1.1.1.1")).toHaveLength(1); // aliased -> deduped
  });

  it("upgrades an existing LEAD node in place when the hop promotes it (id preserved)", () => {
    const base = buildGraphModel("seed", result([], [lead(domain("up.com", 0))])); // held lead
    const leadNode = base.nodes.find((n) => n.label === "up.com")!;
    expect(leadNode.kind).toBe("lead");
    const from = parentId(buildGraphModel("x", baseGraph())); // any from on base? use objective
    const objId = base.nodes.find((n) => n.kind === "objective")!.id;

    const merged = mergeGraphModel(base, objId, result([domain("up.com", 2)])); // now promotes
    const upgraded = merged.nodes.find((n) => n.id === leadNode.id)!;
    expect(upgraded.kind).toBe("finding"); // upgraded in place
    expect(upgraded.promoted).toBe(true);
    expect(from).toBeDefined(); // (silence unused)
  });

  it("is gate-faithful: a forged lead verdict is ignored; the entity is re-gated", () => {
    const base = buildGraphModel("seed", baseGraph());
    const objId = base.nodes.find((n) => n.kind === "objective")!.id;
    // forged: claims promote:false grade D, but the entity has infra corroboration -> must promote
    const forged = { finding: ip("3.3.3.3", 2), verdict: { promote: false, grade: "D", reason: "forged" } as GateVerdict };
    const merged = mergeGraphModel(base, objId, result([], [forged]));
    const node = merged.nodes.find((n) => n.label === "3.3.3.3")!;
    expect(node.kind).toBe("finding"); // recomputed, not the forged "lead"
    expect(node.promoted).toBe(true);
  });

  it("omits an inadmissible addition (CSS @-rule)", () => {
    const base = buildGraphModel("seed", baseGraph());
    const objId = base.nodes.find((n) => n.kind === "objective")!.id;
    const merged = mergeGraphModel(base, objId, result([], [lead({ entity: "@media screen", entity_type: "domain" })]));
    expect(merged.nodes.some((n) => n.label === "@media screen")).toBe(false);
  });

  it("a missing fromNodeId is a no-op (base returned unchanged, no dangling edges)", () => {
    const base = buildGraphModel("seed", baseGraph());
    const merged = mergeGraphModel(base, "no-such-node", result([ip("4.4.4.4")]));
    expect(merged.nodes).toHaveLength(base.nodes.length);
    expect(merged.edges).toHaveLength(base.edges.length);
  });

  it("does not mutate base and never produces a dangling edge", () => {
    const base = buildGraphModel("seed", baseGraph());
    const beforeNodes = base.nodes.length;
    const beforeEdges = base.edges.length;
    const from = parentId(base);
    const merged = mergeGraphModel(base, from, result([ip("5.5.5.5"), domain("a.com")]));
    expect(base.nodes).toHaveLength(beforeNodes);
    expect(base.edges).toHaveLength(beforeEdges);
    const ids = new Set(merged.nodes.map((n) => n.id));
    for (const e of merged.edges) {
      expect(ids.has(e.from)).toBe(true);
      expect(ids.has(e.to)).toBe(true);
    }
  });

  it("edges are idempotent across a repeat expand (no duplicate edge, no duplicate node)", () => {
    const base = buildGraphModel("seed", baseGraph());
    const from = parentId(base);
    const once = mergeGraphModel(base, from, result([ip("6.6.6.6")]));
    const twice = mergeGraphModel(once, from, result([ip("6.6.6.6")]));
    expect(twice.nodes).toHaveLength(once.nodes.length);
    expect(twice.edges).toHaveLength(once.edges.length);
  });

  it("cross-edges to ALL matching nodes when base has duplicate-entity nodes", () => {
    // buildGraphModel keeps two same-entity promoted nodes (PRD-7 occurrence-indexed)
    const base = buildGraphModel("seed", result([domain("multi.com"), domain("multi.com")]));
    const objId = base.nodes.find((n) => n.kind === "objective")!.id;
    const matches = base.nodes.filter((n) => n.label === "multi.com");
    expect(matches).toHaveLength(2);
    const merged = mergeGraphModel(base, objId, result([domain("multi.com")]));
    // an edge from objId to BOTH existing multi.com nodes
    for (const m of matches) {
      expect(merged.edges.some((e) => e.from === objId && e.to === m.id)).toBe(true);
    }
    expect(merged.nodes.filter((n) => n.label === "multi.com")).toHaveLength(2); // still no new node
  });
});
