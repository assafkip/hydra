import { describe, it, expect } from "vitest";
import { buildGraphModel } from "../../src/graph/model.js";
import type { Finding, GateVerdict } from "../../src/agent/gate.js";
import type { InvestigateResult } from "../../src/agent/loop.js";

// PRD-7 p7-graph-model: the graph model is GATE-FAITHFUL. It must never trust the
// promoted/leads lists blindly — it re-runs isAdmissible() on every entity and
// re-runs promotionGate() on every promoted finding (codex-1, codex-3). Layout is
// deterministic (no Math.random / no Date) so positions are reproducible.

function result(
  promoted: Finding[],
  leads: { finding: Finding; verdict: GateVerdict }[],
): InvestigateResult {
  return { steps: [], promoted, leads, relationships: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", worked: true };
}

function lead(f: Finding, reason = "held — lead"): { finding: Finding; verdict: GateVerdict } {
  return { finding: f, verdict: { promote: false, grade: "C", reason } };
}

describe("buildGraphModel", () => {
  it("happy path: objective + one promoted IP + one name-only lead = 3 nodes, 2 radial edges", () => {
    const m = buildGraphModel("Investigate example.com", result(
      [{ entity: "93.184.216.34", entity_type: "ip", source_count: 2, infra_source_count: 2 }],
      [lead({ entity: "Jane Roe", entity_type: "person" }, "person/handle with no crosslink — lead")],
    ));

    expect(m.nodes).toHaveLength(3);
    const objective = m.nodes.find((n) => n.kind === "objective")!;
    expect(objective.label).toBe("Investigate example.com");

    const ip = m.nodes.find((n) => n.entityType === "ip")!;
    expect(ip.kind).toBe("finding");
    expect(ip.promoted).toBe(true);
    expect(ip.grade).toBe("A"); // infra >= 2

    const person = m.nodes.find((n) => n.entityType === "person")!;
    expect(person.kind).toBe("lead");
    expect(person.promoted).toBe(false);
    expect(person.reason).toContain("crosslink");

    expect(m.edges).toHaveLength(2);
    expect(m.edges.every((e) => e.from === objective.id)).toBe(true);
    const ipEdge = m.edges.find((e) => e.to === ip.id)!;
    expect(ipEdge.kind).toBe("promoted");
    expect(m.edges.find((e) => e.to === person.id)!.kind).toBe("lead");
  });

  it("empty result yields only the objective node and zero edges (no throw)", () => {
    const m = buildGraphModel("nothing here", result([], []));
    expect(m.nodes).toHaveLength(1);
    expect(m.nodes[0].kind).toBe("objective");
    expect(m.edges).toHaveLength(0);
  });

  it("a finding/lead with a blank or non-string entity yields no node", () => {
    const m = buildGraphModel("obj", result(
      [{ entity: "", entity_type: "ip" }, { entity_type: "domain" } as unknown as Finding],
      [lead({ entity: "   ", entity_type: "person" }), lead({ entity: 42 as unknown as string, entity_type: "person" })],
    ));
    expect(m.nodes).toHaveLength(1); // objective only
    expect(m.edges).toHaveLength(0);
  });

  it("inadmissible leads (CSS @-rule, YYYYMMDD date, noise domain, too-short) are OMITTED (codex-1)", () => {
    const m = buildGraphModel("obj", result([], [
      lead({ entity: "@media screen", entity_type: "domain" }),
      lead({ entity: "20240114", entity_type: "date" }),
      lead({ entity: "iana.org", entity_type: "domain" }),
      lead({ entity: "ab", entity_type: "person" }),
    ]));
    expect(m.nodes).toHaveLength(1); // none admissible -> objective only
    expect(m.edges).toHaveLength(0);
  });

  it("a forged 'promoted' finding that no longer promotes is DEMOTED to a lead node (codex-3)", () => {
    const m = buildGraphModel("obj", result(
      [{ entity: "5.5.5.5", entity_type: "ip", claim_unverified: true, source_count: 1, infra_source_count: 1 }],
      [],
    ));
    const ip = m.nodes.find((n) => n.entityType === "ip")!;
    expect(ip).toBeDefined();
    expect(ip.kind).toBe("lead"); // claim_unverified -> grade D -> not promoted
    expect(ip.promoted).toBe(false);
    expect(m.edges.find((e) => e.to === ip.id)!.kind).toBe("lead");
  });

  it("two promoted findings with the SAME entity render as two distinct nodes + edges (codex-4)", () => {
    const dup = (): Finding => ({ entity: "dup.com", entity_type: "domain", source_count: 1, infra_source_count: 1 });
    const m = buildGraphModel("obj", result([dup(), dup()], []));
    const findings = m.nodes.filter((n) => n.kind === "finding");
    expect(findings).toHaveLength(2);
    expect(findings[0].id).not.toBe(findings[1].id);
    expect(m.edges).toHaveLength(2);
    expect(new Set(m.edges.map((e) => e.to)).size).toBe(2);
  });
});
