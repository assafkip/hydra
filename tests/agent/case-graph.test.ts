import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, graphModelForRun, graphModelForCase, graphModelForRunNetwork, growCaseGraph, FILE_SOURCE_KIND } from "../../src/agent/session.js";
import { emptyObjectiveGraphModel, type GraphModel } from "../../src/graph/model.js";
import { MAX_COOCCUR_ENTITIES } from "../../src/entity/db.js";
import type { InvestigateResult } from "../../src/agent/loop.js";

// gh-case-model (parity G1): the whole-case graph folds ALL run: records via the gate-faithful
// mergeGraphModel under one objective node, redacting ALL secrets at the session layer. These tests
// drive the public graphModelForCase + graphModelForRun (no internals).

const MIXED = "sk-ant-" + "AbCdEfGhIjKlMnOp012345";
const LOWER = MIXED.toLowerCase();
const PROVIDER = "shodanKEY01234567ABCDEF";

async function vaultWithKey(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, MIXED);
  return vault;
}

function entityNodeSet(model: GraphModel): Set<string> {
  return new Set(model.nodes.filter((n) => n.kind !== "objective").map((n) => `${n.entityType}|${n.label}`));
}

const RUN_A = {
  objective: "Investigate acme.io",
  steps: [],
  promoted: [
    { entity: "1.2.3.4", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
    { entity: "acme.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
  ],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("graphModelForCase — folds runs, gate-faithful, dedup", () => {
  it("zero runs -> null", async () => {
    const vault = await vaultWithKey();
    expect(graphModelForCase(vault)).toBeNull();
  });

  it("single run -> same finding/lead entity-node SET as graphModelForRun (D3) + folds into the base (D1)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A);
    const caseModel = graphModelForCase(vault)!;
    expect(caseModel).toBeTruthy();
    // proves the fold actually added nodes (objective id matched — D1): more than the bare objective node
    expect(caseModel.nodes.filter((n) => n.kind !== "objective").length).toBeGreaterThan(0);
    const runModel = graphModelForRun(vault, RUN_A.objective, RUN_A as unknown as InvestigateResult);
    expect(entityNodeSet(caseModel)).toEqual(entityNodeSet(runModel));
    // single run keeps its own objective label
    expect(caseModel.objective).toBe("Investigate acme.io");
  });

  it("two runs sharing an entity -> ONE node for it (dedup, not duplicate); co-occurrence draws NO edge", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A);
    await vault.put("run:Investigate beta.io", {
      ...RUN_A,
      objective: "Investigate beta.io",
      promoted: [
        { entity: "1.2.3.4", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }, // SHARED
        { entity: "beta.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
      ],
    });
    const model = graphModelForCase(vault)!;
    const ipNodes = model.nodes.filter((n) => n.label === "1.2.3.4");
    expect(ipNodes).toHaveLength(1); // deduped across runs (ONE node, not a duplicate)
    expect(model.objective).toBe("All runs (2)"); // the label FIELD (not a node) is unchanged
    // founder 2026-06-24 (no-cooccurrence-edges): the shared ip co-occurs with acme.io/beta.io, but
    // co-occurrence is NOT a relationship — it draws NO edge. With no real typed link in these runs, the
    // graph carries no co_occurs edge (the dedup is what makes the shared ip ONE node).
    expect(model.edges.some((e) => e.kind === "co_occurs")).toBe(false);
    expect(model.nodes.some((n) => n.kind === "objective")).toBe(false); // no hub on the case graph
  });

  it("redacts ALL secrets (Anthropic key + provider key, lowercased) from the model (D7)", async () => {
    const vault = await vaultWithKey();
    await vault.put("secret:shodan_key", PROVIDER); // a configured provider secret
    await vault.put("run:Investigate good.io", {
      ...RUN_A,
      objective: "Investigate good.io",
      promoted: [
        { entity: `evil-${LOWER}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
        { entity: `evil-${PROVIDER.toLowerCase()}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      ],
    });
    const json = JSON.stringify(graphModelForCase(vault));
    expect(json).not.toContain(LOWER);
    expect(json).not.toContain(MIXED);
    expect(json.toLowerCase()).not.toContain(PROVIDER.toLowerCase());
  });

  it("gate-faithful: a forged-promoted finding with no corroboration is demoted to a lead", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate forged.io", {
      ...RUN_A,
      objective: "Investigate forged.io",
      promoted: [{ entity: "9.9.9.9", entity_type: "ip", grade: "A", source_count: 0, infra_source_count: 0 }],
      leads: [],
    });
    const model = graphModelForCase(vault)!;
    const n = model.nodes.find((x) => x.label === "9.9.9.9");
    expect(n).toBeTruthy();
    expect(n!.promoted).toBe(false); // re-gated: a non-corroborated "promoted" is a lead
    expect(n!.kind).toBe("lead");
  });

  it("a lead upgraded to promoted across runs leaves NO stale lead edge (D2)", async () => {
    const vault = await vaultWithKey();
    // run 1: the ip appears with weak evidence (a lead)
    await vault.put("run:Investigate r1", {
      ...RUN_A,
      objective: "Investigate r1",
      promoted: [],
      leads: [{ finding: { entity: "5.5.5.5", entity_type: "ip", source_count: 0, infra_source_count: 0 }, verdict: { promote: false, grade: "D", reason: "lead" } }],
    });
    // run 2: the same ip now has strong corroboration (promotes)
    await vault.put("run:Investigate r2", {
      ...RUN_A,
      objective: "Investigate r2",
      promoted: [{ entity: "5.5.5.5", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [],
    });
    const model = graphModelForCase(vault)!;
    const node = model.nodes.find((x) => x.label === "5.5.5.5")!;
    expect(node.promoted).toBe(true); // upgraded across runs
    expect(node.kind).toBe("finding");
    // cg-network: the case graph has no objective spokes, so no edge carries the lead/promoted spoke
    // kind — there is no stale lead spoke to leave behind. Edges are entity↔entity only.
    expect(model.edges.every((e) => e.kind !== "lead" && e.kind !== "promoted")).toBe(true);
  });

  it("caps the fold and SURFACES it in the label (D9, no silent truncation)", async () => {
    const vault = await vaultWithKey();
    for (let i = 0; i < 51; i++) {
      await vault.put(`run:Investigate host${String(i).padStart(3, "0")}.io`, {
        ...RUN_A,
        objective: `Investigate host${String(i).padStart(3, "0")}.io`,
        promoted: [{ entity: `${i}.0.0.1`, entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }],
      });
    }
    const model = graphModelForCase(vault)!;
    expect(model.objective).toBe("All runs (50 of 51)");
  });
});

// gh-hydrate D5/D6: a just-completed run grows into the accumulated case graph from its IN-MEMORY
// result (not a vault re-read), redacted at the session layer + re-gated by mergeGraphModel.
describe("growCaseGraph — folds a run's IN-MEMORY result into the case graph", () => {
  const emptyBase = (): GraphModel => emptyObjectiveGraphModel("All runs (0)");

  it("grows from the in-memory result WITHOUT a vault re-read; a shared entity dedups (D6)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A); // run A persisted
    const base = graphModelForCase(vault)!; // base = run A only
    const before = base.nodes.length;

    // a fresh run's in-memory result — NEVER written to the vault (proves D6: no re-read)
    const fresh = {
      promoted: [
        { entity: "1.2.3.4", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }, // SHARED with run A
        { entity: "gamma.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 }, // NEW
      ],
      leads: [],
    } as unknown as InvestigateResult;

    const grown = growCaseGraph(vault, base, base.nodes[0].id, fresh);
    expect(grown.nodes.some((n) => n.label === "gamma.io")).toBe(true); // new entity on the graph though never persisted
    expect(grown.nodes.filter((n) => n.label === "1.2.3.4")).toHaveLength(1); // shared ip deduped, not duplicated
    expect(grown.nodes.length).toBeGreaterThan(before); // it grew
    expect(base.nodes.some((n) => n.label === "gamma.io")).toBe(false); // base never mutated
    const gamma = grown.nodes.find((n) => n.label === "gamma.io")!;
    expect(grown.edges.some((e) => e.from === base.nodes[0].id && e.to === gamma.id)).toBe(true); // hung off the objective
  });

  it("redacts ALL secrets from the in-memory result before the fold (D7)", async () => {
    const vault = await vaultWithKey();
    await vault.put("secret:shodan_key", PROVIDER);
    const base = emptyBase();
    const fresh = {
      promoted: [
        { entity: `evil-${LOWER}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
        { entity: `evil-${PROVIDER.toLowerCase()}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      ],
      leads: [],
    } as unknown as InvestigateResult;
    const json = JSON.stringify(growCaseGraph(vault, base, base.nodes[0].id, fresh));
    expect(json).not.toContain(LOWER);
    expect(json).not.toContain(MIXED);
    expect(json.toLowerCase()).not.toContain(PROVIDER.toLowerCase());
  });

  it("gate-faithful: a forged-promoted finding in the grown result is demoted to a lead", async () => {
    const vault = await vaultWithKey();
    const base = emptyBase();
    const fresh = {
      promoted: [{ entity: "9.9.9.9", entity_type: "ip", grade: "A", source_count: 0, infra_source_count: 0 }],
      leads: [],
    } as unknown as InvestigateResult;
    const grown = growCaseGraph(vault, base, base.nodes[0].id, fresh);
    const n = grown.nodes.find((x) => x.label === "9.9.9.9")!;
    expect(n.promoted).toBe(false);
    expect(n.kind).toBe("lead");
  });
});

// cg-network (PRD prd-case-graph): the home graph is an entity↔entity NETWORK (co-occurrence edges
// from a RUN's co-occurring entities) with NO objective hub and NO star spokes. The no-objective-hub
// topology is proven by the FIFA real-case model diff (fifa_model_diff.py); the entity-edge SET is
// carved out of that diff per the D1 graph carve-out (2026-06-24) — INTAKE co-occurrence edges are
// dropped by D2 (gated by d2-clump-repro). The objective node is stripped by graphModelForCase.
describe("graphModelForCase — entity↔entity network topology (cg-network)", () => {
  it("co-occurring entities in a run get NO edge (co-occurrence is not a relationship); no objective hub", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A); // 1.2.3.4 + acme.io promoted in ONE run → they co-occur
    const model = graphModelForCase(vault)!;
    expect(model.nodes.some((n) => n.kind === "objective")).toBe(false); // hub stripped (network-only)
    // founder 2026-06-24 (no-cooccurrence-edges): co-occurrence draws NO edge. Only a real typed `linked`
    // relationship does, and RUN_A has none — so the two co-occurring entities are NOT connected.
    expect(model.edges.some((e) => e.kind === "co_occurs")).toBe(false);
    const idByLabel = new Map(model.nodes.map((n) => [n.label, n.id]));
    const ip = idByLabel.get("1.2.3.4")!;
    const dom = idByLabel.get("acme.io")!;
    expect(
      model.edges.some((e) => (e.from === ip && e.to === dom) || (e.from === dom && e.to === ip)),
    ).toBe(false);
  });

  it("a file-only case (no agent runs) does not label the hub 'All runs (N)'", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:file: report one #aaa", { ...RUN_A, objective: "file: report one #aaa", sourceKind: FILE_SOURCE_KIND });
    await vault.put("run:file: report two #bbb", { ...RUN_A, objective: "file: report two #bbb", sourceKind: FILE_SOURCE_KIND });
    const model = graphModelForCase(vault)!;
    expect(model.objective).not.toMatch(/All runs/);
  });

  it("co_occurs projection carries no secret (redaction holds through the new edges)", async () => {
    const vault = await vaultWithKey();
    // an entity value that embeds the live API key — entityDbFor must scrub it before it reaches an edge
    await vault.put("run:Investigate leak", {
      ...RUN_A,
      objective: "Investigate leak",
      promoted: [
        { entity: `host-${MIXED}.io`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
        { entity: "5.6.7.8", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
      ],
    });
    const json = JSON.stringify(graphModelForCase(vault)!);
    expect(json).not.toContain(MIXED);
    expect(json).not.toContain(LOWER);
  });
});

// clu-graph-fit-cap: the entity↔entity network edge cap must be DETERMINISTIC — which edges survive
// must NOT depend on vault write/import order (codex on f8c2d845: the cap iterated entity-DB insertion
// order). Two vaults with the same logical co-occurrences inserted in REVERSED run order must produce
// an identical network-edge LIST (same order, not just same set — the cap takes a prefix).
describe("graphModelForCase — deterministic entity-network edge order (clu-graph-fit-cap)", () => {
  const RUN_P = {
    ...RUN_A,
    objective: "Investigate p.com",
    promoted: [
      { entity: "1.1.1.1", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "p.com", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
    ],
  };
  const RUN_Q = {
    ...RUN_A,
    objective: "Investigate q.com",
    promoted: [
      { entity: "2.2.2.2", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "q.com", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
    ],
  };
  // Each edge is canonicalized by sorted endpoint LABELS (node ids can differ across vaults); the ARRAY
  // ORDER across edges is what the determinism fix controls (the cap-prefix).
  const networkEdgeList = (model: GraphModel): string[] => {
    // cg-network: no objective hub; every edge is entity↔entity, so no objId filter is needed.
    const labelById = new Map(model.nodes.map((n) => [n.id, n.label]));
    return model.edges
      .map((e) => [labelById.get(e.from)!, labelById.get(e.to)!].sort().join("|") + `|${e.kind}`);
  };
  it("co-occurring-only runs yield NO co_occurs edges, deterministically (insertion-order independent)", async () => {
    const v1 = await vaultWithKey();
    await v1.put("run:Investigate p.com", RUN_P);
    await v1.put("run:Investigate q.com", RUN_Q);
    const v2 = await vaultWithKey();
    await v2.put("run:Investigate q.com", RUN_Q);
    await v2.put("run:Investigate p.com", RUN_P);
    const e1 = networkEdgeList(graphModelForCase(v1)!);
    const e2 = networkEdgeList(graphModelForCase(v2)!);
    // founder 2026-06-24 (no-cooccurrence-edges): co-occurring entities draw no edge; runs with no typed
    // relationship yield NO co_occurs edges, identical regardless of insertion order.
    expect(e1.filter((s) => s.endsWith("|co_occurs"))).toEqual([]);
    expect(e1).toEqual(e2);
  });
});

// clu-graph-node-parity: node provenance — a file-ingest entity is "intake" (solid border in the graph),
// an agent-run entity is "osint" (dashed); intake wins when an entity appears in both.
describe("graphModelForCase — node origin/provenance (clu-graph-node-parity)", () => {
  const AGENT = {
    ...RUN_A,
    objective: "Investigate osint-only",
    promoted: [
      { entity: "9.9.9.9", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "shared.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
    ],
  };
  const FILE = {
    ...RUN_A,
    objective: "file: report #zz",
    sourceKind: FILE_SOURCE_KIND,
    promoted: [
      { entity: "intake-only.net", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
      { entity: "shared.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
    ],
  };
  it("intake from a file ingest, osint from an agent run, intake wins on a shared entity", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate osint-only", AGENT);
    await vault.put("run:file: report #zz", FILE);
    const m = graphModelForCase(vault)!;
    const byLabel = new Map(m.nodes.map((n) => [n.label, n]));
    expect(byLabel.get("intake-only.net")!.origin).toBe("intake"); // only in the file ingest
    expect(byLabel.get("9.9.9.9")!.origin).toBe("osint"); // only in the agent run
    expect(byLabel.get("shared.io")!.origin).toBe("intake"); // in BOTH → intake wins
  });
});

// sp-9ef4fa65: cap-parity at scale. The remount (graphModelForCase → withEntityNetworkEdges) bounds the
// per-run co-occurrence clique at MAX_COOCCUR_ENTITIES (slice before pairing) + MAX_NETWORK_EDGES total.
// growCaseNetwork / graphModelForRunNetwork (the first-paint + 2nd-run grow) built an UNCAPPED O(n²)
// clique, so a single run with >MAX_COOCCUR_ENTITIES findings first-painted MORE edges than the remount
// renders. After the fix the two paths must produce the IDENTICAL co_occurs count for the same data.
describe("graphModelForRunNetwork / growCaseNetwork — cap-parity at scale (sp-9ef4fa65)", () => {
  it("first-paint co-occurrence is capped to MAX_COOCCUR_ENTITIES, matching the remount", async () => {
    const vault = await vaultWithKey();
    const N = MAX_COOCCUR_ENTITIES + 12; // 60 > 48 → an uncapped clique would over-draw vs the remount
    const promoted = [];
    for (let i = 0; i < N; i++) {
      promoted.push({ entity: `e${String(i).padStart(3, "0")}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 });
    }
    const objective = "Investigate huge.io";
    const result = { promoted, leads: [] } as unknown as InvestigateResult;

    // REMOUNT (authoritative, already capped): persist the run, project the case graph.
    await vault.put(`run:${objective}`, { ...RUN_A, objective, promoted, leads: [] });
    const remountCoOccurs = graphModelForCase(vault)!.edges.filter((e) => e.kind === "co_occurs").length;

    // FIRST-PAINT / GROW (the path under test): fold the SAME in-memory result onto an empty network base.
    const growCoOccurs = graphModelForRunNetwork(vault, objective, result).edges.filter((e) => e.kind === "co_occurs").length;

    // founder 2026-06-24 (no-cooccurrence-edges): co-occurrence draws NO edge from EITHER path, even at
    // scale — the all-pairs clique (formerly C(48,2)=1128 capped) is gone entirely.
    expect(remountCoOccurs).toBe(0);
    expect(growCoOccurs).toBe(0);
    expect(growCoOccurs).toBe(remountCoOccurs); // grow/first-paint == remount (both zero)
  });

  // codex (issue review): the cap must slice the first MAX_COOCCUR_ENTITIES DISTINCT entities, like
  // buildEntityDb's seenInRun — not raw candidate slots. Duplicate findings (same canonical entity) must
  // NOT consume cap slots, or grow renders fewer/different co_occurs than the remount.
  it("duplicate findings do not consume cap slots — grow still matches the remount", async () => {
    const vault = await vaultWithKey();
    const distinct = 30;
    const promoted: { entity: string; entity_type: string; grade: string; source_count: number; infra_source_count: number }[] = [];
    // FRONT-load 30 copies of ONE entity, then 30 distinct ones → 60 candidates, 31 distinct (all < cap).
    for (let i = 0; i < 30; i++) promoted.push({ entity: "dup.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 });
    for (let i = 0; i < distinct; i++) promoted.push({ entity: `d${String(i).padStart(3, "0")}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 });
    const objective = "Investigate dups.io";
    const result = { promoted, leads: [] } as unknown as InvestigateResult;

    await vault.put(`run:${objective}`, { ...RUN_A, objective, promoted, leads: [] });
    const remountCoOccurs = graphModelForCase(vault)!.edges.filter((e) => e.kind === "co_occurs").length;
    const growCoOccurs = graphModelForRunNetwork(vault, objective, result).edges.filter((e) => e.kind === "co_occurs").length;

    // founder 2026-06-24 (no-cooccurrence-edges): both paths draw ZERO co_occurs edges regardless of
    // duplicate findings — there is no co-occurrence clique anymore.
    expect(remountCoOccurs).toBe(0);
    expect(growCoOccurs).toBe(remountCoOccurs); // both zero
  });
});
