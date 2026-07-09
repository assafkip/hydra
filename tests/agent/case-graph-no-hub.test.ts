import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";

// Each test stands up a real Argon2id-KDF vault (~6-8s); 4 in parallel can exceed the 20s default
// under machine load, so this crypto-heavy file gets a 60s ceiling — a contention guard, not slow logic.
vi.setConfig({ testTimeout: 60_000 });
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, graphModelForCase, graphModelForRun, graphModelForRunNetwork, FILE_SOURCE_KIND } from "../../src/agent/session.js";
import type { InvestigateResult } from "../../src/agent/loop.js";

// cg-objective-guard (PRD prd-case-graph-2026-06-22, codex finding-3): the network-only case graph
// is a global invariant ("the home/case graph has NO objective hub and NO objective→entity spokes").
// An invariant with no enumerated targets + no guard is the recurring gap class that re-ships. This
// is the RATCHET: it asserts the invariant holds for representative single-run / multi-run / file-only
// vaults AND for the LIVE first-paint helper graphModelForRunNetwork (sp-77a52e2c — the home graph must
// be network-only on the FIRST in-session run too, not just on remount). It documents the ONE intended
// exception (graphModelForRun, a STANDALONE objective-rooted single-run projection no longer used for the
// live home graph — kept for a future run-detail view). If a future change re-introduces a case-graph
// hub on any of these paths, this fails.

const KEY = "sk-ant-" + "AbCdEfGhIjKlMnOp012345";

async function vaultWithKey(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  return vault;
}

const run = (objective: string, promoted: { entity: string; entity_type: string }[], sourceKind?: string) => ({
  objective,
  steps: [],
  promoted: promoted.map((p) => ({ ...p, grade: "A", source_count: 2, infra_source_count: 2 })),
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
  ...(sourceKind ? { sourceKind } : {}),
});

// The case-graph network-only invariant, enumerated from the MODEL itself (not a hand list of nodes):
// zero objective-kind nodes, and zero edges whose endpoint is an objective node (no surviving spoke).
// The conventional objective node id (model.ts OBJECTIVE_ID). Checked literally so a DANGLING spoke
// (an edge to "objective" left behind even if the hub node was stripped) is still caught — the line-43
// objective-node check alone goes vacuous when no objective node exists (codex).
const OBJECTIVE_ID = "objective";

function assertNoHub(model: { nodes: { id: string; kind: string }[]; edges: { from: string; to: string; kind: string }[] }): void {
  const objIds = new Set(model.nodes.filter((n) => n.kind === "objective").map((n) => n.id));
  expect(objIds.size, "case graph must have ZERO objective hub nodes").toBe(0);
  // no edge may reference an objective node id OR the conventional "objective" id (a dangling spoke),
  // and no spoke-kind edge (promoted/lead) may exist on the case graph.
  const incident = (id: string): boolean => objIds.has(id) || id === OBJECTIVE_ID;
  const spokeToHub = model.edges.filter((e) => incident(e.from) || incident(e.to));
  expect(spokeToHub, "case graph must have ZERO edges incident to an objective hub").toHaveLength(0);
  const spokeKinds = model.edges.filter((e) => e.kind === "promoted" || e.kind === "lead");
  expect(spokeKinds, "case graph must carry NO objective→entity spoke-kind edges").toHaveLength(0);
}

describe("cg-objective-guard — graphModelForCase is network-only (no objective hub) across vault shapes", () => {
  it("single agent run: no hub, no spokes", async () => {
    const v = await vaultWithKey();
    await v.put("run:Investigate acme.io", run("Investigate acme.io", [
      { entity: "1.2.3.4", entity_type: "ip" },
      { entity: "acme.io", entity_type: "domain" },
    ]));
    assertNoHub(graphModelForCase(v)!);
  });

  it("multiple agent runs (shared entity): no hub, no spokes", async () => {
    const v = await vaultWithKey();
    await v.put("run:Investigate acme.io", run("Investigate acme.io", [
      { entity: "1.2.3.4", entity_type: "ip" },
      { entity: "acme.io", entity_type: "domain" },
    ]));
    await v.put("run:Investigate beta.io", run("Investigate beta.io", [
      { entity: "1.2.3.4", entity_type: "ip" }, // shared
      { entity: "beta.io", entity_type: "domain" },
    ]));
    assertNoHub(graphModelForCase(v)!);
  });

  it("file-only case (no agent runs): no hub, no spokes", async () => {
    const v = await vaultWithKey();
    await v.put("run:file: report #aaa", run("file: report #aaa", [
      { entity: "intake.net", entity_type: "domain" },
      { entity: "5.6.7.8", entity_type: "ip" },
    ], FILE_SOURCE_KIND));
    assertNoHub(graphModelForCase(v)!);
  });

  it("first in-session paint (graphModelForRunNetwork) is network-only: no hub, no spokes (sp-77a52e2c)", async () => {
    const v = await vaultWithKey();
    const result = run("Investigate acme.io", [
      { entity: "1.2.3.4", entity_type: "ip" },
      { entity: "acme.io", entity_type: "domain" },
    ]) as unknown as InvestigateResult;
    // the LIVE first paint must match the remount (graphModelForCase) + the 2nd-run grow — no transient hub.
    assertNoHub(graphModelForRunNetwork(v, "Investigate acme.io", result));
  });

  it("documents the STANDALONE projection: graphModelForRun (NOT the live home graph) DOES keep its objective hub", async () => {
    const v = await vaultWithKey();
    const result = run("Investigate acme.io", [{ entity: "acme.io", entity_type: "domain" }]) as unknown as InvestigateResult;
    const runModel = graphModelForRun(v, "Investigate acme.io", result);
    // graphModelForRun is intentionally objective-rooted but is NO LONGER used for the live home graph
    // (renderRunGraph uses graphModelForRunNetwork now). Kept as a standalone single-run projection for a
    // future run-detail view; this makes the case-vs-run boundary explicit.
    expect(runModel.nodes.filter((n) => n.kind === "objective")).toHaveLength(1);
  });
});
