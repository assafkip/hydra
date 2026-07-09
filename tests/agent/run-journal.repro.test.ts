// REPRO (hydra ISSUE-1 + ISSUE-5, founder 2026-07-07): the live run graph is grown in memory only and made
// durable ONLY at finalize (run:<objective> persist). So an ABORT (skips finalize) or a RELOAD (kills the JS
// context) before finalize loses the whole in-flight graph — the founder sees the graph snap back to "Start
// here" mid-run, and a refresh wipes it. The fix journals the live model to a durable run-live key AS it grows,
// so hydrateCaseGraph rehydrates from it independent of finalize.
//
// This pins the persistence contract: a live-grown model must round-trip a reload via persist/read/clear.

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault";
import { memoryStorage } from "../../src/vault/store";
import { scopedVault, persistLiveRun, readLiveRun, clearLiveRun, graphModelForCase } from "../../src/agent/session";
import type { GraphModel } from "../../src/graph/model";

const CASE = "case-test";

function liveModel(): GraphModel {
  // a model shaped like one liveGrowObserved builds: the objective label + an entity lead node + its edge.
  return {
    objective: "who runs empresas.com?",
    nodes: [
      { id: "obj", label: "who runs empresas.com?", kind: "objective", promoted: false },
      { id: "n:empresas.com", label: "empresas.com", kind: "lead", promoted: false },
      { id: "n:godaddy", label: "GoDaddy", kind: "lead", promoted: false },
    ],
    edges: [{ from: "n:empresas.com", to: "n:godaddy", kind: "lead", relType: "registrar" }],
  };
}

describe("run journal persistence repro", () => {
  it("REPRO: today a live-grown graph has NO durable record before finalize (graphModelForCase is null)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    const sv = scopedVault(vault, CASE);
    // We grew a live model in memory (as liveGrowObserved does) but never finalized a run: record.
    // graphModelForCase folds run:<objective> records only → a mid-run reload rebuilds EMPTY. That is the bug.
    expect(graphModelForCase(sv)).toBeNull();
  });

  it("FIX: a journaled live model survives a reload (persist → new Vault → read round-trips)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    await persistLiveRun(scopedVault(vault, CASE), liveModel());

    // A new Vault reading the SAME storage = the F5 / abort-remount case.
    const reopened = await Vault.unlock(storage, "hunter2");
    const loaded = readLiveRun(scopedVault(reopened, CASE));
    expect(loaded).not.toBeNull();
    expect(loaded!.nodes.some((n) => n.label === "empresas.com")).toBe(true);
    expect(loaded!.nodes.some((n) => n.label === "GoDaddy")).toBe(true);
  });

  it("clearLiveRun removes the durable live record (clean finalize supersedes it)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    const sv = scopedVault(vault, CASE);
    await persistLiveRun(sv, liveModel());
    expect(readLiveRun(sv)).not.toBeNull();
    await clearLiveRun(sv);
    expect(readLiveRun(sv)).toBeNull();
  });
});
