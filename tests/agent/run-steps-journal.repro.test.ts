// REPRO (hydra reload-survival, founder 2026-07-08): the run STEP TRAIL (#trail) lived in the in-memory
// run-store only, so a reload wiped it — a finished run's log read as "gone". The fix journals the step trail
// to a case-scoped `run-live-steps` key (parallel to the graph journal), replayed into #trail on reattach.
//
// This pins the step-journal contract: steps round-trip a reload, redact secrets, and — unlike the graph
// journal — SURVIVE a clean finalize (nothing re-folds the trail on load, so clearing it would lose the log).

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault";
import { memoryStorage } from "../../src/vault/store";
import {
  scopedVault,
  persistLiveRunSteps,
  readLiveRunSteps,
  clearLiveRun,
  ANTHROPIC_KEY,
} from "../../src/agent/session";
import type { Step } from "../../src/agent/loop";

const CASE = "case-test";

function steps(): Step[] {
  return [
    { kind: "reasoning", text: "Start with the domain." },
    { kind: "tool", tool: "dns_lookup", input: { domain: "empresas.com" }, result: "A 1.2.3.4" },
    { kind: "tool", tool: "rdap", input: { domain: "empresas.com" }, result: "registrar: GoDaddy" },
  ];
}

describe("run step-journal persistence repro", () => {
  it("FIX: the step trail survives a reload (persist → new Vault → read round-trips, in order)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    await persistLiveRunSteps(scopedVault(vault, CASE), steps());

    // A new Vault reading the SAME storage = the F5 / reload case (the JS context was killed).
    const reopened = await Vault.unlock(storage, "hunter2");
    const loaded = readLiveRunSteps(scopedVault(reopened, CASE));
    expect(loaded.length).toBe(3);
    expect(loaded[0].text).toBe("Start with the domain.");
    expect(loaded[1].tool).toBe("dns_lookup");
    expect(loaded[2].result).toContain("GoDaddy");
  });

  it("SURVIVES a clean finalize: clearLiveRun drops the graph journal but KEEPS the step trail", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    const sv = scopedVault(vault, CASE);
    await persistLiveRunSteps(sv, steps());
    await clearLiveRun(sv); // a clean finalize
    // The trail must remain — nothing re-folds it into #trail on load, so a finished run's log stays visible.
    expect(readLiveRunSteps(sv).length).toBe(3);
  });

  it("redacts a secret echoed in a tool result before it is journaled", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    // Set the Anthropic key, then simulate a tool result that echoed it (the exact leak vector).
    await vault.put(ANTHROPIC_KEY, "sk-ant-secret-value-123");
    const sv = scopedVault(vault, CASE);
    await persistLiveRunSteps(sv, [
      { kind: "tool", tool: "leaky", result: "the key is sk-ant-secret-value-123 oops" },
    ]);
    const loaded = readLiveRunSteps(sv);
    expect(loaded[0].result).not.toContain("sk-ant-secret-value-123");
  });

  it("absent journal reads back as [] (fresh case / never ran)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    expect(readLiveRunSteps(scopedVault(vault, CASE)).length).toBe(0);
  });
});
