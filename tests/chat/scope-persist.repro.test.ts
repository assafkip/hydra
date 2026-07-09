// REGRESSION GUARD (hydra ISSUE-2, fixed 2026-07-07): "I pressed Save scope inside the form and it still
// didn't save." Root cause was a fire-and-forget durable write — recordScope -> putTradecraft -> vault.put
// with the put promise neither awaited nor returned, so a reload read `null`. The fix made putTradecraft +
// recordScope async and awaited end-to-end (deps.recordScope + saveScope). This test now proves scope
// round-trips a reload; if it goes red again the write stopped being awaited.

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault";
import { memoryStorage } from "../../src/vault/store";
import { scopedVault, recordScope, getScopeFields } from "../../src/agent/session";

const CASE = "case-test";

describe("scope persistence repro", () => {
  it("in-memory read works on the SAME vault instance", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    const sv = scopedVault(vault, CASE);
    recordScope(sv, { question: "who runs empresas.com?", hypotheses: "same registrar cluster", proof: "T1 whois" });
    // same instance reads the in-memory doc synchronously
    expect(getScopeFields(sv)?.question).toBe("who runs empresas.com?");
  });

  it("recordScope returns an awaitable durability handle (the fix — saveScope can await the landed write)", async () => {
    // structural: saveScope now has a Promise to await before it starts the run / navigates, so it can
    // guarantee the durable write landed. Before the fix this returned a sync object with nothing to await.
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    const ret = recordScope(scopedVault(vault, CASE), { question: "awaitable now" });
    expect(typeof (ret as { then?: unknown }).then).toBe("function"); // it is a Promise
    const rec = await ret;
    expect(rec.step).toBe("scope");
  });

  it("REPRO: survives a reload only if the fire-and-forget put flushed first", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    await recordScope(scopedVault(vault, CASE), { question: "remember me after reload" });

    // A new Vault reading the SAME storage = the F5 / tab-switch case (ISSUE-5).
    const reopened = await Vault.unlock(storage, "hunter2");
    const loaded = getScopeFields(scopedVault(reopened, CASE));
    // If this is null, the un-awaited put lost the write on reload. If it round-trips, persistence
    // itself is sound and the founder's failure is UI-layer (busy guard / clicked the wrong control).
    console.log("[scope-repro] reopened scope =", JSON.stringify(loaded));
    expect(loaded?.question).toBe("remember me after reload");
  });

  it("CONTROL: the SAME write AWAITED survives the reload (proves the fix = await the put)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    const sv = scopedVault(vault, CASE);
    // Mirror putTradecraft's write, but AWAIT it (the one-line fix: putTradecraft/recordScope await + return the put).
    await sv.put("tradecraft:scope", { content: "Question: awaited survives", when: 1 });

    const reopened = await Vault.unlock(storage, "hunter2");
    const loaded = getScopeFields(scopedVault(reopened, CASE));
    console.log("[scope-repro] awaited reopened scope =", JSON.stringify(loaded));
    expect(loaded?.question).toBe("awaited survives");
  });
});
