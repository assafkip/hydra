import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  answerQuestion,
  recordScope,
  runInvestigation,
  runTradecraftGate,
  getScopeFields,
} from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// Reproducer for "I add a scope, but the LLM ignores it completely" (founder 2026-07-07).
// The whole-case ▶ run already frames its task with the scope (buildCaseTask); these assert the two
// paths the analyst actually hits day-to-day ALSO carry the scope into the model, and that the saved
// scope can be read back structured (so the Scope form can re-hydrate — it looked un-persisted before).

async function vaultWithKey(key = "sk-ant-scope"): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

function captureFetch(text: string): { impl: FetchLike; calls: { body: string }[] } {
  const calls: { body: string }[] = [];
  const impl = (async (_url: string, init: RequestInit) => {
    calls.push({ body: String(init.body) });
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) };
  }) as unknown as FetchLike;
  return { impl, calls };
}

const PROMOTED_RUN = {
  objective: "Investigate live.example.com",
  steps: [],
  promoted: [{ entity: "live.example.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("scope reaches the model (bug: scope saved but ignored)", () => {
  it("Q&A: a saved scope is injected into the grounding prompt", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    recordScope(vault, {
      question: "Who operates the casino-scam network?",
      hypotheses: "One operator is behind every seed",
      proof: "a shared registrant or a shared payout wallet",
    });
    const { impl, calls } = captureFetch("live.example.com is the operating domain [run: Investigate live.example.com].");
    await answerQuestion(vault, "what is operating?", { fetchImpl: impl });
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toContain("Who operates the casino-scam network?"); // the scope framed the answer
  });

  it("single-objective investigate: a saved scope frames the objective sent to the agent", async () => {
    const vault = await vaultWithKey();
    recordScope(vault, { question: "Map the casino-scam infrastructure end to end", hypotheses: "", proof: "" });
    const { impl, calls } = captureFetch('{"findings":[]}');
    await runInvestigation({ vault, objective: "example.com", fetchImpl: impl, persist: false, maxTurns: 1 });
    expect(calls.length).toBeGreaterThan(0);
    expect(calls[0].body).toContain("Map the casino-scam infrastructure end to end");
  });

  it("Challenge/Premortem gate: a saved scope frames the pressure-test", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    recordScope(vault, { question: "Is one operator behind the whole network?", hypotheses: "", proof: "" });
    const { impl, calls } = captureFetch("Challenge: the single load-bearing claim is the shared registrant.");
    await runTradecraftGate(vault, "challenge", { fetchImpl: impl });
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toContain("Is one operator behind the whole network?");
  });

  it("getScopeFields round-trips the saved scope so the form can re-hydrate", async () => {
    const vault = await vaultWithKey();
    recordScope(vault, { question: "Q1", hypotheses: "H1", proof: "P1" });
    expect(getScopeFields(vault)).toEqual({ question: "Q1", hypotheses: "H1", proof: "P1" });
  });

  it("getScopeFields is null when no scope was set", async () => {
    const vault = await vaultWithKey();
    expect(getScopeFields(vault)).toBeNull();
  });
});
