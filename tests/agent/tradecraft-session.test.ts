import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  recordScope,
  runTradecraftGate,
  tradecraftState,
  getTradecraft,
  unmetTradecraftGates,
  SessionError,
} from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// cd-tradecraft (chat-graph-parity-fixes): the session-layer Scope/Challenge/Premortem gates ported
// from investigations/tradecraft.py. Scope is analyst input (no model call); the gates run a bounded
// no-tools pass over the case findings, key-redacted in the evidence + prompt + output, stored per-case.

async function vaultWithKey(key = "sk-ant-tc"): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

function gateFetch(text: string): { impl: FetchLike; calls: { body: string }[] } {
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

describe("recordScope + tradecraftState", () => {
  it("captures scope with NO model call, marks the gate done, leaves challenge/premortem unmet", async () => {
    const vault = await vaultWithKey();
    const rec = await recordScope(vault, { question: "Who operates the funnel?", hypotheses: "A single operator", proof: "shared infra" });
    expect(rec.step).toBe("scope");
    expect(rec.content).toContain("Who operates the funnel?");
    expect(rec.content).toContain("Hypotheses: A single operator");
    expect(rec.content).toContain("What counts as proof: shared infra");

    const state = tradecraftState(vault);
    expect(state.find((s) => s.step === "scope")?.done).toBe(true);
    expect(unmetTradecraftGates(vault)).toEqual(["challenge", "premortem"]);
    expect(getTradecraft(vault, "scope")?.content).toContain("Who operates the funnel?");
  });

  it("rejects an empty scope question", async () => {
    const vault = await vaultWithKey();
    await expect(recordScope(vault, { question: "  " })).rejects.toBeInstanceOf(SessionError);
  });
});

describe("runTradecraftGate (challenge / premortem)", () => {
  it("runs over the case findings, stores the result, marks the gate done", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl, calls } = gateFetch("1) Name-match traps: none here. To resolve: verify the registrant.");
    const rec = await runTradecraftGate(vault, "challenge", { fetchImpl: impl });
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toContain("live.example.com"); // the evidence reached the model
    expect(calls[0].body).toContain("challenge analysis");
    expect(rec.content).toContain("Name-match traps");
    expect(tradecraftState(vault).find((s) => s.step === "challenge")?.done).toBe(true);
    expect(unmetTradecraftGates(vault)).toEqual(["scope", "premortem"]); // challenge now met
  });

  it("throws (no model call) when the case has no findings yet", async () => {
    const vault = await vaultWithKey();
    const { impl, calls } = gateFetch("should never be called");
    await expect(runTradecraftGate(vault, "premortem", { fetchImpl: impl })).rejects.toBeInstanceOf(SessionError);
    expect(calls).toHaveLength(0);
  });

  it("redacts the live key from the evidence, the prompt, and the output", async () => {
    const KEY = "sk-ant-TC-REDACT-9";
    const vault = await vaultWithKey(KEY);
    await vault.put(`run:probe ${KEY}`, {
      objective: `probe ${KEY}`,
      steps: [],
      promoted: [{ entity: "live.example.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2, note: KEY }],
      leads: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    });
    const { impl, calls } = gateFetch(`the model echoes ${KEY} and live.example.com`);
    const rec = await runTradecraftGate(vault, "premortem", { fetchImpl: impl });
    expect(calls[0].body).not.toContain(KEY); // key never reaches the model
    expect(rec.content).not.toContain(KEY); // output redacted
    expect(getTradecraft(vault, "premortem")?.content).not.toContain(KEY); // stored redacted
  });

  it("no key with evidence -> clean SessionError", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    await expect(runTradecraftGate(vault, "challenge")).rejects.toBeInstanceOf(SessionError);
  });
});
