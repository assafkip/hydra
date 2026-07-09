import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  getApiKey,
  setApiKey,
  hasApiKey,
  runInvestigation,
  SessionError,
  ANTHROPIC_KEY,
} from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

async function freshVault(): Promise<{ vault: Vault; storage: ReturnType<typeof memoryStorage> }> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return { vault: await Vault.unlock(storage, "pw"), storage };
}

function scriptedAnthropic(): FetchLike {
  const turns = [
    {
      content: [
        { type: "text", text: "Resolving the domain." },
        { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
      ],
      stop_reason: "tool_use",
      usage: { input_tokens: 50, output_tokens: 10 },
    },
    {
      content: [
        {
          type: "text",
          text:
            'Found it.\n```json\n{"findings":[' +
            '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
            '{"entity":"Jane Roe","entity_type":"person","confidence":"high"}]}\n```',
        },
      ],
      stop_reason: "end_turn",
      usage: { input_tokens: 80, output_tokens: 20 },
    },
  ];
  return (async () => ({ ok: true, status: 200, json: async () => turns.shift() })) as unknown as FetchLike;
}

function cannedOsint(): FetchLike {
  return (async (url: string) =>
    String(url).includes("dns.google")
      ? { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }) }
      : { ok: false, status: 404, json: async () => ({}) }) as unknown as FetchLike;
}

describe("api key storage (reserved secret namespace)", () => {
  it("set/get round-trips under secret:anthropic_key", async () => {
    const { vault } = await freshVault();
    expect(hasApiKey(vault)).toBe(false);
    await setApiKey(vault, "sk-ant-abc");
    expect(getApiKey(vault)).toBe("sk-ant-abc");
    expect(vault.get(ANTHROPIC_KEY)).toBe("sk-ant-abc");
    expect(hasApiKey(vault)).toBe(true);
  });

  it("treats empty/whitespace as no key", async () => {
    const { vault } = await freshVault();
    await expect(setApiKey(vault, "   ")).rejects.toBeInstanceOf(SessionError);
    await vault.put(ANTHROPIC_KEY, "   "); // sneak a blank value in directly
    expect(getApiKey(vault)).toBeNull();
  });

  it("a locked vault surfaces a clean SessionError, not a vault payload", async () => {
    const { vault } = await freshVault();
    await setApiKey(vault, "sk-ant-abc");
    vault.lock();
    expect(() => getApiKey(vault)).toThrow(SessionError);
    await expect(runInvestigation({ vault, objective: "x" })).rejects.toBeInstanceOf(SessionError);
  });
});

describe("runInvestigation", () => {
  it("no key -> a clear 'add your key' error", async () => {
    const { vault } = await freshVault();
    await expect(runInvestigation({ vault, objective: "x" })).rejects.toThrow(/add your anthropic api key/i);
  });

  it("runs the agent, streams onStep in order, gates, and persists a sanitized run", async () => {
    const { vault } = await freshVault();
    await setApiKey(vault, "sk-ant-abc");
    const seen: string[] = [];
    const result = await runInvestigation({
      vault,
      objective: "Investigate example.com",
      onStep: (s) => seen.push(s.kind),
      fetchImpl: scriptedAnthropic(),
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });

    expect(result.stopReason).toBe("end_turn");
    expect(result.promoted.map((f) => f.entity)).toEqual(["93.184.216.34"]);
    expect(result.leads.map((l) => l.finding.entity)).toContain("Jane Roe");
    expect(seen).toEqual(["reasoning", "tool", "reasoning"]); // live trail, in order

    const run = vault.get("run:Investigate example.com") as { stopReason: string; promoted: unknown[] };
    expect(run.stopReason).toBe("end_turn");
    expect(run.promoted.length).toBe(1);
  });

  it("KEY HYGIENE: the key never appears in the result or the persisted run", async () => {
    const { vault } = await freshVault();
    await setApiKey(vault, "sk-ant-LEAKTEST-0001");
    const result = await runInvestigation({
      vault,
      objective: "probe",
      fetchImpl: scriptedAnthropic(),
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });
    expect(JSON.stringify(result)).not.toContain("sk-ant-LEAKTEST-0001");
    expect(JSON.stringify(vault.get("run:probe"))).not.toContain("sk-ant-LEAKTEST-0001");
  });
});
