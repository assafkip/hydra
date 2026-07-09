// PRD-3 p3-smoke (node): the full agent SESSION end-to-end through the public API —
// a real vault, the key set via setApiKey, a scripted Anthropic + canned OSINT, and
// runInvestigation producing a live trail + gated findings + a sanitized persisted
// run. The DOM render is proven separately in tests/smoke/agent.spec.ts (Playwright);
// the live model call is the user's to make with their key (docs/agent-loop.md).

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, runInvestigation } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

function scriptedAnthropic(): FetchLike {
  const turns = [
    {
      content: [
        { type: "text", text: "Resolving infrastructure." },
        { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
      ],
      stop_reason: "tool_use",
      usage: { output_tokens: 10 },
    },
    {
      content: [
        {
          type: "text",
          text:
            '```json\n{"findings":[' +
            '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
            '{"entity":"Jane Roe","entity_type":"person","confidence":"high"}]}\n```',
        },
      ],
      stop_reason: "end_turn",
      usage: { output_tokens: 20 },
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

describe("agent session end-to-end (real vault + tools, scripted model)", () => {
  it("set key -> run -> live trail -> gated findings -> sanitized persisted run", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, "sk-ant-SMOKE-KEY-9");

    const trail: string[] = [];
    const result = await runInvestigation({
      vault,
      objective: "Investigate example.com",
      onStep: (s) => trail.push(s.kind),
      fetchImpl: scriptedAnthropic(),
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });

    // live trail streamed in order
    expect(trail).toEqual(["reasoning", "tool", "reasoning"]);
    // tradecraft gate: infra-confirmed IP promotes, name-only person held as lead
    expect(result.promoted.map((f) => f.entity)).toEqual(["93.184.216.34"]);
    expect(result.leads.map((l) => l.finding.entity)).toContain("Jane Roe");

    // the run persisted to the vault, sanitized (no key anywhere)
    const persisted = vault.get("run:Investigate example.com");
    expect(persisted).toBeTruthy();
    expect(JSON.stringify(persisted)).not.toContain("sk-ant-SMOKE-KEY-9");
    expect(JSON.stringify(result)).not.toContain("sk-ant-SMOKE-KEY-9");
  });
});
