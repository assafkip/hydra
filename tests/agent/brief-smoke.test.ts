// PRD-4 p4-smoke (node): the deliverable chain end-to-end — a scripted investigation
// produces a saved run, then generateBrief turns it into a sanitized, persisted brief.
// The DOM render is tests/smoke/brief.spec.ts; the live brief is the user's.

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, runInvestigation, generateBrief } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

function investigateWire(): FetchLike {
  const turns = [
    { content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: {} },
    { content: [{ type: "text", text: '```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' }], stop_reason: "end_turn", usage: {} },
  ];
  return (async () => ({ ok: true, status: 200, json: async () => turns.shift() })) as unknown as FetchLike;
}
function osintWire(): FetchLike {
  return (async (url: string) =>
    String(url).includes("dns.google")
      ? { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }) }
      : { ok: false, status: 404, json: async () => ({}) }) as unknown as FetchLike;
}
function briefWire(text: string): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) })) as unknown as FetchLike;
}

describe("deliverable chain: investigate -> brief", () => {
  it("a scripted run feeds a brief that is persisted and key-free", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, "sk-ant-CHAIN-KEY");

    const run = await runInvestigation({
      vault,
      objective: "Investigate example.com",
      fetchImpl: investigateWire(),
      toolOpts: { fetchImpl: osintWire(), retries: 0 },
    });
    expect(run.promoted.map((f) => f.entity)).toEqual(["93.184.216.34"]);

    const brief = await generateBrief(vault, "Investigate example.com", {
      fetchImpl: briefWire("# Investigation brief\n## Executive summary\n93.184.216.34 is live infrastructure."),
    });
    expect(brief).toContain("Investigation brief");
    expect(brief).toContain("93.184.216.34");

    const saved = vault.get("brief:Investigate example.com") as { brief: string };
    expect(saved.brief).toBe(brief);
    expect(JSON.stringify(saved)).not.toContain("sk-ant-CHAIN-KEY");
  });
});
