// PRD-2 p2-smoke: the offline end-to-end proof. Unlike loop.test.ts (which injects
// a fake runTool), this drives the REAL runTool + REAL OSINT adapters against canned
// provider responses, with a scripted Anthropic wire — so the whole path is exercised:
// model turn -> real tool dispatch -> real adapter parse -> tool_result -> attribution
// -> gate -> step trail. The LIVE agent call is the user's to make with their key
// (docs/agent-loop.md); a mock cannot prove the model CHOOSES good tools, only that
// the loop mechanics are correct.

import { describe, it, expect } from "vitest";
import { AnthropicClient } from "../../src/llm/client.js";
import type { FetchLike } from "../../src/osint/types.js";
import { investigate } from "../../src/agent/loop.js";

type Payload = { content: unknown[]; stop_reason: string; usage?: { input_tokens?: number; output_tokens?: number } };

// A scripted Anthropic wire: one tool_use turn, then an end_turn with findings.
function scriptedAnthropic(): FetchLike {
  const turns: Payload[] = [
    {
      content: [
        { type: "text", text: "Resolving example.com to its infrastructure." },
        { type: "tool_use", id: "tu_dns", name: "dns_lookup", input: { domain: "example.com" } },
      ],
      stop_reason: "tool_use",
      usage: { input_tokens: 100, output_tokens: 12 },
    },
    {
      content: [
        {
          type: "text",
          text:
            "The domain resolves to 93.184.216.34. A name appeared but with no crosslink.\n" +
            '```json\n{"findings":[' +
            '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high","claim":"A record of example.com via dns.google"},' +
            '{"entity":"Jane Roe","entity_type":"person","confidence":"high","claim":"name seen on a page"}' +
            "]}\n```",
        },
      ],
      stop_reason: "end_turn",
      usage: { input_tokens: 140, output_tokens: 30 },
    },
  ];
  return (async () => ({ ok: true, status: 200, json: async () => turns.shift() })) as unknown as FetchLike;
}

// Canned OSINT provider wire: dns.google returns a real-shaped DoH answer.
function cannedOsint(): FetchLike {
  return (async (url: string) => {
    if (String(url).includes("dns.google")) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ Status: 0, Answer: [{ name: "example.com", type: 1, data: "93.184.216.34" }] }),
      };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  }) as unknown as FetchLike;
}

describe("agent loop end-to-end (real tools + gate, scripted model)", () => {
  it("dispatches the real OSINT tool, feeds it back, and gates the findings", async () => {
    const client = new AnthropicClient("sk-ant-smoke", scriptedAnthropic());
    const r = await investigate({
      objective: "Investigate example.com and report its infrastructure.",
      client,
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });

    expect(r.stopReason).toBe("end_turn");

    // the real dns_lookup ran and produced a tool step (not an error)
    const toolStep = r.steps.find((s) => s.kind === "tool");
    expect(toolStep).toMatchObject({ tool: "dns_lookup", isError: false });
    expect(String(toolStep?.result)).toContain("93.184.216.34");

    // infra-confirmed IP promotes; the name-only person is a held lead (no tool
    // corroborated it -> grade D; the gate never graphs an uncorroborated identity)
    expect(r.promoted.map((f) => f.entity)).toEqual(["93.184.216.34"]);
    const jane = r.leads.find((l) => l.finding.entity === "Jane Roe");
    expect(jane).toBeDefined();
    expect(jane?.verdict.promote).toBe(false);
    expect(jane?.verdict.reason.length).toBeGreaterThan(0);

    // usage accumulated across both turns
    expect(r.usage.output).toBe(42);
  });

  it("an AbortSignal stops a run cleanly (the Stop button)", async () => {
    const client = new AnthropicClient("sk-ant-smoke", scriptedAnthropic());
    const ctrl = new AbortController();
    ctrl.abort();
    const r = await investigate({
      objective: "Investigate example.com.",
      client,
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
      signal: ctrl.signal,
    });
    expect(r.stopReason).toBe("aborted");
    expect(r.promoted).toEqual([]);
  });
});
