// PRD-5a p5-smoke: the agent pivots on a BTC address end-to-end (real runTool +
// real mempool adapter against a canned fixture, scripted model). Proves the
// on-chain tool dispatches, feeds back, and a wallet finding promotes (T1).
// The live on-chain lookup is the user's, like every OSINT tool.

import { describe, it, expect } from "vitest";
import { AnthropicClient } from "../../src/llm/client.js";
import type { FetchLike } from "../../src/osint/types.js";
import { investigate } from "../../src/agent/loop.js";

const ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

function scriptedAnthropic(): FetchLike {
  const turns = [
    {
      content: [
        { type: "text", text: "Tracing the payout address." },
        { type: "tool_use", id: "b1", name: "btc_address", input: { address: ADDR } },
      ],
      stop_reason: "tool_use",
      usage: {},
    },
    {
      content: [{ type: "text", text: `\`\`\`json\n{"findings":[{"entity":"${ADDR}","entity_type":"wallet","confidence":"high"}]}\n\`\`\`` }],
      stop_reason: "end_turn",
      usage: {},
    },
  ];
  return (async () => ({ ok: true, status: 200, json: async () => turns.shift() })) as unknown as FetchLike;
}

function cannedMempool(): FetchLike {
  return (async (url: string) =>
    String(url).includes("mempool.space")
      ? {
          ok: true,
          status: 200,
          json: async () => ({ address: ADDR, chain_stats: { funded_txo_sum: 5_000_000_000, spent_txo_sum: 1_000_000_000, tx_count: 100 }, mempool_stats: {} }),
        }
      : { ok: false, status: 404, json: async () => ({}) }) as unknown as FetchLike;
}

describe("agent on-chain pivot (btc_address)", () => {
  it("dispatches the BTC tool, feeds it back, and promotes the wallet finding", async () => {
    const client = new AnthropicClient("sk-ant-onchain", scriptedAnthropic());
    const r = await investigate({
      objective: `Trace BTC address ${ADDR}`,
      client,
      toolOpts: { fetchImpl: cannedMempool(), retries: 0 },
    });

    expect(r.stopReason).toBe("end_turn");
    const toolStep = r.steps.find((s) => s.kind === "tool");
    expect(toolStep).toMatchObject({ tool: "btc_address", isError: false });
    expect(String(toolStep?.result)).toContain("mempool.space");
    // an on-chain-confirmed wallet promotes (T1, non-fakeable)
    expect(r.promoted.map((f) => f.entity)).toContain(ADDR);
  });
});
