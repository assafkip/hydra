import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { AnthropicClient } from "../../src/llm/client.js";
import type { FetchLike } from "../../src/osint/types.js";
import { investigate } from "../../src/agent/loop.js";
import type { ToolOutcome } from "../../src/agent/tools.js";
import { enrichToolsFor, runInvestigation, setApiKey, setProviderKey } from "../../src/agent/session.js";

// m3-wire: the session registers the keyed enrich providers as agent tools, the loop credits per-provider
// infra + marks the query echo self, redacts content in-flight (D9), and a per-run budget bounds spend (D7).

type Payload = { content: unknown[]; stop_reason: string; usage?: { input_tokens?: number; output_tokens?: number } };

function scriptedImpl(responses: Payload[], requests: Record<string, unknown>[]): FetchLike {
  const queue = [...responses];
  return (async (_url: string, init: RequestInit) => {
    requests.push(JSON.parse(String(init.body)));
    const payload = queue.shift() ?? { content: [{ type: "text", text: "```json\n{\"findings\":[]}\n```" }], stop_reason: "end_turn", usage: {} };
    return { ok: true, status: 200, json: async () => payload };
  }) as unknown as FetchLike;
}

async function vaultWith(anthropic: string, providers: Record<string, string> = {}): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const v = await Vault.unlock(storage, "pw");
  await setApiKey(v, anthropic);
  for (const [id, key] of Object.entries(providers)) await setProviderKey(v, id, key);
  return v;
}

describe("m3-wire — dynamic enrich tools, loop infra/self/redact, per-run budget", () => {
  it("enrichToolsFor: [] keyless, exactly the keyed provider when a key is set (D10 no-regression)", async () => {
    const keyless = await vaultWith("sk-ant-x");
    expect(enrichToolsFor(keyless)).toEqual([]);
    const keyed = await vaultWith("sk-ant-x", { shodan: "shdn-123" });
    const tools = enrichToolsFor(keyed);
    expect(tools.map((t) => t.name)).toEqual(["enrich_shodan"]);
  });

  it("the loop credits per-provider infra, excludes the self echo, and redacts content in-flight", async () => {
    const SECRET = "shodanKEY-leak-9999";
    const requests: Record<string, unknown>[] = [];
    const client = new AnthropicClient(
      "sk-ant-x",
      scriptedImpl(
        [
          { content: [{ type: "tool_use", id: "t1", name: "enrich_shodan", input: { target: "8.8.8.8" } }], stop_reason: "tool_use", usage: {} },
          {
            content: [
              {
                type: "text",
                text:
                  '```json\n{"findings":[{"entity":"8.8.8.8","entity_type":"ip"},' +
                  '{"entity":"1.2.3.4","entity_type":"ip"}]}\n```',
              },
            ],
            stop_reason: "end_turn",
            usage: { output_tokens: 20 },
          },
        ],
        requests,
      ),
    );

    // an enrich-shaped outcome: the queried target (self echo) + a related infra ip + a person echo, with
    // a SECRET in the content the injected redactor must cut before the trail OR the model sees it.
    const enrichOutcome: ToolOutcome = {
      content: JSON.stringify({ provider: "enrich:shodan", note: SECRET, entities: [{ type: "ip", value: "1.2.3.4" }] }),
      is_error: false,
      entities: [
        { type: "ip", value: "8.8.8.8" }, // the queried target -> self echo (excluded)
        { type: "ip", value: "1.2.3.4" }, // a related infra ip -> corroborates
      ],
      provider: "enrich:shodan",
      infra: true,
      queryEcho: "8.8.8.8",
    };

    const r = await investigate({
      objective: "dig 8.8.8.8",
      client,
      runTool: async () => enrichOutcome,
      redactContent: (s) => s.split(SECRET).join("[REDACTED]"),
    });

    // gate-faithful: the related infra ip promotes; the self-echoed target stays a lead.
    // (A person echo is structurally impossible via the typed OsintEntity path — that D5 case is
    //  covered by a directly-constructed Observed in gate-enrich.test.ts.)
    expect(r.promoted.map((f) => f.entity)).toEqual(["1.2.3.4"]);
    const leadEntities = r.leads.map((l) => l.finding.entity);
    expect(leadEntities).toContain("8.8.8.8"); // self echo alone never promotes (D4)

    // D9: the secret never reaches the trail step result, nor the tool_result sent to the model.
    const toolStep = r.steps.find((s) => s.kind === "tool");
    expect(toolStep?.result).not.toContain(SECRET);
    expect(toolStep?.result).toContain("[REDACTED]");
    const toolResultTurn = (requests[1].messages as { content: unknown }[])[2].content as { content?: string }[];
    expect(JSON.stringify(toolResultTurn)).not.toContain(SECRET);
  });

  it("the per-run budget blocks a repeat (provider,target) enrich call (D7)", async () => {
    const vault = await vaultWith("sk-ant-x", { shodan: "shdn-key-abc" });
    const osint = { n: 0 };
    const osintFetch = (async () => {
      osint.n++;
      return { ok: true, status: 200, json: async () => ({ ip_str: "8.8.8.8", hostnames: ["dns.google"], asn: "AS15169", org: "Google" }) } as Response;
    }) as unknown as FetchLike;

    const anthropicReqs: Record<string, unknown>[] = [];
    const anthropicFetch = scriptedImpl(
      [
        { content: [{ type: "tool_use", id: "t1", name: "enrich_shodan", input: { target: "8.8.8.8" } }], stop_reason: "tool_use", usage: {} },
        { content: [{ type: "tool_use", id: "t2", name: "enrich_shodan", input: { target: "8.8.8.8" } }], stop_reason: "tool_use", usage: {} },
        { content: [{ type: "text", text: "```json\n{\"findings\":[]}\n```" }], stop_reason: "end_turn", usage: {} },
      ],
      anthropicReqs,
    );

    await runInvestigation({
      vault,
      objective: "dig 8.8.8.8",
      fetchImpl: anthropicFetch,
      toolOpts: { fetchImpl: osintFetch },
      maxTurns: 5,
    });

    // two enrich_shodan calls on the SAME target, but the adapter ran ONCE — the second was budget-blocked.
    expect(osint.n).toBe(1);
  });
});
