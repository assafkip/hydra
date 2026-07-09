import { describe, it, expect } from "vitest";
import { AnthropicClient } from "../../src/llm/client.js";
import type { FetchLike } from "../../src/osint/types.js";
import { investigate, extractFindings, DEEP_MAX_TURNS, type ObservedEvent } from "../../src/agent/loop.js";
import type { ToolOutcome } from "../../src/agent/tools.js";

type Payload = { content: unknown[]; stop_reason: string; usage?: { input_tokens?: number; output_tokens?: number } };

function scriptedClient(responses: Payload[]): { client: AnthropicClient; requests: Record<string, unknown>[] } {
  const queue = [...responses];
  const requests: Record<string, unknown>[] = [];
  const impl = (async (_url: string, init: RequestInit) => {
    requests.push(JSON.parse(String(init.body)));
    const payload = queue.shift() ?? { content: [], stop_reason: "end_turn", usage: {} };
    return { ok: true, status: 200, json: async () => payload };
  }) as unknown as FetchLike;
  return { client: new AnthropicClient("sk-ant-test", impl), requests };
}

const ipTool = (value: string): ToolOutcome => ({
  content: JSON.stringify({ provider: "dns.google", entities: [{ type: "ip", value }] }),
  is_error: false,
  entities: [{ type: "ip", value }],
  provider: "dns.google",
});

const findingsTurn = (text: string): Payload => ({
  content: [{ type: "text", text }],
  stop_reason: "end_turn",
  usage: { output_tokens: 20 },
});

describe("investigate: the manual agentic loop", () => {
  it("runs a tool_use turn, feeds the result back, extracts + gates findings", async () => {
    const { client, requests } = scriptedClient([
      {
        content: [
          { type: "text", text: "I'll resolve the domain." },
          { type: "tool_use", id: "tu1", name: "dns_lookup", input: { domain: "example.com" } },
        ],
        stop_reason: "tool_use",
        usage: { output_tokens: 10 },
      },
      findingsTurn(
        'Found the host.\n```json\n{"findings":[{"entity":"1.2.3.4","entity_type":"ip","confidence":"high"},' +
          '{"entity":"John Doe","entity_type":"person","confidence":"high"}]}\n```',
      ),
    ]);

    const r = await investigate({
      objective: "investigate example.com",
      client,
      runTool: async () => ipTool("1.2.3.4"),
    });

    expect(r.stopReason).toBe("end_turn");
    // an infra-confirmed IP promotes; a name-only person is held as a lead
    expect(r.promoted.map((f) => f.entity)).toEqual(["1.2.3.4"]);
    expect(r.leads.map((l) => l.finding.entity)).toContain("John Doe");
    // ordered step trail: reasoning -> tool -> reasoning
    expect(r.steps.map((s) => s.kind)).toEqual(["reasoning", "tool", "reasoning"]);
    expect(r.steps[1]).toMatchObject({ kind: "tool", tool: "dns_lookup", isError: false });

    // transcript ordering: turn 2 sends [user, assistant(tool_use), user(tool_result by id)]
    const msgs = requests[1].messages as { role: string; content: unknown }[];
    expect(msgs[0].role).toBe("user");
    expect(msgs[1].role).toBe("assistant");
    const assistantBlocks = msgs[1].content as { type: string; id?: string }[];
    expect(assistantBlocks.some((b) => b.type === "tool_use" && b.id === "tu1")).toBe(true);
    const toolResultTurn = msgs[2].content as { type: string; tool_use_id?: string }[];
    expect(toolResultTurn[0]).toMatchObject({ type: "tool_result", tool_use_id: "tu1" });
  });

  it("kweb-findings-cutoff: a max_tokens-truncated findings JSON is CONTINUED across calls, not discarded", async () => {
    // The regression: a fully-worked rich case truncates its final findings JSON at the per-call cap,
    // returns stop_reason max_tokens, and (pre-fix) the loop threw it all away → 0 promoted on a real case.
    const { client, requests } = scriptedClient([
      {
        content: [{ type: "tool_use", id: "tu1", name: "dns_lookup", input: { domain: "example.com" } }],
        stop_reason: "tool_use",
        usage: { output_tokens: 10 },
      },
      // the agent starts writing its findings JSON and the per-call cap truncates it mid-object
      {
        content: [{ type: "text", text: '```json\n{"findings":[{"entity":"1.2.3.4","entity_type":"ip",' }],
        stop_reason: "max_tokens",
        usage: { output_tokens: 16000 },
      },
      // continuation: the agent finishes only the remaining characters
      {
        content: [{ type: "text", text: '"confidence":"high"}]}\n```' }],
        stop_reason: "end_turn",
        usage: { output_tokens: 40 },
      },
    ]);

    const r = await investigate({ objective: "investigate example.com", client, runTool: async () => ipTool("1.2.3.4") });

    expect(r.stopReason).toBe("end_turn"); // finished cleanly via the continuation, NOT "incomplete"
    expect(r.promoted.map((f) => f.entity)).toEqual(["1.2.3.4"]); // reconstructed + gated, NOT discarded
    expect(r.worked).toBe(true);
    // a continuation turn was actually sent (tool call, truncated answer, continuation) = 3 model calls
    expect(requests.length).toBe(3);
    const contMsgs = requests[2].messages as { role: string; content: unknown }[];
    expect((contMsgs[contMsgs.length - 1] as { role: string }).role).toBe("user"); // the "continue" nudge
  });

  it("kweb-findings-cutoff: a truncated TOOL_USE turn is NOT continued — it is an honest cutoff", async () => {
    // A half-emitted tool call is unusable, so a max_tokens stop WITH tool_use must still finish as a cutoff
    // (worked:false, nothing saved) rather than be continued as if it were a findings answer.
    const { client, requests } = scriptedClient([
      {
        content: [
          { type: "text", text: "resolving…" },
          { type: "tool_use", id: "tu1", name: "dns_lookup", input: { domain: "example.com" } },
        ],
        stop_reason: "max_tokens",
        usage: { output_tokens: 16000 },
      },
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.stopReason).toBe("incomplete");
    expect(r.promoted).toEqual([]);
    expect(r.worked).toBe(false);
    expect(requests.length).toBe(1); // no continuation was attempted
  });

  it("a forged high source_count does not promote (attribution overrides model trust)", async () => {
    const { client } = scriptedClient([
      findingsTurn('```json\n{"findings":[{"entity":"9.9.9.9","entity_type":"ip","source_count":9,"infra_source_count":9}]}\n```'),
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.promoted).toEqual([]);
    expect(r.leads.map((l) => l.finding.entity)).toContain("9.9.9.9");
  });

  it("runs MULTIPLE tool calls in one turn into one tool_result user message", async () => {
    const { client, requests } = scriptedClient([
      {
        content: [
          { type: "tool_use", id: "a", name: "dns_lookup", input: { domain: "example.com" } },
          { type: "tool_use", id: "b", name: "rdap_domain", input: { domain: "example.com" } },
        ],
        stop_reason: "tool_use",
        usage: {},
      },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    const resultTurn = (requests[1].messages as { role: string; content: unknown }[])[2].content as {
      type: string;
      tool_use_id: string;
    }[];
    expect(resultTurn.map((b) => b.tool_use_id)).toEqual(["a", "b"]);
  });

  it("a truncated findings JSON that never completes is NEVER parsed as real findings", async () => {
    // The agent truncates mid-JSON; the continuation (kweb-findings-cutoff) cannot complete it (no further
    // text), so the reconstructed block stays malformed and is never gated as real — the parse-safety
    // invariant holds regardless of how the run ends.
    const { client } = scriptedClient([
      {
        content: [{ type: "text", text: '```json\n{"findings":[{"entity":"1.2.3.4","entity_type":"ip"' }],
        stop_reason: "max_tokens",
        usage: {},
      },
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.promoted).toEqual([]);
    expect(r.leads).toEqual([]);
  });

  it("pause_turn resends and continues to end_turn", async () => {
    const { client } = scriptedClient([
      { content: [{ type: "text", text: "thinking..." }], stop_reason: "pause_turn", usage: {} },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.stopReason).toBe("end_turn");
  });

  it("an already-aborted signal stops the loop before any call", async () => {
    const { client, requests } = scriptedClient([findingsTurn('```json\n{"findings":[]}\n```')]);
    const ctrl = new AbortController();
    ctrl.abort();
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4"), signal: ctrl.signal });
    expect(r.stopReason).toBe("aborted");
    expect(requests.length).toBe(0);
  });

  it("fires onStep in order as steps are produced", async () => {
    const { client } = scriptedClient([
      {
        content: [{ type: "text", text: "thinking" }, { type: "tool_use", id: "t", name: "dns_lookup", input: { domain: "example.com" } }],
        stop_reason: "tool_use",
        usage: {},
      },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    const seen: string[] = [];
    await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4"), onStep: (s) => seen.push(s.kind) });
    expect(seen).toEqual(["reasoning", "tool", "reasoning"]); // turn1 text+tool, turn2 findings text
  });

  it("redacts streamed text deltas before emitting them from the loop", async () => {
    const fakeClient = {
      tokensUsed: { input: 0, output: 0 },
      run: async (opts: { onTextDelta?: (text: string) => void }) => {
        opts.onTextDelta?.("raw sk-ant-secret delta");
        return {
          content: [{ type: "text", text: '```json\n{"findings":[]}\n```' }],
          stopReason: "end_turn",
          usage: {},
        };
      },
    } as unknown as AnthropicClient;
    const deltas: string[] = [];

    await investigate({
      objective: "x",
      client: fakeClient,
      onTextDelta: (text) => deltas.push(text),
      redactContent: (s) => s.replace(/sk-ant-secret/g, "[REDACTED]"),
    });

    expect(deltas).toEqual(["raw [REDACTED] delta"]);
  });

  it("isolates a THROWING onStep — the loop still completes and returns its result", async () => {
    const { client } = scriptedClient([
      findingsTurn('```json\n{"findings":[{"entity":"a.com","entity_type":"domain"}]}\n```'),
    ]);
    const r = await investigate({
      objective: "x",
      client,
      runTool: async () => ipTool("1.2.3.4"),
      onStep: () => {
        throw new Error("renderer blew up");
      },
    });
    expect(r.stopReason).toBe("end_turn");
    expect(r.steps.length).toBeGreaterThan(0); // step still recorded despite the throw
  });

  // sp-2c870c26: the honest-degraded / false-exhausted signal (port of investigator.py _run_agent's
  // worked:false branches L1999-2010). A pass that did NO real work (no successful tool AND nothing
  // surfaced) must report worked:false with a diagnostic — so a degraded/keys-missing run is not read
  // as a genuine "exhausted, nothing to find" clean case.
  const errorTool = (): ToolOutcome => ({ content: JSON.stringify({ error: "no key configured" }), is_error: true, entities: [], infra: false });

  it("worked:false when every tool call errors and nothing surfaces (degraded — not clean-empty)", async () => {
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "t", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: {} },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => errorTool() });
    expect(r.worked).toBe(false);
    expect(r.degradedReason).toBeTruthy();
    expect(r.promoted).toEqual([]);
    expect(r.leads).toEqual([]);
  });

  it("worked:false when the agent ran NO tools and found nothing (no-work)", async () => {
    const { client } = scriptedClient([findingsTurn('```json\n{"findings":[]}\n```')]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.worked).toBe(false);
    expect(r.degradedReason).toBeTruthy();
  });

  it("worked:true when a tool succeeds even if NOTHING is found (genuine clean-empty, not degraded)", async () => {
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "t", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: {} },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.worked).toBe(true);
    expect(r.degradedReason).toBeUndefined();
  });

  it("worked:true (no degradedReason) for an aborted run — analyst-stopped is not degraded (codex C1)", async () => {
    const { client } = scriptedClient([findingsTurn('```json\n{"findings":[]}\n```')]);
    const ctrl = new AbortController();
    ctrl.abort();
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4"), signal: ctrl.signal });
    expect(r.stopReason).toBe("aborted");
    expect(r.worked).toBe(true); // worked:false is reserved for a tooling degradation, not an analyst stop
    expect(r.degradedReason).toBeUndefined();
  });

  it("worked:true when findings surface even with no successful tool (salvaged-style)", async () => {
    const { client } = scriptedClient([
      findingsTurn('```json\n{"findings":[{"entity":"a.com","entity_type":"domain"}]}\n```'),
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.worked).toBe(true);
  });

  it("kweb-live-graph: onObserved fires per SUCCESSFUL tool with its target + entities", async () => {
    const events: ObservedEvent[] = [];
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "tu1", name: "dns_lookup", input: { domain: "fifa-hr.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    await investigate({
      objective: "x",
      client,
      runTool: async () => ({ content: "{}", is_error: false, entities: [{ type: "ip", value: "91.195.240.94" }], provider: "dns.google" }),
      onObserved: (ev) => events.push(ev),
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ tool: "dns_lookup", target: "fifa-hr.com" });
    expect(events[0].entities.map((e) => e.value)).toEqual(["91.195.240.94"]);
  });

  it("kweb-live-graph: a FAILED tool does NOT fire onObserved (no live node for a dead lookup)", async () => {
    const events: ObservedEvent[] = [];
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "tu1", name: "dns_lookup", input: { domain: "x.com" } }], stop_reason: "tool_use", usage: {} },
      findingsTurn('```json\n{"findings":[]}\n```'),
    ]);
    await investigate({
      objective: "x",
      client,
      runTool: async () => ({ content: "boom", is_error: true, entities: [], provider: "dns.google" }),
      onObserved: (ev) => events.push(ev),
    });
    expect(events).toHaveLength(0);
  });

  it("maxTurns caps the loop with stopReason 'budget'", async () => {
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "t", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: {} },
      { content: [{ type: "tool_use", id: "t2", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: {} },
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4"), maxTurns: 1 });
    expect(r.stopReason).toBe("budget");
  });
});

// Issue kweb-salvage-01/02 + kweb-findings-cutoff: NO TURN LEASH + PREVENT-THE-CUTOFF + HONEST CUT-OFF
// ERROR. The cost budget, not a turn count, bounds a whole-case run. A max_tokens stop while the agent is
// writing its FINAL answer is CONTINUED across calls so a findings JSON that exceeds one call's output cap
// finishes (founder 2026-06-24, "prevent the cutoff"). A run that is GENUINELY cut off (continuation budget
// exhausted, a truncated tool_use, or a refusal) still saves NOTHING and reports an honest error — a
// half-run's partial findings are not reliable. No blind salvage of the agent's prose exists.
describe("investigate: prevent-the-cutoff + honest cut-off error (kweb-salvage-01/02, kweb-findings-cutoff)", () => {
  it("a run that NEVER finishes its findings JSON (continuation budget exhausted) saves NOTHING", async () => {
    // The agent keeps truncating its findings JSON every turn. After MAX_FINDINGS_CONTINUATIONS (4)
    // continuations the run is a genuine cutoff: nothing saved, honest error.
    const truncated = {
      content: [{ type: "text", text: '```json\n{"findings":[{"entity":"x",' }],
      stop_reason: "max_tokens",
      usage: { output_tokens: 16000 },
    };
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "fifa-tickets.com" } }],
        stop_reason: "tool_use", usage: { output_tokens: 10 } },
      truncated, truncated, truncated, truncated, truncated, // first truncation + 4 continuations, then give up
    ]);
    const r = await investigate({ objective: "investigate fifa-tickets.com", client, runTool: async () => ipTool("91.195.240.94") });
    expect(r.stopReason).toBe("incomplete");
    expect(r.promoted).toEqual([]); // a half-run saves nothing — no partial findings
    expect(r.leads).toEqual([]);
    expect(r.worked).toBe(false); // surfaced as an ERROR, not a clean "nothing to find"
    expect(r.degradedReason).toContain("cut off");
  });

  it("a refusal is a genuine cutoff — nothing saved, honest error (never continued)", async () => {
    const { client, requests } = scriptedClient([
      { content: [{ type: "text", text: "I can't help with that." }], stop_reason: "refusal", usage: {} },
    ]);
    const r = await investigate({ objective: "x", client, runTool: async () => ipTool("1.2.3.4") });
    expect(r.promoted).toEqual([]);
    expect(r.leads).toEqual([]);
    expect(r.worked).toBe(false);
    expect(r.degradedReason).toContain("cut off");
    expect(requests.length).toBe(1); // a refusal is not continued
  });

  it("aborted (analyst Stop) saves nothing but is NOT an error (worked:true, no cut-off reason)", async () => {
    const ctrl = new AbortController();
    const { client, requests } = scriptedClient([
      { content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "a.com" } }],
        stop_reason: "tool_use", usage: {} },
    ]);
    const r = await investigate({
      objective: "x", client, signal: ctrl.signal,
      runTool: async () => { ctrl.abort(); return ipTool("1.2.3.4"); },
    });
    expect(r.stopReason).toBe("aborted");
    expect(r.promoted).toEqual([]);
    expect(r.leads).toEqual([]);
    expect(r.worked).toBe(true); // analyst's choice — not a degradation
    expect(r.degradedReason).toBeUndefined();
    expect(requests.length).toBe(1);
  });

  it("no-turn-leash: a run past the OLD 28-turn cap continues to its clean end_turn", async () => {
    // Script 30 tool_use turns then a clean end_turn with findings. With the old DEEP_MAX_TURNS=28
    // cap (passed verbatim as maxTurns), the loop stopped at turn 28 and returned nothing; with the cap
    // raised to a high runaway-backstop, the budget — not a turn count — bounds the run, so it reaches
    // the real end_turn and returns a FULL result. Robust to the exact backstop value (> 30).
    expect(DEEP_MAX_TURNS).toBeGreaterThan(30);
    const turns: Payload[] = [];
    for (let i = 0; i < 30; i++) {
      turns.push({ content: [{ type: "tool_use", id: `t${i}`, name: "dns_lookup", input: { domain: `host${i}.com` } }],
        stop_reason: "tool_use", usage: { output_tokens: 5 } });
    }
    turns.push(findingsTurn('done\n```json\n{"findings":[{"entity":"1.2.3.4","entity_type":"ip","confidence":"high"}]}\n```'));
    const { client } = scriptedClient(turns);
    const r = await investigate({ objective: "whole case", client, runTool: async () => ipTool("1.2.3.4"), maxTurns: DEEP_MAX_TURNS });
    expect(r.stopReason).toBe("end_turn");
    expect(r.promoted.map((f) => f.entity)).toContain("1.2.3.4");
  });
});

describe("extractFindings (strict, zero on parse failure)", () => {
  it("extracts the trailing fenced JSON, ignoring prose/thinking before it", () => {
    const t = "Some reasoning.\nMore.\n```json\n{\"findings\":[{\"entity\":\"a.com\",\"entity_type\":\"domain\"}]}\n```";
    expect(extractFindings(t)).toHaveLength(1);
  });
  it("returns [] on malformed JSON and on truncation", () => {
    expect(extractFindings('```json\n{"findings":[{"entity":"a.com"')).toEqual([]); // truncated, no fence close
    expect(extractFindings("no json here at all")).toEqual([]);
    expect(extractFindings('```json\n{"findings": not-json}\n```')).toEqual([]);
  });
  it("parses a bare {\"findings\"...} object when unfenced", () => {
    expect(extractFindings('chatter {"findings":[{"entity":"a.com","entity_type":"domain"}]} tail')).toHaveLength(1);
  });
});

// PRD-B agent-completeness-stop: the loop nudges the agent to keep digging while it has surfaced
// pivotable entities it has not worked — bounded by a nudge budget + a plateau guard.
describe("investigate: completeness stop (PRD-B)", () => {
  // a tool that surfaces TWO IPs; the agent reports only one → the other is a DROPPED discovery.
  const twoIpTool = (): ToolOutcome => ({
    content: JSON.stringify({ provider: "dns", entities: [{ type: "ip", value: "9.9.9.9" }, { type: "ip", value: "8.8.8.8" }] }),
    is_error: false,
    entities: [{ type: "ip", value: "9.9.9.9" }, { type: "ip", value: "8.8.8.8" }],
    provider: "dns",
  });

  it("nudges-continues when a discovered target was neither worked NOR reported, then stops on plateau", async () => {
    const { client, requests } = scriptedClient([
      {
        content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }],
        stop_reason: "tool_use",
        usage: { output_tokens: 10 },
      },
      // first end_turn: reports 9.9.9.9 but NOT 8.8.8.8 (a dropped discovery) → the loop nudges.
      findingsTurn('done\n```json\n{"findings":[{"entity":"9.9.9.9","entity_type":"ip","confidence":"high"}]}\n```'),
      // second end_turn after the nudge: no new tool ran → plateau → the loop accepts it.
      findingsTurn('still done\n```json\n{"findings":[{"entity":"9.9.9.9","entity_type":"ip","confidence":"high"}]}\n```'),
    ]);
    const res = await investigate({ client, objective: "look at example.com", runTool: async () => twoIpTool() });
    // 3 requests = tool turn + the nudged extra end_turn (without the stop it would be 2: tool + end_turn).
    expect(requests.length).toBe(3);
    expect(res.stopReason).toBe("end_turn");
    expect(JSON.stringify(requests[2])).toContain("8.8.8.8"); // the nudge named the dropped lead
  });

  it("codex C2: a nudge never DOWNGRADES the result — the richest end_turn's findings survive", async () => {
    const { client } = scriptedClient([
      {
        content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }],
        stop_reason: "tool_use",
        usage: { output_tokens: 10 },
      },
      // first end_turn reports 9.9.9.9 (rich) but drops 8.8.8.8 → nudge.
      findingsTurn('found it\n```json\n{"findings":[{"entity":"9.9.9.9","entity_type":"ip","confidence":"high"}]}\n```'),
      // nudged end_turn is EMPTY (the model wandered) → plateau accept, but the result must KEEP 9.9.9.9.
      findingsTurn('on second thought, nothing\n```json\n{"findings":[]}\n```'),
    ]);
    const res = await investigate({ client, objective: "x", runTool: async () => twoIpTool() });
    const all = res.promoted.concat(res.leads.map((l) => l.finding)).map((f) => f.entity);
    expect(all).toContain("9.9.9.9"); // negative proof: without the best-findings guard this would be [] (the empty turn)
  });

  it("does NOT nudge when every surfaced target was reported as a finding (accounted for)", async () => {
    const { client, requests } = scriptedClient([
      {
        content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }],
        stop_reason: "tool_use",
        usage: { output_tokens: 10 },
      },
      // reports BOTH surfaced IPs → nothing dropped → the first end_turn is accepted (negative proof).
      findingsTurn('done\n```json\n{"findings":[{"entity":"9.9.9.9","entity_type":"ip","confidence":"high"},{"entity":"8.8.8.8","entity_type":"ip","confidence":"high"}]}\n```'),
    ]);
    const res = await investigate({ client, objective: "look at example.com", runTool: async () => twoIpTool() });
    expect(requests.length).toBe(2); // tool turn + the accepted end_turn — no nudge
    expect(res.stopReason).toBe("end_turn");
  });
});
