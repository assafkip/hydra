import { describe, it, expect } from "vitest";
import { AnthropicClient } from "../../src/llm/client.js";
import type { FetchLike } from "../../src/osint/types.js";
import { buildDigest, synthesizeBrief, BRIEF_PERSONA, composeRunBriefing, RUN_BRIEFING_PERSONA } from "../../src/agent/synthesize.js";
import type { Finding, GateVerdict } from "../../src/agent/gate.js";

const live: Finding = { entity: "live.example.com", entity_type: "domain", grade: "A", infra_source_count: 2, source_count: 2 };
const dormant: Finding = { entity: "Old Seed", entity_type: "person", grade: "B", infra_source_count: 1, source_count: 2 };
const lead = { finding: { entity: "jdoe", entity_type: "handle" } as Finding, verdict: { promote: false, grade: "C", reason: "no crosslink" } as GateVerdict };

function capturingClient(payload: unknown): { client: AnthropicClient; bodies: Record<string, unknown>[] } {
  const bodies: Record<string, unknown>[] = [];
  const impl = (async (_url: string, init: RequestInit) => {
    bodies.push(JSON.parse(String(init.body)));
    return { ok: true, status: 200, json: async () => payload };
  }) as unknown as FetchLike;
  return { client: new AnthropicClient("sk-ant-x", impl), bodies };
}

describe("buildDigest", () => {
  it("tags operational status and puts LIVE infra first", () => {
    const d = buildDigest([dormant, live], [lead], [{ kind: "tool", tool: "dns_lookup", isError: false }]);
    expect(d).toContain("LIVE infrastructure");
    expect(d).toContain("live.example.com");
    // the LIVE section appears before the "Other confirmed" context section
    expect(d.indexOf("LIVE / operating now")).toBeLessThan(d.indexOf("Other confirmed"));
    expect(d).toContain("no crosslink"); // lead reason carried for Open questions
    expect(d).toContain("dns_lookup");
  });

  it("PRD-B: feeds the agent's per-finding CLAIM into the digest (model-input restoration)", () => {
    const withClaim: Finding = { entity: "scam.example", entity_type: "domain", grade: "A", infra_source_count: 1, claim: "resolves to the payout host 9.9.9.9" };
    const d = buildDigest([withClaim], [], []);
    expect(d).toContain("resolves to the payout host 9.9.9.9"); // the claim reaches the model
    // NEGATIVE: a finding without a claim adds no trailing ' — ' claim segment beyond its status line.
    const noClaim = buildDigest([live], [], []);
    expect(noClaim).not.toContain("undefined");
  });
});

describe("BRIEF_PERSONA section model (PRD-B synthesize-sections)", () => {
  it("instructs at least 14 DISTINCT brief sections (restored from the thinned 6)", () => {
    const headers = new Set((BRIEF_PERSONA.match(/## [A-Z][a-zA-Z ]+/g) ?? []).map((h) => h.trim()));
    expect(headers.size).toBeGreaterThanOrEqual(14); // negative: the thinned port had 6
    // the restored richer sections are present
    expect(BRIEF_PERSONA).toContain("## Target dossiers");
    expect(BRIEF_PERSONA).toContain("## Indicators of compromise");
    expect(BRIEF_PERSONA).toContain("## Attribution verdicts");
  });
});

// video-review 2026-06-25: the co-investigator run briefing — the agent's actual "where we stand" reply that
// replaced the hardcoded count line ("N promoted, N leads"). Reference: 4_points case-037 op log.
describe("composeRunBriefing (co-investigator reply)", () => {
  it("is a SHORT no-tools call: objective + findings in the user msg, the co-investigator persona as system", async () => {
    const { client, bodies } = capturingClient({ content: [{ type: "text", text: "We were after live.example.com.\n## What I found\nConfirmed the host.\n## What I think\nLive infra.\n## Where I'd go next\nDig the host." }], stop_reason: "end_turn", usage: {} });
    const out = await composeRunBriefing({ objective: "Investigate live.example.com", promoted: [live], leads: [lead], stopReason: "end_turn", pivots: ["next-seed.com"], client });
    expect(out).toContain("What I found");
    const body = bodies[0];
    expect(body.tools).toBeUndefined(); // never tools on a briefing
    expect(Array.isArray(body.system) ? (body.system as { text: string }[])[0].text : body.system).toBe(RUN_BRIEFING_PERSONA);
    const msg = (body.messages as { content: string }[])[0].content;
    expect(msg).toContain("live.example.com"); // the finding reaches the model
    expect(msg).toContain("next-seed.com"); // the still-uninvestigated pivot feeds the "Next" move
    expect(msg).toContain("end_turn"); // the stop reason is honest input
    expect(RUN_BRIEFING_PERSONA).not.toContain("live.example.com"); // run material is NOT baked into the cached persona
  });

  it("returns '' on a max_tokens truncation so the caller falls back to the deterministic count line", async () => {
    const { client } = capturingClient({ content: [{ type: "text", text: "half a brief" }], stop_reason: "max_tokens", usage: {} });
    expect(await composeRunBriefing({ objective: "x", promoted: [live], leads: [], client })).toBe("");
  });

  it("the persona demands the plain-words 3-part close (objective, confirmed-vs-lead, gap, what-found/think/next)", () => {
    const p = RUN_BRIEFING_PERSONA.toLowerCase();
    expect(p).toContain("objective");
    expect(p).toContain("confirmed");
    expect(p).toContain("lead");
    expect(p).toContain("gap");
    // plain-words-legs (2026-07-08): the three headed sections that close every leg
    expect(p).toContain("what i found");
    expect(p).toContain("what i think");
    expect(p).toContain("where i'd go next");
  });
});

describe("synthesizeBrief", () => {
  it("sends a NO-TOOLS bounded request with the persona as system and run material in the user msg", async () => {
    const { client, bodies } = capturingClient({ content: [{ type: "text", text: "# Investigation brief\n..." }], stop_reason: "end_turn", usage: {} });
    const r = await synthesizeBrief({ objective: "Investigate live.example.com", promoted: [live], leads: [lead], steps: [], client, maxTokens: 1200 });
    expect(r.ok).toBe(true);
    expect(r.brief).toContain("Investigation brief");
    const body = bodies[0];
    expect(body.tools).toBeUndefined(); // NO tools on the brief request
    expect(body.max_tokens).toBe(1200); // bounded
    expect(Array.isArray(body.system) ? (body.system as { text: string }[])[0].text : body.system).toBe(BRIEF_PERSONA);
    // run/objective material lives in the user message, not the cached persona
    const msg = (body.messages as { content: string }[])[0].content;
    expect(msg).toContain("live.example.com");
    expect(BRIEF_PERSONA).not.toContain("live.example.com");
  });

  it("treats a max_tokens truncation as a clean non-persisted failure", async () => {
    const { client } = capturingClient({ content: [{ type: "text", text: "half a bri" }], stop_reason: "max_tokens", usage: {} });
    const r = await synthesizeBrief({ objective: "x", promoted: [live], leads: [], steps: [], client });
    expect(r.ok).toBe(false);
    expect(r.brief.toLowerCase()).toContain("truncated");
  });

  it("NEVER retries an externally aborted brief (the user pressed Stop)", async () => {
    let calls = 0;
    const impl = (async () => {
      calls++;
      return { ok: true, status: 200, json: async () => ({ content: [], stop_reason: "end_turn", usage: {} }) };
    }) as unknown as FetchLike;
    const client = new AnthropicClient("sk-ant-x", impl);
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      synthesizeBrief({ objective: "x", promoted: [live], leads: [], steps: [], client, signal: ctrl.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(calls).toBe(0); // aborted before the request
  });

  it("retries ONCE on an internal timeout, then succeeds", async () => {
    let calls = 0;
    const impl = (async (_url: string, init: RequestInit) => {
      calls++;
      if (calls === 1) {
        // hang until the internal timeout aborts this attempt
        await new Promise<void>((_res, rej) => {
          init.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")), { once: true });
        });
      }
      return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: "BRIEF OK" }], stop_reason: "end_turn", usage: {} }) };
    }) as unknown as FetchLike;
    const client = new AnthropicClient("sk-ant-x", impl);
    const r = await synthesizeBrief({ objective: "x", promoted: [live], leads: [], steps: [], client, timeoutMs: 5 });
    expect(r.ok).toBe(true);
    expect(r.brief).toBe("BRIEF OK");
    expect(calls).toBe(2); // one timed-out attempt + one success
  });
});
