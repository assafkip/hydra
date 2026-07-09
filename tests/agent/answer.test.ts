import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, answerQuestion, SessionError } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// cd-grounding (D2): the session-layer answerQuestion — no-tools, grounded ONLY on run: records,
// key redacted from context + question + output, empty-evidence short-circuit with NO model call.

async function vaultWithKey(key = "sk-ant-answer"): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

function qaFetch(text: string): { impl: FetchLike; calls: { body: string }[] } {
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

describe("answerQuestion grounded path", () => {
  it("answers from run findings and returns cited sources", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl, calls } = qaFetch("live.example.com is the operating domain [run: Investigate live.example.com].");
    const { answer, sources } = await answerQuestion(vault, "what is operating?", { fetchImpl: impl });
    expect(answer).toContain("live.example.com");
    expect(calls).toHaveLength(1); // the model WAS called
    expect(calls[0].body).toContain("live.example.com"); // the evidence reached the model
    expect(calls[0].body).toContain("what is operating?");
    expect(calls[0].body).not.toContain("(oldest first"); // negative: no history -> no history block
    expect(sources).toEqual([
      { run: "Investigate live.example.com", entity: "live.example.com", entity_type: "domain", status: "promoted" },
    ]);
  });
});

describe("A5 answerQuestion map-reduce sweep (large case is swept, never silently capped)", () => {
  // a prompt-aware fake: the MAP pass (GROUNDING_MAP_PERSONA — "Extract every fact") returns an extract;
  // the REDUCE pass returns the composed answer. Lets us assert the two-stage sweep ran.
  function sweepFetch(): { impl: FetchLike; calls: { body: string; isMap: boolean }[] } {
    const calls: { body: string; isMap: boolean }[] = [];
    const impl = (async (_url: string, init: RequestInit) => {
      const body = String(init.body);
      const isMap = body.includes("Extract every fact");
      calls.push({ body, isMap });
      const text = isMap
        ? "live.example.com is live [run: big]"
        : "The case operates from live.example.com [run: big].";
      return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) };
    }) as unknown as FetchLike;
    return { impl, calls };
  }

  it("sweeps a >cap case in MAP batches + a REDUCE, and reports partial-or-full coverage", async () => {
    const vault = await vaultWithKey();
    const many = Array.from({ length: 200 }, (_, i) => ({ entity: `e${i}.example.com`, entity_type: "domain", grade: "B" }));
    await vault.put("run:big", { objective: "big", steps: [], promoted: many, leads: [], usage: {}, stopReason: "end_turn" });
    const { impl, calls } = sweepFetch();
    const res = await answerQuestion(vault, "what is live?", { fetchImpl: impl });
    expect(calls.filter((c) => c.isMap).length).toBeGreaterThan(1); // multiple MAP batches — the WHOLE case swept
    expect(calls.filter((c) => !c.isMap).length).toBe(1); // exactly one REDUCE
    expect(res.answer).toContain("live.example.com");
    expect(res.coverage.total).toBe(200); // coverage reports the true total — no silent cap
    expect(res.coverage.used).toBeGreaterThan(80); // swept more than the single-shot cap
  });

  it("surfaces an unverified citation: an answer fact the cited run doesn't contain is flagged", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    // the model hallucinates an IP the run never surfaced, but cites the run anyway.
    const { impl } = qaFetch("The host is 5.5.5.5 [run: Investigate live.example.com].");
    const res = await answerQuestion(vault, "what ip?", { fetchImpl: impl });
    expect(res.unsupportedCitations).toHaveLength(1);
    expect(res.unsupportedCitations[0].unsupportedFacts).toContain("5.5.5.5");
  });
});

describe("answerQuestion empty-evidence short-circuit", () => {
  it("returns the deterministic no-evidence answer with NO model call", async () => {
    const vault = await vaultWithKey();
    const { impl, calls } = qaFetch("should never be called");
    const { answer, sources } = await answerQuestion(vault, "who runs example.com?", { fetchImpl: impl });
    // cd-guidance (bug #3): the no-evidence reply GUIDES (it is no longer a dead "I don't know") —
    // it points at how to start + the help walkthrough, still with NO model call.
    expect(answer.toLowerCase()).toContain("no findings");
    expect(answer.toLowerCase()).toContain("investigate");
    expect(answer.toLowerCase()).toContain("help");
    expect(calls).toHaveLength(0); // no spend with no evidence
    expect(sources).toEqual([]);
  });

  it("no key with evidence present -> clean SessionError (never echoes vault state)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    await expect(answerQuestion(vault, "x")).rejects.toBeInstanceOf(SessionError);
  });
});

describe("answerQuestion KEY HYGIENE + exclusion", () => {
  it("redacts the key from the context, the question, and the output; excludes secret/brief/pivot", async () => {
    const KEY = "sk-ant-QA-REDACT-7";
    const vault = await vaultWithKey(KEY);
    // adversarial seeds: a run objective + finding carrying the key, plus brief/pivot/secret noise
    await vault.put(`run:probe ${KEY}`, {
      objective: `probe ${KEY}`,
      steps: [],
      promoted: [{ entity: "live.example.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2, note: KEY }],
      leads: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    });
    await vault.put("brief:noise", { objective: "noise", brief: `brief leaks ${KEY}` });
    await vault.put("pivot:noise", [{ provider: "dns", entities: [{ type: "ip", value: "9.9.9.9" }] }]);

    const { impl, calls } = qaFetch(`the model echoes ${KEY} and live.example.com`);
    const { answer, sources } = await answerQuestion(vault, `does ${KEY} matter?`, { fetchImpl: impl });

    // the request body (context + question) never carries the key, the brief, or the pivot
    expect(calls[0].body).not.toContain(KEY);
    expect(calls[0].body).not.toContain("brief leaks");
    expect(calls[0].body).not.toContain("9.9.9.9");
    // the answer redacts the key the model echoed
    expect(answer).not.toContain(KEY);
    // the sources never carry the key
    expect(JSON.stringify(sources)).not.toContain(KEY);
  });
});

// ---- co-investigator Q&A (founder 2026-07-03): follow-up memory + conclusions routing ----
// The two wiring gaps that made the chat dump-then-refuse: answerQuestion was STATELESS (a follow-up
// had no prior answer to compress) and every question got the flat per-fact voice. These tests pin the
// fix at the request layer: what actually reaches the wire.

describe("answerQuestion follow-up history (statelessness fix)", () => {
  it("threads the prior turns into the prompt so a follow-up can compress the previous answer", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl, calls } = qaFetch("Shorter: live.example.com is the operating domain [run: Investigate live.example.com].");
    const res = await answerQuestion(vault, "more succinctly", {
      fetchImpl: impl,
      history: [
        { role: "you", text: "what are the conclusions?" },
        { role: "agent", text: "PRIOR-ANSWER-MARKER: live.example.com is operating [run: Investigate live.example.com]." },
      ],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toContain("(oldest first"); // the history BLOCK (not just the persona) reached the wire
    expect(calls[0].body).toContain("PRIOR-ANSWER-MARKER"); // with the prior answer to compress
    expect(calls[0].body).toContain("more succinctly");
    expect(res.answer).toContain("live.example.com"); // a real answer, never the refusal
  });

  it("redacts the live key out of history turns before they reach the wire", async () => {
    const KEY = "sk-ant-history-leak-99";
    const vault = await vaultWithKey(KEY);
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl, calls } = qaFetch("ok");
    await answerQuestion(vault, "why?", {
      fetchImpl: impl,
      history: [{ role: "agent", text: `the key is ${KEY} and the domain is live.example.com` }],
    });
    expect(calls[0].body).not.toContain(KEY); // key hygiene holds for history too
    expect(calls[0].body).toContain("live.example.com");
  });
});

describe("answerQuestion conclusions routing (synthesis voice)", () => {
  it('routes "what are the conclusions" to the SYNTHESIS persona (connected picture, bottom line + next)', async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl, calls } = qaFetch("**Bottom line:** live.example.com is the operating hub [run: Investigate live.example.com]. **Next:** pivot its registrant.");
    await answerQuestion(vault, "what are the conclusions of the investigation?", { fetchImpl: impl });
    expect(calls[0].body).toContain("connected picture"); // SYNTHESIS_PERSONA marker in the system prompt
    expect(calls[0].body).toContain("key judgments");
  });

  it("a plain per-fact question keeps the grounded co-investigator persona, not the synthesis frame", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl, calls } = qaFetch("live.example.com [run: Investigate live.example.com].");
    await answerQuestion(vault, "what ip does the domain resolve to?", { fetchImpl: impl });
    expect(calls[0].body).not.toContain("connected picture"); // no synthesis frame
    expect(calls[0].body).toContain("co-investigator"); // the grounded analyst persona
  });
});
