import { describe, it, expect } from "vitest";
import {
  buildGroundingContext,
  buildGroundingBatches,
  caseInvestigationLevel,
  isInvestigated,
  hardTokens,
  verifyCitations,
  type GroundingSource,
  type VaultEntry,
} from "../../src/chat/grounding.js";

// cd-grounding (D9): the PURE inclusion/exclusion contract. Only run: promoted findings + held
// leads are evidence; briefs, pivots, and the secret: namespace are dropped.

function runEntry(objective: string, promoted: unknown[], leads: unknown[] = []): VaultEntry {
  return { key: `run:${objective}`, value: { objective, promoted, leads } };
}

const FINDING = { entity: "live.example.com", entity_type: "domain", grade: "A", source_count: 2 };
const LEAD = { finding: { entity: "Jane Roe", entity_type: "person" }, verdict: { promote: false, grade: "D", reason: "name only" } };

describe("buildGroundingContext inclusion", () => {
  it("includes promoted findings and held leads with the [run: …] citation", () => {
    const ctx = buildGroundingContext([runEntry("Investigate example.com", [FINDING], [LEAD])]);
    expect(ctx.hasEvidence).toBe(true);
    expect(ctx.text).toContain("[run: Investigate example.com]");
    expect(ctx.text).toContain("live.example.com (domain) — promoted finding");
    expect(ctx.text).toContain("Jane Roe (person) — held lead: name only");
    expect(ctx.sources).toEqual([
      { run: "Investigate example.com", entity: "live.example.com", entity_type: "domain", status: "promoted" },
      { run: "Investigate example.com", entity: "Jane Roe", entity_type: "person", status: "lead" },
    ]);
  });
});

describe("buildGroundingContext exclusion", () => {
  it("drops briefs, pivots, and the secret namespace — only run: records contribute", () => {
    const entries: VaultEntry[] = [
      { key: "brief:Investigate example.com", value: { objective: "x", brief: "live.fake.com is operating" } },
      { key: "pivot:example.com", value: [{ provider: "dns", entities: [{ type: "ip", value: "1.2.3.4" }] }] },
      { key: "secret:anthropic_key", value: "sk-ant-SHOULD-NEVER-APPEAR" },
      runEntry("Investigate example.com", [FINDING]),
    ];
    const ctx = buildGroundingContext(entries);
    expect(ctx.sources).toHaveLength(1);
    expect(ctx.sources[0].entity).toBe("live.example.com");
    expect(ctx.text).not.toContain("live.fake.com"); // brief content excluded
    expect(ctx.text).not.toContain("1.2.3.4"); // pivot content excluded
    expect(JSON.stringify(ctx)).not.toContain("sk-ant-SHOULD-NEVER-APPEAR"); // secret never read in
  });

  it("empty / malformed runs yield no evidence (the short-circuit signal)", () => {
    expect(buildGroundingContext([]).hasEvidence).toBe(false);
    expect(buildGroundingContext([runEntry("ran nothing", [])]).hasEvidence).toBe(false);
    expect(buildGroundingContext([{ key: "run:bad", value: null }]).hasEvidence).toBe(false);
    expect(buildGroundingContext([{ key: "run:bad", value: { promoted: "notarray" } }]).hasEvidence).toBe(false);
    // a non-finding object is skipped
    expect(buildGroundingContext([runEntry("x", [{ nope: true }])]).hasEvidence).toBe(false);
  });
});

describe("buildGroundingContext caps", () => {
  it("caps the number of sources so a huge case cannot blow the budget", () => {
    const many = Array.from({ length: 500 }, (_, i) => ({ entity: `e${i}.example.com`, entity_type: "domain" }));
    const ctx = buildGroundingContext([runEntry("big", many)]);
    expect(ctx.sources.length).toBeLessThanOrEqual(80);
    expect(ctx.hasEvidence).toBe(true);
  });
});

// ---- A5: coverage reporting (full vs partial — never a silent truncation) ----
describe("A5 grounding coverage (ask.py:select)", () => {
  it("reports FULL coverage when the whole case fits", () => {
    const ctx = buildGroundingContext([runEntry("small", [FINDING], [LEAD])]);
    expect(ctx.coverage.mode).toBe("full");
    expect(ctx.coverage.total).toBe(2);
    expect(ctx.coverage.used).toBe(2);
  });

  it("reports PARTIAL coverage when the case exceeds the single-shot cap (no silent cap)", () => {
    const many = Array.from({ length: 200 }, (_, i) => ({ entity: `e${i}.example.com`, entity_type: "domain" }));
    const ctx = buildGroundingContext([runEntry("big", many)]);
    expect(ctx.coverage.mode).toBe("partial"); // the analyst is TOLD it is partial
    expect(ctx.coverage.total).toBe(200);
    expect(ctx.coverage.used).toBeLessThan(200);
  });

  it("empty case reports full/0/0", () => {
    const ctx = buildGroundingContext([]);
    expect(ctx.coverage).toEqual({ mode: "full", total: 0, used: 0 });
  });
});

// ---- A5: map-reduce sweep batches (ask.py:_sweep — read the WHOLE case, not the first 80) ----
describe("A5 buildGroundingBatches", () => {
  it("splits the whole case into batches that cover EVERY finding (no cap loss)", () => {
    const many = Array.from({ length: 200 }, (_, i) => ({ entity: `e${i}.example.com`, entity_type: "domain" }));
    const batches = buildGroundingBatches([runEntry("big", many)]);
    const totalSources = batches.reduce((n, b) => n + b.sources.length, 0);
    expect(batches.length).toBeGreaterThan(1);
    expect(totalSources).toBe(200); // every finding is in some batch — the whole case is swept
  });
  it("empty case yields no batches", () => {
    expect(buildGroundingBatches([])).toEqual([]);
  });
});

// ---- A5: citation verification (ask.py:_verify_citations + verify.hard_tokens) ----
describe("A5 hardTokens + verifyCitations", () => {
  it("extracts ISO date / IPv4 / email / ETH wallet as hard facts; nothing from a soft claim", () => {
    expect([...hardTokens("seen 2026-06-22 at 9.9.9.9 from a@b.io and 0x" + "a".repeat(40))].sort()).toEqual(
      ["0x" + "a".repeat(40), "2026-06-22", "9.9.9.9", "a@b.io"].sort(),
    );
    expect(hardTokens("the operator likely runs the campaign").size).toBe(0);
  });

  it("does NOT extract a partial IP from an over-long dotted run (sp-e8a3c054, lockstep with verify.py)", () => {
    // 5+ octets are not valid IPv4; the old \\b...\\b regex wrongly yielded 1.2.3.4. Fail closed.
    expect(hardTokens("host is 1.2.3.4.5 today").size).toBe(0);
    expect(hardTokens("upgraded to version 1.2.3.4.5.6").size).toBe(0);
    expect(hardTokens("seq 0.1.2.3.4 here").size).toBe(0);
    // word-boundary parity with the old \\b...\\b regex (codex: don't over-extract from identifiers):
    expect(hardTokens("build foo1.2.3.4 failed").size).toBe(0);
    expect(hardTokens("host 1.2.3.4beta").size).toBe(0);
    expect(hardTokens("id_1.2.3.4 here").size).toBe(0);
    // explicit ASCII classes keep Python(\\d=Unicode)/JS(\\d=ASCII) lockstep (codex finding-2):
    expect([...hardTokens("ip ٦1.2.3.4 x")]).toEqual(["1.2.3.4"]); // Arabic-Indic digit not absorbed
    expect([...hardTokens("ip １1.2.3.4 x")]).toEqual(["1.2.3.4"]); // fullwidth digit not absorbed
    // must not over-reject real IPv4 in normal contexts:
    expect(hardTokens("resolves to 1.2.3.4 now").has("1.2.3.4")).toBe(true);
    expect(hardTokens("resolves to 9.9.9.9.").has("9.9.9.9")).toBe(true); // sentence-ending period
    expect(hardTokens("server (192.168.0.1) down").has("192.168.0.1")).toBe(true);
  });

  it("ISO date uses explicit ASCII classes + lookaround boundaries (sp-cbeb7d29, lockstep with verify.py)", () => {
    // The divergence is Python-side (its \d/\b are Unicode-aware, JS's are ASCII): Python over-extracted
    // an Arabic-Indic / fullwidth date as a hard token while JS did not. JS already rejects these — these
    // assertions lock the invariant so a future JS rewrite using \d can't reintroduce the drift.
    expect(hardTokens("seen ٢٠٢٦-٠٦-٢٢ today").size).toBe(0); // Arabic-Indic date not extracted
    expect(hardTokens("seen ２０２６-０６-２２ today").size).toBe(0); // fullwidth date not extracted
    // word-boundary parity (don't over-extract from identifiers):
    expect(hardTokens("rev2026-06-22 here").size).toBe(0);
    expect(hardTokens("date 2026-06-22x here").size).toBe(0);
    expect(hardTokens("id_2026-06-22 here").size).toBe(0);
    expect(hardTokens("ref 2026-06-220 here").size).toBe(0);
    // must not over-reject real ISO dates in normal contexts:
    expect(hardTokens("seen 2026-06-22 now").has("2026-06-22")).toBe(true);
    expect(hardTokens("dated 2026-06-22.").has("2026-06-22")).toBe(true); // sentence-ending period
    expect(hardTokens("filed (2026-06-22) ok").has("2026-06-22")).toBe(true);
  });

  it("flags an answer sentence that cites a run NOT containing the asserted hard fact (hallucinated cite)", () => {
    const sources: GroundingSource[] = [
      { run: "r1", entity: "9.9.9.9", entity_type: "ip", status: "promoted" },
      { run: "r1", entity: "good.com", entity_type: "domain", status: "promoted" },
    ];
    // sentence 1: cites a fact that IS in r1 → supported. sentence 2: cites an IP r1 does NOT contain.
    const answer = "The host 9.9.9.9 is live [run: r1]. It also resolves 5.5.5.5 [run: r1].";
    const bad = verifyCitations(answer, sources);
    expect(bad).toHaveLength(1);
    expect(bad[0].unsupportedFacts).toContain("5.5.5.5");
    expect(bad[0].runs).toContain("r1");
  });

  it("does NOT flag a soft (uncited or fact-free) sentence", () => {
    const sources: GroundingSource[] = [{ run: "r1", entity: "good.com", entity_type: "domain", status: "promoted" }];
    expect(verifyCitations("The operator is sophisticated [run: r1]. good.com is theirs.", sources)).toEqual([]);
  });

  it("does NOT self-flag a hard token that lives in the [run: …] LABEL, not the claim (codex Med)", () => {
    // a run named with a date/IP would otherwise make EVERY citation look unsupported.
    const sources: GroundingSource[] = [{ run: "case 2026-06-22", entity: "good.com", entity_type: "domain", status: "promoted" }];
    expect(verifyCitations("good.com is the operating domain [run: case 2026-06-22].", sources)).toEqual([]);
  });

  it("batches by CHAR budget + truncates a long lead reason so a MAP batch can't overflow (codex Med)", () => {
    const longReason = "x".repeat(5000);
    const lead = { finding: { entity: "lead.example.com", entity_type: "domain" }, verdict: { promote: false, reason: longReason } };
    const batches = buildGroundingBatches([runEntry("r", [], [lead])]);
    expect(batches.length).toBe(1);
    expect(batches[0].text.length).toBeLessThan(400); // the 5000-char reason was truncated, not passed whole
  });
});

// ch-gate-floor (controls-honesty / sp-2a98dc39): the honest investigation floor for the tradecraft gates.
// hasEvidence alone is true for ANY finding OR lead; the gate must NOT run a model pass on a case with only
// a stray thin lead (no finished run, no promoted finding) — it produced boilerplate the founder read as
// the gate lying. caseInvestigationLevel counts FINISHED agent runs + PROMOTED findings; isInvestigated
// gates the gate's input.
const PROMOTED = { entity: "live.example.com", entity_type: "domain", grade: "A", source_count: 2 };
const THIN_LEAD = { finding: { entity: "Jane Roe", entity_type: "person" }, verdict: { promote: false, grade: "D", reason: "name only" } };

describe("caseInvestigationLevel / isInvestigated (ch-gate-floor)", () => {
  it("empty case: not investigated (0 runs, 0 findings)", () => {
    expect(caseInvestigationLevel([])).toEqual({ finishedRuns: 0, promotedFindings: 0 });
    expect(isInvestigated([])).toBe(false);
  });

  it("thin-leads-only, NO finished run: NOT investigated (the sp-2a98dc39 case)", () => {
    // a run: record with only a lead and no stopReason and no promoted finding — e.g. a stray/orphaned lead
    const entries: VaultEntry[] = [{ key: "run:thin", value: { objective: "thin", promoted: [], leads: [THIN_LEAD] } }];
    expect(caseInvestigationLevel(entries)).toEqual({ finishedRuns: 0, promotedFindings: 0 });
    expect(isInvestigated(entries)).toBe(false);
  });

  it("a file-ingest report (sourceKind file_ingest), even with a stopReason, is NOT a finished agent run", () => {
    const entries: VaultEntry[] = [{ key: "run:report", value: { objective: "report", sourceKind: "file_ingest", stopReason: "end_turn", promoted: [], leads: [] } }];
    expect(caseInvestigationLevel(entries).finishedRuns).toBe(0);
    expect(isInvestigated(entries)).toBe(false);
  });

  it("an OSINT enrichment record (sourceKind enrich) is NOT a finished agent run (codex: 3rd run: class)", () => {
    // enrich records set sourceKind=stopReason="enrich"; a thin enrich-only case must stay NOT investigated
    const entries: VaultEntry[] = [{ key: "run:enrich", value: { objective: "1.2.3.4", sourceKind: "enrich", stopReason: "enrich", promoted: [], leads: [THIN_LEAD] } }];
    expect(caseInvestigationLevel(entries)).toEqual({ finishedRuns: 0, promotedFindings: 0 });
    expect(isInvestigated(entries)).toBe(false);
  });

  it("a record with an UNKNOWN future sourceKind + stopReason is NOT counted (fail-closed)", () => {
    const entries: VaultEntry[] = [{ key: "run:future", value: { objective: "x", sourceKind: "some_future_kind", stopReason: "done", promoted: [], leads: [] } }];
    expect(caseInvestigationLevel(entries).finishedRuns).toBe(0);
    expect(isInvestigated(entries)).toBe(false);
  });

  it("a finished agent run (no ingest sourceKind, has a stopReason): INVESTIGATED — gate may run", () => {
    const entries: VaultEntry[] = [{ key: "run:agent", value: { objective: "investigate evil.com", stopReason: "end_turn", promoted: [], leads: [THIN_LEAD] } }];
    expect(caseInvestigationLevel(entries)).toEqual({ finishedRuns: 1, promotedFindings: 0 });
    expect(isInvestigated(entries)).toBe(true);
  });

  it("a promoted finding (any run: record): INVESTIGATED — gate may run", () => {
    const entries: VaultEntry[] = [{ key: "run:r", value: { objective: "r", promoted: [PROMOTED], leads: [] } }];
    expect(caseInvestigationLevel(entries)).toEqual({ finishedRuns: 0, promotedFindings: 1 });
    expect(isInvestigated(entries)).toBe(true);
  });

  it("never counts the secret: namespace", () => {
    const entries: VaultEntry[] = [{ key: "secret:run:x", value: { stopReason: "end_turn", promoted: [PROMOTED] } }];
    expect(isInvestigated(entries)).toBe(false);
  });
});

// holistic-fix P2 (amnesia): the agent's TRAIL (reasoning notes + tool observations — the LOGS the
// founder reads in chat) is fed to Q&A as "observed" evidence, so a run that SAW something but did not
// PROMOTE it is still answerable. Before this, collectEvidence read only promoted+leads, so asking about
// a log line returned "I don't know from the investigation" (founder, 2026-07-03).
describe("buildGroundingContext — run steps become observed evidence (amnesia fix)", () => {
  const STEP_RUN: VaultEntry = {
    key: "run:Investigate evil.com",
    value: {
      objective: "Investigate evil.com",
      promoted: [], // NOTHING promoted — the answer must still come from the trail
      leads: [],
      steps: [
        { kind: "tool", tool: "dns_lookup", result: "evil.com resolves to 93.184.216.34" },
        { kind: "reasoning", text: "The IP 93.184.216.34 also hosts two sibling domains — likely a cluster." },
        { kind: "tool", tool: "rdap", isError: true },
      ],
    },
  };

  it("has evidence from steps alone (0 promoted, 0 leads)", () => {
    const ctx = buildGroundingContext([STEP_RUN]);
    expect(ctx.hasEvidence).toBe(true); // was FALSE before the fix -> NO_EVIDENCE_ANSWER
  });

  it("surfaces the tool observation and the reasoning note as evidence lines", () => {
    const ctx = buildGroundingContext([STEP_RUN]);
    expect(ctx.text).toContain("observed via dns_lookup: evil.com resolves to 93.184.216.34");
    expect(ctx.text).toContain("investigation note: The IP 93.184.216.34 also hosts two sibling domains");
    expect(ctx.text).toContain("observed via rdap: error");
  });

  it("marks step sources as 'observed' (distinct from promoted/lead)", () => {
    const ctx = buildGroundingContext([STEP_RUN]);
    expect(ctx.sources.every((s) => s.status === "observed")).toBe(true);
  });

  it("caps observed rows so a long run can't drown findings", () => {
    const manySteps = Array.from({ length: 100 }, (_, i) => ({ kind: "tool", tool: "t", result: `obs ${i}` }));
    const ctx = buildGroundingContext([{ key: "run:big", value: { objective: "big", promoted: [], leads: [], steps: manySteps } }]);
    const observedLines = ctx.text.split("\n").filter((l) => l.includes("observed via t:")).length;
    expect(observedLines).toBeLessThanOrEqual(24);
  });
});

// co-investigator (founder 2026-07-03): the evidence line carries the finding's grade + claim so the
// Q&A voice has material to reason across — bare entity names made every answer a list.
describe("evidence lines carry grade + claim", () => {
  it("a promoted finding's grade and (newline-collapsed, bounded) claim ride into its line", () => {
    const entries = [{
      key: "run:x",
      value: {
        objective: "x",
        promoted: [{ entity: "a.com", entity_type: "domain", grade: "B", claim: "registered by the same operator\nas b.com" }],
        leads: [],
      },
    }];
    const ctx = buildGroundingContext(entries);
    expect(ctx.text).toContain("a.com (domain) — promoted finding [grade B]: registered by the same operator as b.com");
  });
});
