// cd-grounding (PRD chat-dock D9): the PURE grounding-context builder for the chat's third mode
// (grounded Q&A). It is the single place that decides WHAT counts as case evidence: a question is
// answered ONLY from a run's promoted findings + held leads — never from briefs, OSINT pivots,
// the reserved secret: namespace, or any server-only placeholder the client does not have.
//
// It is vault-unaware + key-unaware (no DOM, no fetch): the session layer (answerQuestion) reads
// the vault, redacts the live key, and feeds the raw entries here. Keeping the selection logic
// pure makes the inclusion/exclusion contract node-testable.

import type { Finding, GateVerdict } from "../agent/gate.js";

/** One raw vault entry (key + decoded value) handed to the builder. */
export interface VaultEntry {
  key: string;
  value: unknown;
}

/** A cited source row — one promoted finding or one held lead from a run. */
export interface GroundingSource {
  run: string;
  entity: string;
  entity_type: string;
  // "observed" = a step the agent actually took during the run (a reasoning note or a tool result — the
  // LOGS). Added so Q&A can answer "what did the investigation find about X" from what the agent SAW, not
  // only from what it PROMOTED to a finding (holistic-fix P2: the amnesia bug, founder 2026-07-03).
  status: "promoted" | "lead" | "observed";
}

/** A5 (ask.py:156 select): full vs partial grounding so the analyst is TOLD when the answer did not
 *  see the whole case — never a silent cap (the original reports coverage; the first web port dropped it). */
export interface GroundingCoverage {
  mode: "full" | "partial"; // full ⇒ every finding/lead was fed; partial ⇒ the cap bit
  total: number; // findings + leads available across the case
  used: number; // how many were actually fed to the model
}

export interface GroundingContext {
  /** false ⇒ no findings/leads anywhere ⇒ answerQuestion takes its deterministic no-model code path
   *  (unit-tested: answer.test.ts empty-evidence short-circuit). */
  hasEvidence: boolean;
  /** The EVIDENCE block fed to the model (empty when hasEvidence is false). */
  text: string;
  sources: GroundingSource[];
  /** A5: coverage report (full vs partial) so a >cap case is never silently truncated. */
  coverage: GroundingCoverage;
}

const RUN_PREFIX = "run:";
const SECRET_PREFIX = "secret:";
const MAX_SOURCES = 80; // cap so a huge case can't blow the context / token budget (single-shot path)
const MAX_TEXT = 8000; // hard char cap on the EVIDENCE block
const SWEEP_BATCH_CHARS = MAX_TEXT; // A5 map-reduce: batch by CHARACTER budget (ask.py:_batch), not a fixed
const SWEEP_ROW_CHARS = 200; // cap ONE evidence line so a long lead reason can't make a single batch overflow the window

interface RunShape {
  objective?: unknown;
  promoted?: unknown;
  leads?: unknown;
  // ch-gate-floor: the run: namespace is THREE-way (codex): a file-ingest report (sourceKind="file_ingest"),
  // an OSINT enrichment (sourceKind="enrich"), and an AGENT investigation run — which deliberately OMITS
  // sourceKind (it is the non-forgeable discriminator the briefs engine + Inbox split on; session.ts line
  // 425). Only an agent run is a "finished investigation" for the floor; both other kinds SET sourceKind,
  // so "no sourceKind + a stopReason" isolates agent runs and fail-closes against any future kind.
  sourceKind?: unknown;
  stopReason?: unknown;
  steps?: unknown; // the agent's trail (reasoning + tool results) — the LOGS; fed to Q&A as "observed" evidence
}

function isFinding(v: unknown): v is Finding {
  return !!v && typeof v === "object" && typeof (v as Finding).entity === "string" && typeof (v as Finding).entity_type === "string";
}

/** One evidence row: its cited source + the line shown in the EVIDENCE block + the run it belongs to. */
interface EvidenceRow {
  source: GroundingSource;
  line: string;
  run: string;
}

/** Flatten EVERY run's promoted findings + held leads into evidence rows — UNCAPPED, so the caller can
 *  report true coverage and the sweep path can read the whole case. ONLY `run:` entries (never secret:).
 *  Pure (D9): the exclusion contract is unchanged; this just stops capping at the collection step. */
function collectEvidence(entries: VaultEntry[]): EvidenceRow[] {
  const rows: EvidenceRow[] = [];
  for (const { key, value } of entries) {
    if (!key.startsWith(RUN_PREFIX) || key.startsWith(SECRET_PREFIX)) continue; // run: only, never secret:
    if (!value || typeof value !== "object") continue;
    const rec = value as RunShape;
    const objective = typeof rec.objective === "string" ? rec.objective : key.slice(RUN_PREFIX.length);
    if (!objective) continue;
    const promoted = Array.isArray(rec.promoted) ? rec.promoted : [];
    for (const f of promoted) {
      if (!isFinding(f)) continue;
      // co-investigator (founder 2026-07-03): feed the finding's GRADE + CLAIM into the evidence line,
      // not just its name. The persona is told to reason ACROSS findings — with bare entity names it had
      // nothing to reason WITH, so answers read as lists. Claim is normalized to one bounded line (same
      // injection guard as buildDigest's cleanClaim) so model-authored text can't escape its bullet.
      const claim = typeof (f as { claim?: unknown }).claim === "string"
        ? clip(((f as { claim: string }).claim).replace(/[\u0000-\u001f]+/g, " ").replace(/\s+/g, " ").trim(), CLAIM_EVIDENCE_CHARS)
        : "";
      const grade = typeof (f as { grade?: unknown }).grade === "string" ? ` [grade ${(f as { grade: string }).grade}]` : "";
      rows.push({ run: objective, source: { run: objective, entity: f.entity, entity_type: f.entity_type, status: "promoted" },
                  line: `- ${f.entity} (${f.entity_type}) — promoted finding${grade}${claim ? `: ${claim}` : ""}` });
    }
    const leads = Array.isArray(rec.leads) ? rec.leads : [];
    for (const l of leads) {
      const finding = (l as { finding?: unknown })?.finding;
      const verdict = (l as { verdict?: unknown })?.verdict as GateVerdict | undefined;
      if (!isFinding(finding)) continue;
      const reason = verdict && typeof verdict.reason === "string" ? verdict.reason : "held lead";
      rows.push({ run: objective, source: { run: objective, entity: finding.entity, entity_type: finding.entity_type, status: "lead" },
                  line: `- ${finding.entity} (${finding.entity_type}) — held lead: ${reason}` });
    }
    // holistic-fix P2 (amnesia): also feed the agent's TRAIL — the reasoning notes + tool observations the
    // founder reads in the logs — as "observed" evidence, so Q&A can answer about what the run SAW, not
    // only what it promoted. Capped + truncated so a long run can't drown the findings; redaction happens
    // downstream (answerQuestion redacts the composed context) exactly as for promoted/lead lines.
    const steps = Array.isArray(rec.steps) ? rec.steps : [];
    let observedCount = 0;
    for (const s of steps) {
      if (observedCount >= STEP_EVIDENCE_CAP) break;
      if (!s || typeof s !== "object") continue;
      const step = s as { kind?: unknown; text?: unknown; tool?: unknown; result?: unknown; isError?: unknown };
      let line: string | null = null;
      if (step.kind === "tool" && typeof step.tool === "string") {
        const res = step.isError ? "error" : (typeof step.result === "string" ? clip(step.result, SWEEP_ROW_CHARS) : "no result");
        line = `- observed via ${step.tool}: ${res}`;
      } else if (step.kind === "reasoning" && typeof step.text === "string" && step.text.trim()) {
        line = `- investigation note: ${clip(step.text.trim(), SWEEP_ROW_CHARS)}`;
      }
      if (!line) continue;
      rows.push({ run: objective, source: { run: objective, entity: objective, entity_type: "observation", status: "observed" }, line });
      observedCount++;
    }
  }
  return rows;
}

const STEP_EVIDENCE_CAP = 24; // max "observed" (trail) rows per run — the logs inform Q&A without drowning findings
const CLAIM_EVIDENCE_CHARS = 160; // bound ONE finding's claim in its evidence line (MAX_TEXT still backstops the block)
function clip(s: string, n: number): string { return s.length > n ? s.slice(0, n) + "…" : s; }

// ch-gate-floor (controls-honesty / sp-2a98dc39): how substantively investigated a case is. A tradecraft
// gate (challenge/premortem) over a case with only a stray thin lead — no finished investigator run, no
// promoted finding — produced weak generic boilerplate the founder read as the gate "lying". This is the
// honest floor: count FINISHED AGENT RUNS (a run: record that carries a stopReason AND has NO sourceKind —
// agent runs omit it; file-ingest + enrichment both SET it, so this excludes both and fail-closes against
// any future non-agent kind, codex) and PROMOTED findings (any run: record with >=1 real finding in
// `promoted`). Pure over the raw entries (no vault) so it is unit-testable; runTradecraftGate blocks the
// model call when both are 0.
export interface CaseInvestigationLevel {
  finishedRuns: number;
  promotedFindings: number;
}

export function caseInvestigationLevel(entries: VaultEntry[]): CaseInvestigationLevel {
  let finishedRuns = 0;
  let promotedFindings = 0;
  for (const { key, value } of entries) {
    if (!key.startsWith(RUN_PREFIX) || key.startsWith(SECRET_PREFIX)) continue; // run: only, never secret:
    if (!value || typeof value !== "object") continue;
    const rec = value as RunShape;
    // an AGENT run omits sourceKind; file_ingest + enrich both set a non-empty sourceKind string (codex).
    const hasSourceKind = typeof rec.sourceKind === "string" && rec.sourceKind.length > 0;
    const stopReason = typeof rec.stopReason === "string" ? rec.stopReason.trim() : "";
    if (!hasSourceKind && stopReason) finishedRuns += 1; // a completed agent investigation run only
    if (Array.isArray(rec.promoted) && rec.promoted.some(isFinding)) promotedFindings += 1;
  }
  return { finishedRuns, promotedFindings };
}

/** True when the case has been substantively investigated: >=1 finished agent run OR >=1 promoted finding.
 *  A case with only thin leads (or only un-processed ingest) is NOT investigated — the gate says so plainly
 *  instead of running a thin model pass. */
export function isInvestigated(entries: VaultEntry[]): boolean {
  const level = caseInvestigationLevel(entries);
  return level.finishedRuns > 0 || level.promotedFindings > 0;
}

/** Group evidence rows into per-run text blocks (the `[run: …]` blocks the model + citations read). */
function blocksFor(rows: EvidenceRow[]): string[] {
  const byRun = new Map<string, string[]>();
  for (const r of rows) {
    const list = byRun.get(r.run);
    if (list) list.push(r.line);
    else byRun.set(r.run, [r.line]);
  }
  return [...byRun.entries()].map(([run, lines]) => `[run: ${run}]\n${lines.join("\n")}`);
}

/**
 * Build the SINGLE-SHOT grounding context (the small/medium case path). Sources + text are capped, but
 * `coverage` now reports full vs partial against the TRUE total (A5 ask.py:156 select) so a >cap case is
 * never silently truncated — answerQuestion switches to the sweep when coverage is partial.
 */
export function buildGroundingContext(entries: VaultEntry[]): GroundingContext {
  const all = collectEvidence(entries);
  if (!all.length) return { hasEvidence: false, text: "", sources: [], coverage: { mode: "full", total: 0, used: 0 } };
  const used = all.slice(0, MAX_SOURCES);
  let text = blocksFor(used).join("\n\n");
  let usedCount = used.length;
  if (text.length > MAX_TEXT) {
    // honour the hard char cap, but recompute how many rows actually fit so coverage is honest.
    text = text.slice(0, MAX_TEXT) + "\n… (evidence truncated)";
    usedCount = Math.min(usedCount, text.split("\n").filter((l) => l.startsWith("- ")).length);
  }
  const coverage: GroundingCoverage = {
    mode: all.length > usedCount ? "partial" : "full",
    total: all.length,
    used: usedCount,
  };
  return { hasEvidence: true, text, sources: used.map((r) => r.source), coverage };
}

/** A batch fed to the MAP stage of the sweep: its EVIDENCE text + the sources it covers. */
export interface GroundingBatch {
  text: string;
  sources: GroundingSource[];
}

/**
 * A5 map-reduce sweep (ask.py:_sweep): for a case bigger than the single-shot cap, read the WHOLE case
 * in batches instead of capping at the first 80. Each batch is a self-contained EVIDENCE block the MAP
 * stage extracts question-relevant facts from; the REDUCE stage composes the final answer. Pure.
 */
export function buildGroundingBatches(entries: VaultEntry[]): GroundingBatch[] {
  const all = collectEvidence(entries);
  if (!all.length) return [];
  // Each evidence line is truncated to SWEEP_ROW_CHARS (an unbounded lead reason can't blow one batch),
  // then rows are packed into batches under SWEEP_BATCH_CHARS — character-budget batching (ask.py:_batch),
  // NOT a fixed source count, so a MAP batch always fits the model window regardless of line length.
  const rows: EvidenceRow[] = all.map((r) =>
    r.line.length > SWEEP_ROW_CHARS ? { ...r, line: r.line.slice(0, SWEEP_ROW_CHARS) + "…" } : r,
  );
  const batches: GroundingBatch[] = [];
  let cur: EvidenceRow[] = [];
  let curChars = 0;
  const flush = (): void => {
    if (cur.length) batches.push({ text: blocksFor(cur).join("\n\n"), sources: cur.map((r) => r.source) });
    cur = [];
    curChars = 0;
  };
  for (const r of rows) {
    if (cur.length && curChars + r.line.length > SWEEP_BATCH_CHARS) flush();
    cur.push(r);
    curChars += r.line.length;
  }
  flush();
  return batches;
}

// ---- A5: deterministic citation verification (ask.py:_verify_citations + verify.hard_tokens) ----

// High-precision facts (ISO date / IPv4 / email / ETH wallet), lowercased — port of verify.py:_HARD_TOKEN_RES.
const HARD_TOKEN_RES: RegExp[] = [
  // ISO date — `[A-Za-z0-9_]` lookarounds reproduce the old `\b...\b` boundary; ALL classes are
  // explicit ASCII (`[0-9]`, never \d) to stay byte-identical with verify.py. The divergence is
  // Python-side (its \d/\b are Unicode, JS's ASCII) — Python over-extracted an Arabic-Indic/fullwidth
  // date; JS already rejected it. Lockstep source so a future \d rewrite can't reintroduce drift
  // (sp-cbeb7d29). es2022 target → fixed-length lookbehind is safe.
  /(?<![A-Za-z0-9_])[0-9]{4}-[0-9]{2}-[0-9]{2}(?![A-Za-z0-9_])/g, // ISO date
  // IPv4 — `[A-Za-z0-9_]` lookarounds reproduce the old `\b...\b` word boundary (kept verbatim,
  // incl. parity vs identifiers like foo1.2.3.4); the added `[0-9]\.` / `\.[0-9]` guards reject an
  // ADJACENT octet so an over-long run (1.2.3.4.5, a version string) yields no partial IP
  // (sp-e8a3c054, fail closed). A trailing sentence period is still allowed (9.9.9.9.). ALL classes
  // are explicit ASCII (never \w/\d) to stay byte-identical with verify.py — Python's \w/\d are
  // Unicode, JS's are ASCII (codex finding-2). es2022 target → fixed-length lookbehind is safe.
  /(?<![A-Za-z0-9_])(?<![0-9]\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9_])(?!\.[0-9])/g, // IPv4
  /\b[a-z0-9][a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,}\b/gi, // email
  /\b0x[a-fA-F0-9]{40}\b/g, // ETH wallet
];

/** Hard facts asserted in `text` (lowercased). Empty ⇒ a soft/interpretive claim, nothing to verify. */
export function hardTokens(text: string): Set<string> {
  const out = new Set<string>();
  if (!text) return out;
  for (const rx of HARD_TOKEN_RES) for (const m of text.matchAll(rx)) out.add(m[0].toLowerCase());
  return out;
}

export interface UnsupportedCitation {
  sentence: string;
  runs: string[];
  unsupportedFacts: string[];
}

const RUN_CITE_RE = /\[run:\s*([^\]]+)\]/gi;

/**
 * For each answer sentence that asserts a HARD fact AND cites `[run: X]`, confirm the cited run's
 * evidence actually contains that fact (the web grounds on a run's findings, so the fact must appear
 * among that run's entity values). Returns the unsupported sentences so the caller can surface them —
 * a hallucinated citation that the [run: X] requirement alone can't catch. Port of ask.py:_verify_citations.
 */
export function verifyCitations(answer: string, sources: GroundingSource[]): UnsupportedCitation[] {
  // per-run evidence text = the lowercased entity values surfaced in that run.
  const runEvidence = new Map<string, string>();
  for (const s of sources) {
    const prev = runEvidence.get(s.run) ?? "";
    runEvidence.set(s.run, `${prev} ${s.entity.toLowerCase()}`);
  }
  const out: UnsupportedCitation[] = [];
  for (const sentence of (answer || "").split(/(?<=[.!?])\s+/)) {
    const runs = [...sentence.matchAll(RUN_CITE_RE)].map((m) => m[1].trim());
    // tokenize the sentence WITHOUT its [run: …] labels (codex): a run named `case 2026-06-22` carries
    // a date/IP/email in the LABEL — counting that as an asserted fact would self-flag every citation.
    const toks = hardTokens(sentence.replace(RUN_CITE_RE, " "));
    if (!runs.length || !toks.size) continue; // uncited or soft sentence — not checkable here
    const citedText = runs.map((r) => runEvidence.get(r) ?? "").join(" ");
    const missing = [...toks].filter((t) => !citedText.includes(t)).sort();
    if (missing.length) out.push({ sentence: sentence.trim().slice(0, 200), runs, unsupportedFacts: missing });
  }
  return out;
}

// The grounded-Q&A persona — a CO-INVESTIGATOR, not a citation index (founder 2026-07-03: the old text
// forbade synthesis, so answers read as dumps and follow-ups reset to "I don't know"). Grounding is NOT
// prose-only here: the deterministic mirrors are verifyCitations() + hardTokens() below (unit-tested in
// answer.test.ts / grounding.test.ts) and the chat-conclusions smoke test, which fail on a fabricated cite.
export const GROUNDING_PERSONA = [
  "You are the analyst's co-investigator on ONE investigation case — a colleague reasoning about the",
  "case with them, not a search index.",
  "EVIDENCE is this case's promoted findings, held leads, and run observations.",
  "GROUNDING: every factual claim (an entity, infrastructure, ownership, attribution) must come from the",
  "EVIDENCE or the CONVERSATION SO FAR. Never invent one. Cite the run behind each fact inline, like",
  "[run: <objective>].",
  "REASON ACROSS the evidence — that is your job: connect related findings, name the pattern they add up",
  "to, and weigh confidence (a promoted finding outranks a held lead outranks a raw observation).",
  "Label interpretation as assessment; an assessment must follow from cited evidence, never add new facts.",
  "When the question calls for a judgment, end with a bold **Bottom line:** and a concrete **Next:** move.",
  "FOLLOW-UPS: use the CONVERSATION SO FAR. 'More succinctly' means compress your previous answer.",
  "'Why?' or 'drill into X' means go deeper on what you already said. Never reset to 'I don't know' when",
  "the conversation holds the answer.",
  "GAPS: if the evidence does not cover the question, say plainly what this case does not yet show and",
  "name the collection step that would close the gap. A gap is a fact about the case, not a failure.",
].join(" ");

// Conclusions-style questions ("what are the conclusions", "summarize", "where do we stand") get the
// SYNTHESIS voice: the connected picture across every run, not a per-fact answer. Routed by
// isConclusionsQuestion() in answerQuestion (code, unit-tested in answer.test.ts — not a suggestion).
export const SYNTHESIS_PERSONA = [
  GROUNDING_PERSONA,
  "The analyst is asking where the investigation STANDS. Write the connected picture, not a list:",
  "(1) what the case set out to answer; (2) the key judgments — each one connecting the findings that",
  "support it, with its [run: …] cites and a confidence; (3) what is live or operating now vs dormant;",
  "(4) the open gaps and what would close them. End with **Bottom line:** and **Next:**.",
].join(" ");

/** Deterministic router for the synthesis voice (unit-tested): a question asking for conclusions /
 *  summary / where-we-stand reads the WHOLE case, so it gets SYNTHESIS_PERSONA in answerQuestion. */
const CONCLUSIONS_RE =
  /\b(?:conclusions?|summar(?:y|ize|ise|ies)|key\s+judgments?|what\s+(?:did|have|do)\s+we\s+(?:find|found|learn(?:ed)?|know)|where\s+(?:do\s+we|does\s+(?:this|the\s+case))\s+stand|overall\s+picture|big\s+picture|bottom\s+line|wrap(?:\s|-)?up|recap|state\s+of\s+the\s+(?:case|investigation))\b/i;
export function isConclusionsQuestion(question: string): boolean {
  return CONCLUSIONS_RE.test(question ?? "");
}

/** One prior chat turn fed back into Q&A so follow-ups work (statelessness fix, founder 2026-07-03).
 *  Redaction + capping happen in the session layer (answerQuestion) before this reaches the wire. */
export interface QaTurn {
  role: "you" | "agent";
  text: string;
}

/** The deterministic no-evidence answer (returned with NO model call when hasEvidence is false).
 *  cd-guidance (bug #3): a GUIDE, not a dead refusal — the founder put in a key and expects the chat to
 *  walk them through the tool. Points at the two ways to start + the `help` walkthrough. */
export const NO_EVIDENCE_ANSWER =
  "Nothing to answer from yet — this case has no findings or leads. To get going: type **`investigate <domain>`** " +
  "(or a wallet / IP / @handle) to run the agent, or add evidence on **Reports & intake** and **Process** the case. " +
  "Type **`help`** for a full walkthrough.";

/** Assemble the user message: optional ANALYST SCOPE + CONVERSATION SO FAR + the EVIDENCE block + the
 *  question. History rides inside ONE user message (never separate API turns) so the alternating-role
 *  rules of the wire can't reject a transcript that starts or repeats on either side. Pure; caller
 *  redacts + caps.
 *  scope-injection (founder 2026-07-07, "I add a scope but the LLM ignores it"): the saved case scope
 *  frames the whole-case ▶ run (buildCaseTask) but was absent from Q&A, so asking a question ignored it.
 *  It rides FIRST so the analyst's question and proof-bar frame every answer. */
export function buildQaPrompt(context: string, question: string, history?: QaTurn[], scope?: string): string {
  const frame = scope?.trim()
    ? `ANALYST SCOPE / OBJECTIVE (the question this case must answer — frame your answer to it):\n${scope.trim()}\n\n`
    : "";
  const turns = (history ?? []).filter((t) => t && typeof t.text === "string" && t.text.trim());
  const convo = turns.length
    ? "CONVERSATION SO FAR (oldest first — resolve follow-ups like 'more succinctly' / 'why?' against it):\n" +
      turns.map((t) => `${t.role === "you" ? "Analyst" : "You"}: ${t.text.trim()}`).join("\n") +
      "\n\n"
    : "";
  return `${frame}${convo}EVIDENCE:\n${context}\n\nQUESTION: ${question}`;
}

/** A5 sweep MAP persona (ask.py:MAP_SYSTEM): a cheap extract pass — pull only the question-relevant
 *  facts from one batch, KEEP each fact's [run: X] citation, or reply exactly NONE. Do NOT answer. */
export const GROUNDING_MAP_PERSONA = [
  "Extract every fact in the EVIDENCE that is relevant to the QUESTION.",
  "Keep each fact's [run: <objective>] citation. One fact per line, each ending with its [run: …].",
  "If no evidence line is relevant, reply with exactly: NONE.",
  "Do NOT answer the question; only extract the relevant facts.",
].join(" ");

/** The MAP user message for one batch. */
export function buildMapPrompt(context: string, question: string): string {
  return `QUESTION: ${question}\n\nEVIDENCE:\n${context}\n\nExtract the relevant facts (keep [run: …] cites), or reply NONE.`;
}
