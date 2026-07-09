// PRD-4: the synthesize/brief pass — turn a run's gated findings into a written
// brief that LEADS with the live/operating threat. Ported doctrine:
// investigations/synthesize.py. Uses client.run with NO tools (it already carries a
// signal + returns stop_reason); bounded maxTokens; an INTERNAL timeout retries once
// while an EXTERNAL user abort (Stop) is never retried.

import type { AnthropicClient, ContentBlock } from "../llm/client.js";
import type { Finding, GateVerdict } from "./gate.js";
import type { Step } from "./loop.js";

/** Frozen, timestamp-free so the persona prefix caches. The doctrine, ported. */
export const BRIEF_PERSONA = [
  "You are a senior intelligence analyst writing the deliverable brief for an OSINT investigation.",
  "You synthesize ONLY from the evidence digest given below the line — you never invent facts, entities,",
  "or sources. Expertise shapes how you INTERPRET the evidence, never what you ADD to it.",
  "",
  "PRIORITIZE BY OPERATIONAL URGENCY (this decides the headline):",
  "- LEAD with what is LIVE and operating now. Infra-confirmed infrastructure (a live IP, an active",
  "  domain, a resolving nameserver) is THE headline — the first sentence of the executive summary is",
  "  about it.",
  "- Dead, dormant, or merely-named items are CONTEXT, never the lede. The seed/most-mentioned entity",
  "  being inactive does NOT make it the story. Do not bury an active threat under a dormant one.",
  "- Each evidence line is tagged with an operational status (live / unconfirmed / unknown) and a",
  "  reliability grade (A best .. D weakest). A claim's confidence cannot exceed its best-graded source.",
  "",
  // PRD-B synthesize-sections (RCA discipline-evaporation): the port thinned the brief from synthesize.py's
  // 16-section model to 6, so briefs read flat. Restored to the original's section set (target dossiers,
  // key actors, channels, IOCs, attribution verdicts, cross-report, leads, timeline…), keeping kipi's
  // live-threat-leads doctrine. Emit a section only if it has content; never pad an empty one.
  "Output a single markdown brief with these sections IN THIS ORDER, terse, no filler. Omit a section only",
  "if it would be empty (do not invent content to fill one):",
  "  # Investigation brief",
  "  ## Executive summary  (3-5 sentences; the first is the live-threat headline)",
  "  ## Key judgments  (KJ-1, KJ-2, ... each one declarative judgment with a calibrated confidence,",
  "       ordered by importance; these are the load-bearing conclusions)",
  "  ## Operational picture  (what is happening now, what infra is live, what is dormant)",
  "  ## Target dossiers  (one short subsection per investigated target — what it is, what it does, status)",
  "  ## Key actors  (named operators / people / handles, each with a role assessment)",
  "  ## Communication channels  (named channels — telegram / forums / sites — with an assessment)",
  "  ## Indicators of compromise  (concrete IOCs an analyst can pivot on: domains, IPs, wallets, hashes)",
  "  ## Attribution verdicts  (what is attributed to whom and the EXACT crosslinks that support it; do",
  "       not assert an attribution the evidence does not carry)",
  "  ## Cross report findings  (what each piece of evidence added; where they converge or conflict)",
  "  ## Investigator leads  (the held, unpromoted leads worth chasing)",
  "  ## Open questions and gaps  (the specific unverified attributions that need corroboration — name them)",
  "  ## Sources and methods  (the OSINT tools run + the evidence this brief drew on — from the digest, not invented)",
  "  ## Timeline  (the chronology of activity where the evidence dates it)",
  "  ## Where to look next  (the highest-value SPECIFIC pivots — name exact entities to chase and why)",
  "",
  "Keep fact, assessment, and speculation clearly separated. If the evidence is thin, say so plainly.",
].join("\n");

export interface SynthesizeOpts {
  objective: string;
  promoted: Finding[];
  leads: { finding: Finding; verdict: GateVerdict }[];
  steps: Step[];
  client: AnthropicClient;
  /** External user abort (Stop). Never retried. */
  signal?: AbortSignal;
  maxTokens?: number;
  /** Internal timeout per attempt; a timeout retries ONCE. */
  timeoutMs?: number;
}

export interface BriefResult {
  brief: string;
  ok: boolean;
}

const INFRA_TYPES = new Set(["domain", "subdomain", "ip", "ip_address", "url", "netblock", "asn"]);

/** Operational status for a promoted finding, per the doctrine's live/dead split. */
function operationalStatus(f: Finding): string {
  if (f.infra_source_count === undefined) return "status unknown";
  if (f.infra_source_count >= 1 && INFRA_TYPES.has((f.entity_type ?? "").toLowerCase())) {
    return "LIVE infrastructure (infra-confirmed)";
  }
  if (f.infra_source_count >= 1) return "confirmed";
  return "unconfirmed";
}

/** A compact, graded digest of the run — summarized, not dumped (bounding). */
export function buildDigest(
  promoted: Finding[],
  leads: { finding: Finding; verdict: GateVerdict }[],
  steps: Step[],
): string {
  const live = promoted.filter((f) => operationalStatus(f).startsWith("LIVE"));
  const other = promoted.filter((f) => !operationalStatus(f).startsWith("LIVE"));
  // PRD-B: feed the agent's per-finding CLAIM into the digest (the model-input the original got from the
  // profile dossiers; RCA discipline-evaporation thinned both the section model AND the evidence fed). The
  // claim is the agent's one-line evidence for the entity — it lets the brief write dossiers + verdicts
  // instead of a flat list. Secrets are redacted upstream; here we ALSO normalize the model-authored text
  // to ONE bounded line — strip control chars / collapse whitespace / cap — so a claim with newlines or
  // markdown cannot escape its bullet and corrupt the digest or inject prompt structure (codex issue-4).
  const cleanClaim = (s: string): string => s.replace(/[\u0000-\u001f]+/g, " ").replace(/\s+/g, " ").trim().slice(0, 280);
  const fline = (f: Finding) => {
    const raw = typeof f.claim === "string" ? cleanClaim(f.claim) : "";
    const claim = raw ? ` — ${raw}` : "";
    return `- ${f.entity} [${f.entity_type}] grade ${f.grade ?? "?"} — ${operationalStatus(f)}${claim}`;
  };
  const toolCalls = steps.filter((s) => s.kind === "tool");
  const toolSummary = toolCalls.map((s) => `${s.tool}${s.isError ? "(error)" : ""}`).join(", ") || "none";

  return [
    "OPERATIONAL STATUS (authoritative live/dead split — order the brief by this):",
    live.length ? `LIVE / operating now:\n${live.map(fline).join("\n")}` : "LIVE / operating now: (none confirmed)",
    other.length ? `Other confirmed (context):\n${other.map(fline).join("\n")}` : "",
    "",
    "PROMOTED FINDINGS (graded, graphed):",
    promoted.length ? promoted.map(fline).join("\n") : "(none promoted)",
    "",
    "HELD LEADS (unverified — for Open questions / next pivots):",
    leads.length ? leads.map((l) => `- ${l.finding.entity} [${l.finding.entity_type}] — ${l.verdict.reason}`).join("\n") : "(none)",
    "",
    `TOOL STEPS RUN: ${toolCalls.length} (${toolSummary})`,
  ]
    .filter(Boolean)
    .join("\n");
}

function combineSignals(external: AbortSignal | undefined, internal: AbortSignal): AbortSignal {
  const c = new AbortController();
  const abort = () => c.abort();
  if (external?.aborted || internal.aborted) c.abort();
  external?.addEventListener("abort", abort, { once: true });
  internal.addEventListener("abort", abort, { once: true });
  return c.signal;
}

function textOf(content: ContentBlock[]): string {
  return content
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text as string)
    .join("\n")
    .trim();
}

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === "AbortError";
}

/**
 * Produce the markdown brief. NO tools. Bounded by maxTokens. A truncated
 * (max_tokens) response is a clean non-persisted failure. An INTERNAL timeout
 * retries at most once (a second billable request); an EXTERNAL user abort throws
 * immediately and is never retried.
 */
// sf-briefs: the per-group + standalone summary personas, ported VERBATIM from investigations/briefs.py
// (SYSTEM at briefs.py:49-56, STANDALONE_SYSTEM at briefs.py:59-61). The deterministic markdown scaffold
// is assembled in TS (formatGroupBrief); the LLM produces ONLY the prose summary.
export const GROUP_BRIEF_PERSONA = [
  "You are an OSINT analyst writing a brief that ties together a",
  "related set of intel reports. You receive: (1) the reports' titles and",
  "investigation tags, (2) the entities that appear in MULTIPLE of them,",
  "(3) the clusters/crews that span them, (4) the time window.",
  "",
  "Write 4-7 sentences. Name the shared theme. Name the 2-3 cross-cutting",
  "actors. Note open questions. No fluff. No \"the data suggests\" /",
  "\"below is\" / preamble. Plain text only.",
].join("\n");

export const STANDALONE_PERSONA = [
  "You are an OSINT analyst noting a standalone report",
  "that did NOT meet the relatedness threshold with any other ingested",
  "report. Write 1-2 sentences naming what the report is about. No fluff.",
].join("\n");

export interface GroupSummaryOpts {
  client: AnthropicClient;
  /** true for the per-orphan standalone note (1-2 sentences); false for the per-group brief (4-7). */
  standalone: boolean;
  /** the already-redacted context object (JSON-serialized into the user message). */
  payload: unknown;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * Produce the per-group (or standalone) summary prose. Mirrors synthesizeBrief's discipline: NO tools,
 * bounded maxTokens (smaller than the case brief — 4-7 / 1-2 sentences), an INTERNAL timeout retries
 * once, an EXTERNAL Stop is never retried. Returns the trimmed summary, or a graceful fallback string.
 */
export async function synthesizeGroupSummary(opts: GroupSummaryOpts): Promise<string> {
  const persona = opts.standalone ? STANDALONE_PERSONA : GROUP_BRIEF_PERSONA;
  const ask = opts.standalone ? "Write the 1-2 sentence note." : "Write the 4-7 sentence brief.";
  const user = `${opts.standalone ? "Standalone report" : "Group context"}:\n${JSON.stringify(opts.payload, null, 2)}\n\n${ask}`;
  const maxTokens = opts.standalone ? 150 : 700; // signed client divergence from the server's uncapped llm.ask
  const timeoutMs = opts.timeoutMs ?? 60_000;
  for (let attempt = 0; attempt < 2; attempt++) {
    const timer = new AbortController();
    const to = setTimeout(() => timer.abort(), timeoutMs);
    try {
      const res = await opts.client.run({
        messages: [{ role: "user", content: user }],
        system: persona,
        cache: true,
        kind: "judgment",
        maxTokens,
        signal: combineSignals(opts.signal, timer.signal),
      });
      clearTimeout(to);
      if (res.stopReason === "max_tokens") return textOf(res.content) || "(summary truncated)";
      return textOf(res.content);
    } catch (e) {
      clearTimeout(to);
      if (opts.signal?.aborted) throw e; // user Stop — never retry
      if (isAbort(e) && attempt === 0) continue; // internal timeout — retry once
      return "(summary unavailable)";
    }
  }
  return "(summary unavailable)";
}

export async function synthesizeBrief(opts: SynthesizeOpts): Promise<BriefResult> {
  const digest = buildDigest(opts.promoted, opts.leads, opts.steps);
  const user = `Objective: ${opts.objective}\n\n---\n${digest}`;
  // PRD-B synthesize-max-tokens: 1800 truncated a full multi-section brief (the original brief call is
  // UNCAPPED). Raised to 8192 so the 14-section model fits; the BYO-key client bills the user (parity is
  // the directive). Pinned floor 4096 (depth metric synthesize-max-tokens).
  const maxTokens = opts.maxTokens ?? 8192;
  const timeoutMs = opts.timeoutMs ?? 60_000;

  for (let attempt = 0; attempt < 2; attempt++) {
    const timer = new AbortController();
    const to = setTimeout(() => timer.abort(), timeoutMs);
    try {
      const res = await opts.client.run({
        messages: [{ role: "user", content: user }],
        system: BRIEF_PERSONA,
        cache: true,
        kind: "judgment",
        maxTokens,
        signal: combineSignals(opts.signal, timer.signal),
      });
      clearTimeout(to);
      if (res.stopReason === "max_tokens") {
        return { brief: "Brief truncated (max tokens). Try a narrower objective.", ok: false };
      }
      return { brief: textOf(res.content), ok: true };
    } catch (e) {
      clearTimeout(to);
      if (opts.signal?.aborted) throw e; // user pressed Stop — never retry
      if (isAbort(e) && attempt === 0) continue; // internal timeout — retry once
      return { brief: "Brief unavailable — try again.", ok: false };
    }
  }
  return { brief: "Brief unavailable — try again.", ok: false };
}

// ---- co-investigator run briefing (video-review 2026-06-25) ----
//
// The founder's gap: when a run finishes, kipi-web showed a hardcoded COUNT template ("Worked the whole case
// → 17 promoted, 8 leads. The roster is worked.") instead of the agent's actual briefing. Reference = the real
// 4_points op log (case-037 Rielly Niles Turner): the agent briefs like a CO-INVESTIGATOR — orients to the
// analyst's objective, reasons about findings, separates a collection GAP from an analysis FAILURE, and closes
// the leg with a plain-words "what I found / what I think / where I'd go next" narrative (plain-words-legs,
// founder 2026-07-08). This composer reuses buildDigest (the same evidence the formal brief reads)
// but writes a SHORT conversational update, not a 14-section report. Distinct from synthesizeBrief (the client
// deliverable); this is the chat reply the analyst sees the instant a run ends.
// plain-words-legs (founder 2026-07-08): every investigation leg CLOSES with a three-part narrative in plain
// sentences — "what I found / what I think / where I'd go next" — NOT an entity dump. The three markdown
// headings render as clean bold via renderMarkdown (## → bold), so the close reads as prose the analyst can act
// on. Orient to the objective first, then the three headed sections; keep the confirmed-vs-lead + gap reasoning.
export const RUN_BRIEFING_PERSONA = [
  "You are a co-investigator briefing the analyst the moment an investigation run finishes — a colleague at the",
  "next desk, not a report generator. Close the leg with a SHORT plain-words narrative. First orient in one line",
  "to the analyst's OBJECTIVE — what we were trying to answer. Then write EXACTLY these three sections, each as a",
  "markdown heading on its OWN line, followed by a few plain SENTENCES (never a bulleted list, never a dump of",
  "entity names):",
  '"## What I found" — what the run actually turned up, in prose. Separate what is CONFIRMED from what is only a',
  "HELD LEAD, and say why a lead is just a lead (e.g. single source, no crosslink). Name the key entities inside",
  "sentences, do not list them.",
  '"## What I think" — your read: what it means for the objective, and any GAP still open (say whether a lookup',
  "would close it, or it is a dead end).",
  '"## Where I\'d go next" — the single most useful, concrete next move the analyst can take.',
  "Be specific and use ONLY the findings in the digest. Never invent entities, infrastructure, ownership, or",
  "attribution that is not in the digest. This is a conversation, not a deliverable — no report title, just the",
  "one-line orient followed by those three headed sections in plain words.",
].join(" ");

export interface RunBriefingOpts {
  objective: string;
  promoted: Finding[];
  leads: { finding: Finding; verdict: GateVerdict }[];
  steps?: Step[];
  /** how the run ended (end_turn / budget / degraded …) — folded in so the briefing can be honest about it. */
  stopReason?: string;
  /** still-uninvestigated seeds (case mode) — the raw material for the "Next:" move. */
  pivots?: string[];
  client: AnthropicClient;
  signal?: AbortSignal;
  maxTokens?: number;
  timeoutMs?: number;
}

/** Compose the conversational co-investigator briefing for a finished run. Returns "" on any failure /
 *  truncation so the caller can fall back to the deterministic count line — a briefing must NEVER block or
 *  replace the honest summary with an error. Key redaction is the CALLER's job (session.runBriefingFor). */
export async function composeRunBriefing(opts: RunBriefingOpts): Promise<string> {
  const digest = buildDigest(opts.promoted, opts.leads, opts.steps ?? []);
  const tail = [
    opts.stopReason ? `The run ended: ${opts.stopReason}.` : "",
    opts.pivots && opts.pivots.length ? `Still uninvestigated seeds: ${opts.pivots.slice(0, 10).join(", ")}.` : "",
  ].filter(Boolean).join(" ");
  const user = `Objective: ${opts.objective}\n\n---\n${digest}${tail ? `\n\n---\n${tail}` : ""}`;
  const maxTokens = opts.maxTokens ?? 1024; // a short briefing, not a report
  const timeoutMs = opts.timeoutMs ?? 45_000;

  for (let attempt = 0; attempt < 2; attempt++) {
    const timer = new AbortController();
    const to = setTimeout(() => timer.abort(), timeoutMs);
    try {
      const res = await opts.client.run({
        messages: [{ role: "user", content: user }],
        system: RUN_BRIEFING_PERSONA,
        cache: true,
        kind: "judgment",
        maxTokens,
        signal: combineSignals(opts.signal, timer.signal),
      });
      clearTimeout(to);
      if (res.stopReason === "max_tokens") return ""; // fall back to the count line rather than a half briefing
      return textOf(res.content).trim();
    } catch (e) {
      clearTimeout(to);
      if (opts.signal?.aborted) throw e; // user pressed Stop — never retry, propagate
      if (isAbort(e) && attempt === 0) continue; // internal timeout — retry once
      return ""; // fail-soft: the caller uses the deterministic summary
    }
  }
  return "";
}
