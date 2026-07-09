// r1-runtrail (parity R1): PURE run-trail helpers — attribution (link a finding to the step that
// produced it), display normalization (capped, redaction-agnostic), and a deterministic bottom line.
// No DOM, no clock, no network, no model call: node-testable + identical every render. Fed by
// session.runDetail (which redacts steps + findings at the session layer FIRST), rendered by
// src/pages.ts renderRunsPage. Mirrors the server's _attribute_findings entity-match — provenance
// from REAL tool output, never a model-asserted claim.

import { canonType } from "../graph/model.js";
import type { Step } from "./loop.js";

export interface RunEntityLike {
  value: string;
  type: string;
  promoted: boolean;
  grade?: string;
  // sf-findings: carried through from the stored Finding so the rich row can render the confidence pill
  // + the one-sentence summary. AGENT-only (file-ingest findings have no `claim` → absent → no summary
  // line). Session enriches these from the run record's promoted/leads BEFORE redaction, so `claim` is
  // redacted like every other projected string.
  confidence?: string;
  claim?: string;
}

/** A finding decorated with the step that produced it (1-based stepRef + the step's tool). */
export interface AttributedEntity extends RunEntityLike {
  stepRef?: number;
  stepTool?: string;
}

export interface DisplayStep {
  n: number; // 1-based position in the trail
  kind: "reasoning" | "tool";
  tool?: string;
  inputText?: string; // tool: allowlisted scalar input keys only, capped (D9)
  resultText?: string; // tool: parsed-entity summary | error line | capped raw
  text?: string; // reasoning: capped
  isError?: boolean;
  truncated?: boolean; // any field was cut
}

// Display caps live HERE (not CSS) so a multi-MB step.result can never build a giant text node (D7).
const MAX_RESULT_CHARS = 300;
const MAX_INPUT_CHARS = 120;
const MAX_TEXT_CHARS = 400;
const MAX_ENTITIES_SHOWN = 8;
// The scalar input keys the OSINT tools actually consume (tools.ts DISPATCH params + url). Only these
// are shown — a model could attach an arbitrary huge `unknown` blob the tool ignores (D9).
const INPUT_KEYS = ["domain", "address", "query", "ip", "target", "url"];

const norm = (s: string): string => s.trim().toLowerCase();

interface ParsedEntity {
  type?: string;
  value?: string;
}

/** A tool step's EMITTED entities (D3/D4/D5): ONLY for kind==='tool' && !isError, ONLY the
 *  `entities` array of a successfully-parsed result. [] for reasoning / error / parse-failure /
 *  a result with no entities array — so a value in a note, an error message, or free text is never
 *  treated as provenance. */
function stepEntities(step: Step): ParsedEntity[] {
  if (step.kind !== "tool" || step.isError) return [];
  if (typeof step.result !== "string") return [];
  try {
    const parsed = JSON.parse(step.result) as { entities?: unknown };
    if (!parsed || !Array.isArray(parsed.entities)) return [];
    return (parsed.entities as ParsedEntity[]).filter((e) => e && typeof e.value === "string");
  } catch {
    return [];
  }
}

/** Canonical equality (D3): same alias-folded type AND same trimmed-lowercased value — never a
 *  substring (1.2.3.4 must not match 11.2.3.45; evil.com must not match not-evil.com). Type is
 *  best-effort: if either side lacks a type, fall back to value-only equality. */
function entityMatches(finding: RunEntityLike, e: ParsedEntity): boolean {
  if (typeof e.value !== "string") return false;
  if (norm(e.value) !== norm(finding.value)) return false;
  if (e.type && finding.type) return canonType(e.type) === canonType(finding.type);
  return true;
}

/**
 * Attribute each finding to the LAST successful tool step whose EMITTED entities contain it
 * (canonical match). No match -> stepRef left undefined (never invented — matches the server's
 * step_ref=None). Operates on the ALREADY-REDACTED steps/findings the session layer passes in.
 */
export function attributeFindingsToSteps(steps: Step[], findings: RunEntityLike[]): AttributedEntity[] {
  const perStep = steps.map(stepEntities); // index-aligned with steps
  return findings.map((f) => {
    for (let i = steps.length - 1; i >= 0; i--) {
      if (perStep[i].some((e) => entityMatches(f, e))) {
        return { ...f, stepRef: i + 1, stepTool: steps[i].tool };
      }
    }
    return { ...f };
  });
}

function cap(s: string, max: number): [string, boolean] {
  return s.length <= max ? [s, false] : [s.slice(0, max) + "…", true];
}

function inputText(input: unknown): [string, boolean] {
  if (!input || typeof input !== "object") return ["", false];
  const obj = input as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of INPUT_KEYS) {
    const v = obj[k];
    if (typeof v === "string" && v.trim()) parts.push(`${k}=${v.trim()}`);
    else if (typeof v === "number") parts.push(`${k}=${v}`);
  }
  return cap(parts.join(" "), MAX_INPUT_CHARS);
}

function resultText(step: Step): [string, boolean] {
  if (typeof step.result !== "string") return ["", false];
  if (step.isError) {
    try {
      const parsed = JSON.parse(step.result) as { error?: unknown };
      if (typeof parsed.error === "string") return cap(`error: ${parsed.error}`, MAX_RESULT_CHARS);
    } catch {
      /* fall through to raw */
    }
    return cap(step.result, MAX_RESULT_CHARS);
  }
  const ents = stepEntities(step);
  if (ents.length) {
    const shown = ents.slice(0, MAX_ENTITIES_SHOWN).map((e) => `${e.type ?? "?"}:${e.value}`).join(", ");
    const more = ents.length > MAX_ENTITIES_SHOWN ? ` +${ents.length - MAX_ENTITIES_SHOWN} more` : "";
    const [txt, cut] = cap(shown, MAX_RESULT_CHARS);
    return [`${ents.length} entit${ents.length === 1 ? "y" : "ies"}: ${txt}${more}`, cut || ents.length > MAX_ENTITIES_SHOWN];
  }
  return cap(step.result, MAX_RESULT_CHARS); // a tool result with no entities array: capped raw
}

/** Normalize the persisted steps into a capped, display-safe shape (D7/D9). */
export function displayTrail(steps: Step[]): DisplayStep[] {
  return steps.map((s, i) => {
    if (s.kind === "tool") {
      const [inp, inpCut] = inputText(s.input);
      const [res, resCut] = resultText(s);
      return { n: i + 1, kind: "tool", tool: s.tool, inputText: inp, resultText: res, isError: !!s.isError, truncated: inpCut || resCut };
    }
    const [txt, cut] = cap(typeof s.text === "string" ? s.text : "", MAX_TEXT_CHARS);
    return { n: i + 1, kind: "reasoning", text: txt, truncated: cut };
  });
}

/** Deterministic bottom line: what happened + the single best next move. NO model call (a render
 *  path must stay offline + cheap). The degraded message is gated on `worked === false` — the
 *  AUTHORITATIVE persisted flag (sp-2c870c26) — NOT on `degradedReason` alone (codex issue-review):
 *  a forged/stale degradedReason on a worked/legacy record must NOT read as degraded, and a
 *  worked:false record with a blank reason still reads degraded via a static fallback. `worked`
 *  undefined (legacy records) ⇒ never degraded, preserving prior behavior. */
export function bottomLine(promoted: number, leads: number, stopReason: string, worked?: boolean, degradedReason?: string): string {
  const counts = `${promoted} promoted, ${leads} lead${leads === 1 ? "" : "s"}`;
  if (worked === false) {
    const reason =
      typeof degradedReason === "string" && degradedReason.trim()
        ? degradedReason
        : "no OSINT tool returned data — check your keys / connectivity";
    // sp-26d8021c: a cut-off run (worked:false + the loop.ts cut-off reason, authored at loop.ts:381 and
    // starting "the run was cut off") DID run tools — it just didn't finish. Label it "cut off", not "no
    // real work", so a half-run never reads as an empty case. Matches the one place that string is authored.
    const wasCutOff = typeof degradedReason === "string" && /\bcut off\b/i.test(degradedReason);
    if (wasCutOff) return `Run was cut off before it finished: ${reason}. ${counts}.`;
    return `Run did no real work: ${reason}. ${counts}.`;
  }
  const what =
    stopReason === "aborted" ? "Run was stopped early — kept what it found." :
    stopReason === "budget" ? "Run hit the token budget — kept what it found." :
    stopReason === "incomplete" ? "Run ended incomplete." :
    "Run completed.";
  const next =
    promoted === 0 && leads === 0 ? "Next: nothing surfaced — try a different objective or add OSINT keys." :
    promoted === 0 ? "Next: no promoted findings — expand the strongest lead to corroborate it." :
    "Next: generate a brief, or expand a promoted node one hop.";
  return `${what} ${counts}. ${next}`;
}

// ---- sf-findings: the Discovered-assets rollup — a PURE projection over the persisted step trail ----

/** One discovered asset, projected over the trail (mirrors runs.html's Discovered-assets rows). */
export interface DiscoveredAsset {
  asset: string; // the entity value (literal — rendered via textContent)
  type: string; // the emitted entity type (best-effort)
  foundStep: number; // 1-based step n that FIRST emitted it
  foundVia?: string; // the tool of that step
  checkedWith: string[]; // every tool whose result emitted it (deduped, in first-seen order)
  chased: boolean; // a LATER step took this value as an INPUT (the agent pivoted on it)
  onGraph: boolean; // it matches a PROMOTED finding (it's on the graph)
}

/** The scalar values a step took as INPUT (the same allowlist displayTrail uses), trimmed + lowercased
 *  for comparison. A later step whose input contains an asset means the agent CHASED that asset. */
function stepInputValues(step: Step): string[] {
  if (step.kind !== "tool" || !step.input || typeof step.input !== "object") return [];
  const obj = step.input as Record<string, unknown>;
  const out: string[] = [];
  for (const k of INPUT_KEYS) {
    const v = obj[k];
    if (typeof v === "string" && v.trim()) out.push(norm(v));
  }
  return out;
}

/**
 * Project the persisted step trail into per-asset rows: for each entity a tool step EMITTED, record
 * where it was found (first step n + that tool), every tool that surfaced it (checked-with), whether a
 * LATER step pivoted on it (chased — its value appears as a later step's input), and whether it landed
 * on the graph (matches a promoted finding). PURE — no DOM, no clock, no liveness guess: we show the
 * REAL trail signals (on-graph vs surfaced), never a fabricated live/dead badge. Operates on the
 * already-redacted steps/findings the session layer passes in.
 */
export function assetRollupFor(steps: Step[], findings: RunEntityLike[]): DiscoveredAsset[] {
  const perStep = steps.map(stepEntities); // index-aligned with steps
  const inputsByStep = steps.map(stepInputValues); // index-aligned: the values each step CHASED
  const promotedKeys = new Set(findings.filter((f) => f.promoted).map((f) => norm(f.value)));

  const order: string[] = []; // first-seen order of asset keys (deterministic render)
  const byKey = new Map<string, DiscoveredAsset>();

  for (let i = 0; i < steps.length; i++) {
    const tool = steps[i].tool ?? "";
    for (const e of perStep[i]) {
      if (typeof e.value !== "string" || !e.value.trim()) continue;
      const key = norm(e.value);
      let asset = byKey.get(key);
      if (!asset) {
        asset = {
          asset: e.value,
          type: e.type ?? "",
          foundStep: i + 1, // FIRST step that emitted it
          foundVia: tool || undefined,
          checkedWith: [],
          chased: false,
          onGraph: promotedKeys.has(key),
        };
        byKey.set(key, asset);
        order.push(key);
      }
      if (tool && !asset.checkedWith.includes(tool)) asset.checkedWith.push(tool);
    }
  }

  // chased: a step AFTER the asset's found-step took its value as an input.
  for (const key of order) {
    const asset = byKey.get(key)!;
    for (let i = asset.foundStep; i < steps.length; i++) {
      if (inputsByStep[i].includes(key)) {
        asset.chased = true;
        break;
      }
    }
  }

  return order.map((k) => byKey.get(k)!);
}

// ---- sf-findings: the Next-moves pivots — a DETERMINISTIC projection over the run's LEADS ----

/** One next-move suggestion derived from a held lead (NOT an LLM call). */
export interface Pivot {
  entity: string;
  type: string;
  grade?: string;
  confidence?: string;
  reason: string; // why it's worth chasing next
}

const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3 };
const CONF_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };

function gradeRank(grade?: string): number {
  return GRADE_RANK[(grade ?? "").toUpperCase()] ?? 4; // ungraded sorts last
}
function confRank(conf?: string): number {
  return CONF_RANK[(conf ?? "").toLowerCase()] ?? 3; // unknown confidence sorts last
}

/**
 * DETERMINISTIC next-moves — the run's LEADS (findings where !promoted) ranked as the entities worth
 * chasing next, by grade (A>B>C>D) then confidence (high>medium>low). PURE — a projection over the
 * leads already on the run record; promoted findings are NOT pivots (already on the graph).
 *
 * DIVERGENCE (impl-review #1/#2, documented in the parity-manifest note): the ORIGINAL /runs Next-moves
 * is driven by the agent's `recommended_pivots` (entity + free-text why), classified by OSINT
 * REACHABILITY (legal-process / internal-data / missing-key → "blocked"). The kipi-web browser agent
 * emits only `findings` (no recommended_pivots) and has no reachability classifier — so this is the
 * faithful client-first ANALOG (rank the held leads as next moves), NOT a reproduction of the server's
 * reachability split. A single honest "chase to corroborate" list — no now/blocked split (the client has
 * no reachability signal to populate "blocked"; gate-faithful findings are always graded).
 */
export function pivotsFor(findings: RunEntityLike[]): Pivot[] {
  const leads = findings.filter((f) => !f.promoted);
  const ranked = [...leads].sort((a, b) => gradeRank(a.grade) - gradeRank(b.grade) || confRank(a.confidence) - confRank(b.confidence));
  return ranked.map((f) => ({
    entity: f.value,
    type: f.type,
    grade: f.grade,
    confidence: f.confidence,
    reason: f.grade && f.grade.toUpperCase() in GRADE_RANK ? `grade ${f.grade} lead — chase to corroborate` : "chase to corroborate",
  }));
}
