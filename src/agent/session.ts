// PRD-3: the seam between the app and the agent loop. Pure (no DOM), so it is
// node-testable. The Anthropic key lives ONLY in the encrypted vault under a
// reserved namespace and is passed solely to the client constructor (header use);
// it is never returned in a step, a finding, an error, or the persisted run record.

import { Vault } from "../vault/vault.js";
import { AnthropicClient, type ToolDef } from "../llm/client.js";
import { investigate, DEEP_MAX_TURNS, type InvestigateResult, type Step, type AgentRelationship, type ObservedEvent } from "./loop.js";
import {
  OSINT_TOOLS,
  runTool as defaultRunTool,
  runEnrichTool,
  enrichToolDef,
  enrichBudget,
  validateTarget,
  type ToolOutcome,
} from "./tools.js";
import {
  attributeFindingsToSteps,
  displayTrail,
  bottomLine,
  assetRollupFor,
  pivotsFor,
  type AttributedEntity,
  type DisplayStep,
  type DiscoveredAsset,
  type Pivot,
} from "./runtrail.js";
import { synthesizeBrief, synthesizeGroupSummary, composeRunBriefing } from "./synthesize.js";
import {
  groupReports,
  groupContext,
  verdictForGroup,
  formatGroupBrief,
  formatStandalone,
  filterReportEntities,
  type ReportInput,
  type ReportMeta,
} from "./briefs.js";
import { promotionGate, isAdmissible, attributeFindings, type Finding, type GateVerdict, type Observed } from "./gate.js";
import { extractEntities, inferRelationships, type ExtractedEntity } from "../ingest/extract.js";
import { mergeEntities } from "../ingest/record.js"; // ig-record: union structured CSV/XLSX entities with flat extraction
import { buildGraphModel, mergeGraphModel, mergeNetworkModel, stripObjective, emptyObjectiveGraphModel, type GraphModel } from "../graph/model.js";
import {
  buildEntityDb,
  runRecordToIngest,
  graphModelToIngest,
  getEntity,
  connectionsFor,
  allEntities,
  crossRunEntities,
  computeAliasLinks,
  canonKey,
  entityKey,
  type EntityStore,
  type EntityRecord,
  type Connection,
  type EntityRef,
  type IngestRun,
  type IngestLink,
  type IngestEntity,
} from "../entity/db.js";
import { applyCorrections, applyCorrectionsToModel, isValidCorrection, type CorrectionMap } from "../entity/corrections.js";
import { buildExportFiles, type ExportModel, type ExportEntity, type ExportRel, type ExportCluster, type ExportFiles } from "../export/intel.js";
import {
  applyAnalysis,
  applyAnalysisToModel,
  applyClustersToModel,
  applyScoresToModel,
  applyMetricsToModel,
  applyRelationshipsToModel,
  validateAnalysisRecord,
  validateCaseSchema,
  emptyAnalysis,
  type AnalysisRecord,
  type AnalysisCluster,
  type AnalysisRelationship,
  type EntityScoreRecord,
  type NodeMetricRecord,
  type CaseSchema,
} from "../entity/analysis.js";
import { computeThreatScores, mergeRoleWeights } from "../entity/scoring.js";
import { computeGraphMetrics, computePathConfidence } from "../entity/metrics.js";
import {
  buildAnalyzeSystem,
  buildAnalyzePrompt,
  salvageAnalyzeJson,
  mapAnalyzeToCanonKeys,
  ANALYZE_MAX_TOKENS,
  ANALYZE_MAX_RELATIONSHIPS,
  type PresentedEntity,
} from "./analyze.js";
import {
  buildConsolidatePrompt,
  parseConsolidate,
  buildTypingPrompt,
  parseTyping,
  roleForType,
  MAX_CONSOLIDATE_ENTITIES,
  type Presented,
  type ConsolidateSuggestion,
  type TypingSuggestion,
} from "../entity/consolidate.js";
import { type Cluster } from "../entity/clusters.js";
import { detectRunType, isSpecificType, TAXONOMY_ORDER } from "../entity/typedetect.js";
import { AI_DOSSIER_PERSONA, buildDossierPrompt, parseDossier } from "../entity/dossier.js";
import {
  buildRelationsPrompt,
  parseSemanticRelations,
  relatableConnections,
  type SemanticRelation,
} from "../entity/relations.js";
import {
  buildGroundingContext,
  isInvestigated,
  buildGroundingBatches,
  buildQaPrompt,
  buildMapPrompt,
  GROUNDING_PERSONA,
  SYNTHESIS_PERSONA,
  isConclusionsQuestion,
  GROUNDING_MAP_PERSONA,
  NO_EVIDENCE_ANSWER,
  verifyCitations,
  type QaTurn,
  type GroundingSource,
  type GroundingCoverage,
  type UnsupportedCitation,
  type VaultEntry,
} from "../chat/grounding.js";
import {
  TRADECRAFT_STEPS,
  TRADECRAFT_GATE_KEYS,
  CHALLENGE_SYSTEM,
  PREMORTEM_SYSTEM,
  type TradecraftStep,
  type TradecraftKind,
} from "../chat/tradecraft.js";
import type { FetchLike, OsintOpts } from "../osint/types.js";
import { base64 } from "../osint/types.js";
import { ENRICH_PROVIDERS, BLOCKED_PROVIDERS, enrichProvider, KEY_GUIDANCE } from "../osint/enrich.js";
import { isValidWorkerUrl, runProxiedProvider, proxiedProvider } from "../osint/proxy.js";

/** Reserved vault namespace for secrets. The app's debug hooks refuse this prefix. */
export const SECRET_PREFIX = "secret:";
export const ANTHROPIC_KEY = `${SECRET_PREFIX}anthropic_key`;

export class SessionError extends Error {}

/** The Anthropic key from the vault, or null if unset/blank. Throws if the vault is locked. */
export function getApiKey(vault: Vault): string | null {
  let raw: unknown;
  try {
    raw = vault.get(ANTHROPIC_KEY);
  } catch {
    throw new SessionError("Unlock your vault to use AI features.");
  }
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** Save the Anthropic key to the vault. Empty/whitespace is rejected. */
export async function setApiKey(vault: Vault, key: string): Promise<void> {
  const trimmed = (key ?? "").trim();
  if (!trimmed) throw new SessionError("Enter a non-empty API key.");
  try {
    await vault.put(ANTHROPIC_KEY, trimmed);
  } catch {
    throw new SessionError("Unlock your vault to save your key.");
  }
}

export function hasApiKey(vault: Vault): boolean {
  try {
    return getApiKey(vault) !== null;
  } catch {
    return false;
  }
}

// ---- en-session: per-provider keys (the getApiKey/setApiKey pattern over secret:<id>_key) ----

/** The reserved vault key for a provider's credential. Same `secret:` namespace the __kipi hooks refuse. */
function providerSecretKey(id: string): string {
  return `${SECRET_PREFIX}${id}_key`;
}

/** A provider's key from the vault, or null if unset/blank. Throws if the vault is locked. */
export function getProviderKey(vault: Vault, id: string): string | null {
  let raw: unknown;
  try {
    raw = vault.get(providerSecretKey(id));
  } catch {
    throw new SessionError("Unlock your vault to use enrichment.");
  }
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/** Save a provider's key to the vault. Empty/whitespace is rejected. */
export async function setProviderKey(vault: Vault, id: string, key: string): Promise<void> {
  const trimmed = (key ?? "").trim();
  if (!trimmed) throw new SessionError("Enter a non-empty key.");
  try {
    await vault.put(providerSecretKey(id), trimmed);
  } catch {
    throw new SessionError("Unlock your vault to save your key.");
  }
}

function hasProviderKey(vault: Vault, id: string): boolean {
  try {
    return getProviderKey(vault, id) !== null;
  } catch {
    return false;
  }
}

/** Clear a provider's key. The Vault has no delete (codex D7), so write an empty string — getProviderKey
 *  treats blank as null, so the provider reads back as not-configured. Single-writer vault.put. */
export async function clearProviderKey(vault: Vault, id: string): Promise<void> {
  try {
    await vault.put(providerSecretKey(id), "");
  } catch {
    throw new SessionError("Unlock your vault to clear your key.");
  }
}

/**
 * The agent ToolDefs for the providers whose key is configured in this vault (m3 / parity M3). A keyless
 * vault yields [] — so the agent exposes exactly the 4 free OSINT_TOOLS and the existing scripted smokes
 * are unchanged (codex D10, no regression). A provider with NO key is NEVER registered, so the model can
 * never call a tool that would fail on a missing key. Pure + read-only (no vault write).
 */
export function enrichToolsFor(vault: Vault): ToolDef[] {
  return ENRICH_PROVIDERS.filter((p) => hasProviderKey(vault, p.id)).map(enrichToolDef);
}

/** A budget-exhausted enrich call returns a clean is_error WITHOUT a fetch (codex D7). Matches the
 *  shape tools.ts::errorOutcome produces so the loop treats it like any other recoverable tool error. */
function enrichBudgetError(reason: string): ToolOutcome {
  return { content: JSON.stringify({ error: reason }), is_error: true, entities: [], infra: false };
}

// ---- en-session: secret redaction over EVERY configured secret + its derived forms (codex D2/D3) ----

/**
 * Every string form that must be scrubbed from a persisted record / objective: each configured
 * `secret:*` value (the Anthropic key + every provider key) AND its `encodeURIComponent` form; for a
 * colon-bearing credential (Censys `id:secret`) the `base64(id:secret)` Basic value and each half
 * too. Longest-first so a shorter form never pre-empts a longer one. A value shorter than 4 chars is
 * skipped (avoids redacting common substrings). This is what stops a provider key — pasted into a
 * target, or echoed by a malicious provider in any encoded form — from landing in a vault key/record.
 */
function configuredSecretForms(vault: Vault): string[] {
  let keys: string[];
  try {
    keys = vault.keys();
  } catch {
    return [];
  }
  const forms = new Set<string>();
  const addForms = (v: string): void => {
    if (v.length < 4) return;
    forms.add(v);
    try {
      forms.add(encodeURIComponent(v));
    } catch {
      /* unencodable — skip the encoded form */
    }
  };
  for (const k of keys) {
    if (!k.startsWith(SECRET_PREFIX)) continue;
    let raw: unknown;
    try {
      raw = vault.get(k);
    } catch {
      continue;
    }
    if (typeof raw !== "string") continue;
    const v = raw.trim();
    if (!v) continue;
    addForms(v);
    const colon = v.indexOf(":"); // a colon-bearing credential (Censys id:secret)
    if (colon > 0) {
      forms.add(base64(v)); // the Basic-auth form a malicious provider could echo
      addForms(v.slice(0, colon));
      addForms(v.slice(colon + 1));
    }
  }
  return [...forms].sort((a, b) => b.length - a.length);
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * CASE-INSENSITIVE redaction (en-smoke scar): the adapters lowercase domain/host/wallet values, so a
 * secret echoed by a malicious provider inside a domain (`evil-<KEY>.com`) reaches the record
 * LOWERCASED and would evade an exact-case match. A high-entropy secret has no benign case variant, so
 * redacting case-insensitively cannot over-scrub anything real. Longest-first (the caller sorts) so a
 * shorter half never pre-empts the full credential.
 */
function redactForms(text: string, forms: string[]): string {
  let out = text;
  for (const f of forms) out = out.replace(new RegExp(escapeRegExp(f), "gi"), "[REDACTED]");
  return out;
}

function redactFormsDeep<T>(value: T, forms: string[]): T {
  if (!forms.length) return value;
  return JSON.parse(redactForms(JSON.stringify(value), forms)) as T;
}

export interface RunInvestigationOpts {
  vault: Vault;
  objective: string;
  /** A3: the agent PROMPT, when it must differ from the persist label/key `objective`. A whole-case pass
   *  feeds a long roster TASK to the agent but persists under a short readable label (the key stays
   *  `objective`). Unset → the agent sees `objective` itself (the single-target path, unchanged). */
  taskPrompt?: string;
  onStep?: (step: Step) => void;
  onObserved?: (ev: ObservedEvent) => void; // kweb-live-graph: live entity stream → grow the graph during the run
  onTextDelta?: (text: string) => void;
  /** Production defaults to Anthropic streaming; scripted fetch smokes stay JSON unless explicitly opted in. */
  stream?: boolean;
  signal?: AbortSignal;
  /** Inject the Anthropic fetch (tests). Production uses the real fetch. */
  fetchImpl?: FetchLike;
  /** Inject the OSINT fetch (tests). */
  toolOpts?: OsintOpts;
  maxTurns?: number;
  maxOutputTokens?: number;
  /** Persist a sanitized run:<objective> record (default true). Expand passes false so a
   *  one-hop dig writes NO vault record the key could be read back from (codex-1). */
  persist?: boolean;
}

export interface RunRecord {
  objective: string;
  steps: Step[];
  promoted: InvestigateResult["promoted"];
  leads: InvestigateResult["leads"];
  usage: InvestigateResult["usage"];
  stopReason: InvestigateResult["stopReason"];
  // sp-2c870c26: the honest-degraded signal persisted so /runs + the conductor can tell a degraded
  // run (no tool returned data, nothing found) from a genuine clean-empty case. Optional — legacy
  // records predate it and read back undefined (treated as worked, the prior behavior).
  worked?: boolean;
  degradedReason?: string;
  // sf-briefs: OPTIONAL report metadata (the reports.title/ingested_at/source_type analog) used by the
  // grouped-relatedness engine. Set on file ingest; absent on legacy records (read back as undefined).
  title?: string;
  ingestedAt?: string;
  sourceType?: string;
  // prd-parity-graph-faithful: PROXIMITY co-occurrence pairs (entity VALUE pairs within 200 chars
  // in the source text, the extractor.py:infer_relationships rule). Set on text ingest; absent on
  // agent runs (no text proximity) + legacy records — buildEntityDb falls back to all-pairs then.
  coOccur?: Array<[string, string]>;
  // PRD-B (RCA item 3): the agent's LIVE-emitted entity↔entity relationships — the network built as it
  // digs (a domain→ip resolve, a wallet payout), persisted so the graph draws TYPED edges from what the
  // agent actually established instead of all-pairs co-occurrence. Absent on file-ingest + legacy records.
  agentRelationships?: AgentRelationship[];
}

/**
 * Run one investigation on the user's key and persist a SANITIZED run record (never
 * the key) to the vault. A missing key or a locked vault surface a clean message —
 * no key, no vault payload, no raw caught error is echoed.
 */
export async function runInvestigation(opts: RunInvestigationOpts): Promise<InvestigateResult> {
  const key = getApiKey(opts.vault); // throws SessionError if the vault is locked
  if (!key) throw new SessionError("Add your Anthropic API key to investigate.");

  const client = new AnthropicClient(key, opts.fetchImpl);

  // m3-wire: register the keyed enrich providers as agent tools (only those with a configured key). A
  // keyless vault yields [] and investigate() falls back to exactly the 4 free OSINT_TOOLS + defaultRunTool
  // (no behavior change — codex D10). The combined runTool routes enrich_* through a per-run budget (D7)
  // and the closed-allowlist runEnrichTool (D8) with an INJECTED key resolver; redactContent (allSecretForms)
  // cuts any provider-echoed secret out of the trail + the model messages in-flight (D9).
  const enrichTools = enrichToolsFor(opts.vault);
  const budget = enrichBudget();
  const resolveProviderKey = (id: string): string | null => {
    try {
      return getProviderKey(opts.vault, id);
    } catch {
      return null;
    }
  };
  const combinedRunTool = async (
    name: string,
    input: Record<string, unknown>,
    toolOpts: OsintOpts,
  ): Promise<ToolOutcome> => {
    if (!name.startsWith("enrich_")) return defaultRunTool(name, input, toolOpts);
    const target = typeof input?.target === "string" ? input.target : "";
    const verdict = budget.check(name, target); // D7: bound spend BEFORE any key lookup or fetch
    if (!verdict.ok) return enrichBudgetError(verdict.reason);
    return runEnrichTool(name, input, resolveProviderKey, toolOpts);
  };

  // scope-injection (founder 2026-07-07): a single-target `investigate X` run ignored the saved case scope
  // (only the whole-case ▶ run composed it, via buildCaseTask). Frame the objective with the scope so a
  // one-target dig honors the analyst's question too. ONLY when there is no taskPrompt — the whole-case
  // path already put the scope in taskPrompt (composeCaseTask), so this would double it otherwise.
  const scopeFrame = redactProjectionText(opts.vault, getTradecraft(opts.vault, "scope")?.content?.trim() ?? "");
  const agentTask = opts.taskPrompt
    ? opts.taskPrompt
    : scopeFrame
      ? `Analyst scope / objective (frame this dig to it):\n${scopeFrame}\n\nInvestigate: ${opts.objective}`
      : opts.objective;

  const result = await investigate({
    objective: agentTask, // A3: the agent sees the (possibly long) task; the persist key stays `objective`
    client,
    onStep: opts.onStep,
    onObserved: opts.onObserved,
    onTextDelta: opts.onTextDelta,
    stream: opts.stream ?? !opts.fetchImpl,
    signal: opts.signal,
    // PRD-B agent-browser-forensics: thread the user's Worker URL into toolOpts so the browser-forensic +
    // proxied tools can reach it (absent → those tools error gracefully; the keyless belt still works).
    toolOpts: { ...opts.toolOpts, workerUrl: getWorkerUrl(opts.vault) ?? opts.toolOpts?.workerUrl },
    maxTurns: opts.maxTurns,
    maxOutputTokens: opts.maxOutputTokens,
    tools: enrichTools.length ? [...OSINT_TOOLS, ...enrichTools] : undefined,
    runTool: enrichTools.length ? combinedRunTool : undefined,
    redactContent: (s) => redactProjectionText(opts.vault, s),
  });

  const record: RunRecord = {
    objective: opts.objective,
    steps: result.steps,
    promoted: result.promoted,
    leads: result.leads,
    usage: result.usage,
    stopReason: result.stopReason,
    worked: result.worked,
    degradedReason: result.degradedReason,
    agentRelationships: result.relationships, // PRD-B: the live-emitted network edges (redacted at persist below)
    sourceType: "investigation", // sf-briefs: a human-facing label; the briefs engine already excludes agent runs via the non-forgeable sourceKind (absent here), this just completes the discriminator (impl-review #4)
  };
  if (opts.persist !== false) {
    try {
      // m3-redact-hardening D1: scrub EVERY secret form (the Anthropic key AND every provider key, in
      // their encoded/case-insensitive forms) from the persisted VALUE at rest — not just the Anthropic
      // key — because once enrich tools run, a provider key can reach the record via a model-echoed
      // value. The read projections also redact (defense-in-depth). The vault KEY stays raw (encrypted
      // at rest + lookup-consistency; the only taint vector is a self-typed key objective).
      await opts.vault.put(`run:${opts.objective}`, redactProjectionDeep(opts.vault, record)); // single-writer
    } catch {
      /* persistence is best-effort; a locked vault mid-run must not discard the result */
    }
  }
  return result;
}

// ---- A3: the WHOLE-CASE agentic pass (port of investigator.py:investigate_case_agentic, max_passes=1) ----
//
// The original drives the ENTIRE case with ONE un-caged agent that works every seed and pivots freely to
// the assets each surfaces (the case-031 shape; the cage was the bug). kipi-web only had per-objective
// runInvestigation — "it doesn't investigate on its own". investigateCase restores the whole-case pass:
// build a roster task from the case's entities + the schema thesis, run one DEEP un-caged pass through the
// SAME runInvestigation persist chokepoint, then surface the still-uninvestigated in-scope entities as
// recommendedPivots the analyst directs next (max_passes=1 = analyst-directed; soft in-app per
// q-investigation.md). NOT auto-chased — the web model is analyst-driven one-pass.

const CASE_ROSTER_CAP = 40; // == investigator.py _targets(conn, case, 40) — the seeds named in the task
const MAX_PIVOTS = 12; // a short, named next-action list (focus.py-style cap), never the whole roster

// D3 (finding-6): the per-case UP-FRONT output-token budget. A generous runaway CEILING, not a tight leash
// — the loop enforces it at a turn boundary (finish("budget")), a clean stop, never a mid-run kill (memory:
// cost-model-budget-the-scope). The analyst can lower it before a deep run; persisted per case.
export const DEFAULT_CASE_BUDGET = 200_000;
const CASE_BUDGET_KEY = "case-budget";

/** The per-case output-token budget (persisted), or DEFAULT_CASE_BUDGET when unset / unreadable. Never
 *  throws — a locked vault or missing/garbage record falls back to the default. Pure read. */
export function getCaseBudget(vault: Vault): number {
  try {
    const v = vault.get(CASE_BUDGET_KEY);
    if (v && typeof v === "object" && typeof (v as { tokens?: unknown }).tokens === "number") {
      const n = (v as { tokens: number }).tokens;
      if (Number.isFinite(n) && n > 0) return n;
    }
  } catch {
    /* locked / missing → default */
  }
  return DEFAULT_CASE_BUDGET;
}

/** Persist the per-case output-token budget. Rejects a non-positive / non-finite value (no silent
 *  zero-leash that would kill every run). Awaits the single vault.put (Promise<void>) so the budget is
 *  durable — a fresh unlock reads it (an un-awaited put races the next unlock). */
export async function setCaseBudget(vault: Vault, tokens: number): Promise<void> {
  if (!Number.isFinite(tokens) || tokens <= 0) {
    throw new SessionError("Budget must be a positive number of output tokens.");
  }
  await vault.put(CASE_BUDGET_KEY, { tokens });
}

export interface InvestigateCaseOpts {
  vault: Vault;
  onStep?: (step: Step) => void;
  onObserved?: (ev: ObservedEvent) => void; // kweb-live-graph: live entity stream → grow the graph during the run
  onTextDelta?: (text: string) => void;
  stream?: boolean;
  signal?: AbortSignal;
  fetchImpl?: FetchLike;
  toolOpts?: OsintOpts;
  maxTurns?: number; // default DEEP_MAX_TURNS (the whole-case budget); the per-objective default is 12
  maxOutputTokens?: number; // D3 finding-6: default getCaseBudget(vault) — the up-front per-case ceiling
}

export interface CasePivot {
  ref: EntityRef;
  name: string;
  type: string;
}

export interface InvestigateCaseResult extends InvestigateResult {
  recommendedPivots: CasePivot[]; // still-uninvestigated in-scope entities — the analyst's next moves
  rosterSize: number;
  objective: string; // the persist label the run was stored under
}

/** The case roster: every REAL entity (seeds + ingested), NOT score-gated — a fresh case has no threat
 *  scores yet, so this must work pre-Process (unlike focusGapsFor). isFocusReal = the in-scope predicate
 *  (not noise, not an unresolved person_candidate; focus.py `real`). Deterministic order for a stable task. */
export function caseRoster(vault: Vault): EntityRecord[] {
  const recs = allEntities(entityDbFor(vault, null)).filter(isFocusReal);
  recs.sort((a, b) => Number(b.promoted) - Number(a.promoted) || a.ref.value.localeCompare(b.ref.value));
  return recs;
}

// D3 (finding-5): cap the coOccur leads injected into the task so a dense case can't flood the prompt
// (the executable bound is this constant + the slice below, not prose).
const MAX_COOCCUR_LEADS = 20;
// codex: cap each ENDPOINT length too, not just the pair count — a real entity (domain/wallet/email/ip) is
// well under this; a longer "endpoint" is junk or a prompt-bloat attack, so the pair is skipped. Bounds the
// injected hint block to ~MAX_COOCCUR_LEADS * (2 * MAX_LEAD_ENDPOINT_LEN) chars regardless of the document
// (executable bound: these constants + the slice at the call site).
const MAX_LEAD_ENDPOINT_LEN = 100;

/** D3 (finding-5): the document-proximity pairs (coOccur), gathered across the case's FILE ingests, deduped
 *  and formatted as "a ↔ b". These are the SIGNAL D2 preserved (not rendered as edges) — handed to the agent
 *  as suggested-relationships-to-verify. Redact-on-read (belt) + capped. Pure: reads run records, no write. */
export function caseCoOccurLeads(vault: Vault, cap: number = MAX_COOCCUR_LEADS): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const objective of objectivesUnder(vault, RUN_PREFIX)) {
    let rec: unknown;
    try {
      rec = vault.get(`${RUN_PREFIX}${objective}`);
    } catch {
      continue;
    }
    if (!rec || typeof rec !== "object") continue;
    const r = rec as { sourceKind?: string; coOccur?: Array<[string, string]> };
    if (r.sourceKind !== FILE_SOURCE_KIND || !Array.isArray(r.coOccur)) continue; // only intake proximity
    for (const pair of r.coOccur) {
      if (!Array.isArray(pair) || pair.length !== 2) continue;
      const a = redactProjectionText(vault, String(pair[0])).trim();
      const b = redactProjectionText(vault, String(pair[1])).trim();
      if (!a || !b) continue;
      if (a.length > MAX_LEAD_ENDPOINT_LEN || b.length > MAX_LEAD_ENDPOINT_LEN) continue; // codex: skip junk/bloat endpoints
      const key = [a.toLowerCase(), b.toLowerCase()].sort().join("|");
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(`${a} ↔ ${b}`);
      if (out.length >= cap) return out;
    }
  }
  return out;
}

/** The whole-case TASK handed to the agent (the _build_case_task analog): name the analyst scope (the
 *  objective), the schema thesis, the seeds, and the document-proximity HINTS to verify, then instruct the
 *  un-caged free pivoting the original relies on. */
function buildCaseTask(roster: EntityRecord[], thesis: string, scope: string = "", coOccurLeads: string[] = []): string {
  const seeds = roster.slice(0, CASE_ROSTER_CAP).map((r) => `${r.label} (${r.type})`).join(", ");
  const lines = [
    "Investigate this WHOLE case. Work EVERY seed below and pivot freely across the assets each one " +
      "surfaces — you are NOT limited to a single target. Drive your own paths.",
  ];
  // D3 (finding-5): the recorded scope IS the run objective — name it first so it frames every pivot.
  if (scope) lines.push(`Analyst scope / objective:\n${scope}`);
  if (thesis) lines.push(`Case thesis: ${thesis}`);
  lines.push(`Seeds (${roster.length}): ${seeds || "(none yet — work from the case context)"}`);
  // D3 (finding-5 / D2): the document placed these pairs together. A HINT only — the agent must VERIFY with a
  // tool before treating any as a real relationship (co-occurrence in a file is not an investigated link).
  if (coOccurLeads.length) {
    lines.push(
      "The source documents place these pairs together (a HINT to check, NOT a confirmed link — verify with a " +
        `tool before drawing any edge): ${coOccurLeads.join("; ")}`,
    );
  }
  lines.push(
    "For each seed run the infra / identity pivots that fit it, follow the links you find onto new " +
      "assets, and stop when the inventory is worked. Report what you found and which seeds still need work.",
  );
  return lines.join("\n");
}

/** D3 (finding-5): compose the whole-case task from the live case state — roster seeds + schema thesis +
 *  the recorded analyst scope (the objective) + the coOccur hints. The single seam investigateCase uses, so
 *  a test can prove the scope + leads actually reach the task (the wiring, not just the pure builder). */
export function composeCaseTask(vault: Vault, roster: EntityRecord[]): string {
  const rec = analysisFor(vault);
  const thesis = rec?.schema
    ? `${rec.schema.domain}${rec.schema.summary ? " — " + rec.schema.summary : ""}`.trim()
    : "";
  const scope = getTradecraft(vault, "scope")?.content?.trim() ?? "";
  const leads = caseCoOccurLeads(vault);
  return buildCaseTask(roster, thesis, scope, leads);
}

// The tool-input FIELD names that carry a target (the OSINT tools' target params). Only these contribute
// to "touched" — counting EVERY string arg (codex) would let an incidental param (a note/label/source)
// suppress a real pivot. Generous but target-scoped; a value under one of these = the agent worked it.
const TOUCH_FIELDS = new Set([
  "domain", "subdomain", "host", "hostname", "ip", "ip_address", "target", "url", "email",
  "wallet", "address", "handle", "name", "query", "q", "value", "entity",
]);

/** Collect every string LEAF under a value (codex: a target field can be an array/object, e.g.
 *  `{targets:[...]}` — a flat scan would miss it and re-suggest a worked seed). */
function collectStrings(v: unknown, out: Set<string>): void {
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s) out.add(s);
  } else if (Array.isArray(v)) {
    for (const x of v) collectStrings(x, out);
  } else if (v && typeof v === "object") {
    for (const x of Object.values(v as Record<string, unknown>)) collectStrings(x, out);
  }
}

/** The lowercased values the pass TOUCHED: every finding entity + every tool-call TARGET-field value
 *  (recursing into array/object payloads). A roster seed the agent queried (a tool target) OR surfaced
 *  (a finding) counts as investigated; the rest are the recommendedPivots. Target-field-scoped + leaf-
 *  recursive (codex) so it is deterministic and neither over- nor under-counts worked seeds. */
function touchedValues(result: InvestigateResult): Set<string> {
  const touched = new Set<string>();
  const add = (v: unknown): void => {
    if (typeof v === "string" && v.trim()) touched.add(v.trim().toLowerCase());
  };
  for (const f of result.promoted) add(f.entity);
  for (const l of result.leads) add(l.finding?.entity);
  for (const s of result.steps) {
    if (s.kind !== "tool" || !s.input || typeof s.input !== "object") continue;
    for (const [k, val] of Object.entries(s.input as Record<string, unknown>)) {
      if (TOUCH_FIELDS.has(k.toLowerCase())) collectStrings(val, touched);
    }
  }
  return touched;
}

/**
 * Run ONE whole-case investigation pass. Builds the roster task, runs the DEEP un-caged pass through
 * runInvestigation (single persist chokepoint — NO new write path), and returns the run result plus the
 * still-uninvestigated in-scope roster entities as recommendedPivots. A missing key / locked vault surfaces
 * the same clean SessionError runInvestigation throws.
 */
export async function investigateCase(opts: InvestigateCaseOpts): Promise<InvestigateCaseResult> {
  const roster = caseRoster(opts.vault);
  // D3 (finding-5): compose the recorded scope (the objective) + coOccur hints into the task — not just the
  // roster + schema thesis. Scope is no longer decorative; it frames the whole-case run.
  const taskPrompt = composeCaseTask(opts.vault, roster);
  // A short, stable, readable persist LABEL (the key) distinct from the long agent task. A unique suffix
  // keeps each whole-case pass a separate history entry (the ingestText pattern) instead of overwriting.
  // Fallback is TIME-based, not roster.length (codex: `${roster.length}` collides across re-runs on the
  // same roster size → overwrite); Date.now() differs per run.
  const rid = globalThis.crypto?.randomUUID?.() ?? `${Date.now().toString(36)}-${roster.length}`;
  const objective = `whole-case investigation #${rid.slice(0, 8)}`;

  const result = await runInvestigation({
    vault: opts.vault,
    objective,
    taskPrompt,
    onStep: opts.onStep,
    onObserved: opts.onObserved,
    onTextDelta: opts.onTextDelta,
    stream: opts.stream,
    signal: opts.signal,
    fetchImpl: opts.fetchImpl,
    toolOpts: opts.toolOpts,
    maxTurns: opts.maxTurns ?? DEEP_MAX_TURNS,
    // D3 (finding-6): thread the up-front per-case budget into the deep run — the loop stops cleanly at
    // finish("budget") when output tokens reach it. Was MISSING here, so the whole-case run had no ceiling.
    maxOutputTokens: opts.maxOutputTokens ?? getCaseBudget(opts.vault),
  });

  const touched = touchedValues(result);
  // A seed is investigated if the pass touched EITHER its canonical ref.value OR its display label (codex:
  // the agent is handed the LABEL in the task, so a label-form query must still mark the seed worked).
  const isTouched = (r: EntityRecord): boolean =>
    touched.has(r.ref.value.trim().toLowerCase()) || touched.has(r.label.trim().toLowerCase());
  const recommendedPivots: CasePivot[] = roster
    .filter((r) => !isTouched(r))
    .slice(0, MAX_PIVOTS)
    .map((r) => ({ ref: r.ref, name: r.label, type: r.type }));

  return { ...result, recommendedPivots, rosterSize: roster.length, objective };
}

// ---- PRD-4: the synthesize/brief pass over a saved run ----

/** The Anthropic key's redactable forms: the raw key + its URL-encoded form, length>=4, longest-first
 *  — the same shape configuredSecretForms builds for provider keys, so both paths use ONE engine. */
function keyForms(key: string): string[] {
  const forms = new Set<string>();
  if (key.length >= 4) {
    forms.add(key);
    try {
      forms.add(encodeURIComponent(key));
    } catch {
      /* unencodable — skip the encoded form */
    }
  }
  return [...forms].sort((a, b) => b.length - a.length);
}

/**
 * Generate the deliverable brief for a saved run. Defense-in-depth on the key: it
 * is redacted from the loaded run BEFORE it reaches the model, and from the markdown
 * BEFORE it is persisted. A run with no findings AND no leads returns a deterministic
 * no-evidence brief WITHOUT a model call.
 */
export async function generateBrief(
  vault: Vault,
  objective: string,
  opts?: { fetchImpl?: FetchLike; signal?: AbortSignal },
): Promise<string> {
  const key = getApiKey(vault); // throws SessionError if locked
  if (!key) throw new SessionError("Add your Anthropic API key to generate a brief.");
  const safeObjective = redactProjectionText(vault, objective); // never echo any secret, even via the objective

  let run: unknown;
  try {
    run = vault.get(`run:${objective}`); // the lookup key uses the raw objective
  } catch {
    throw new SessionError("Unlock your vault to generate a brief.");
  }
  if (!run || typeof run !== "object") throw new SessionError("No run to brief — investigate first.");

  const rec = run as RunRecord;
  const promoted: Finding[] = Array.isArray(rec.promoted) ? rec.promoted : [];
  const leads: { finding: Finding; verdict: GateVerdict }[] = Array.isArray(rec.leads) ? rec.leads : [];

  if (promoted.length === 0 && leads.length === 0) {
    const brief = `# Investigation brief\n\nNo evidence to brief yet for "${safeObjective}". Run an investigation that produces findings or leads first.`;
    await persistBrief(vault, objective, safeObjective, brief);
    return brief;
  }

  const steps: Step[] = Array.isArray(rec.steps) ? rec.steps : [];
  // ca-session D9: the brief reads finding entity_type, so apply the analyst's TYPE corrections to a copy
  // of the findings before synthesis (grade/source counts/promotion untouched).
  const cmap = correctionMap(vault);
  const corrPromoted = promoted.map((f) => correctFindingType(f, cmap));
  const corrLeads = leads.map((l) => ({ ...l, finding: correctFindingType(l.finding, cmap) }));
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { brief } = await synthesizeBrief({
    objective: safeObjective,
    promoted: redactProjectionDeep(vault, corrPromoted),
    leads: redactProjectionDeep(vault, corrLeads),
    steps: redactProjectionDeep(vault, steps),
    client,
    signal: opts?.signal,
  });
  const safe = redactProjectionText(vault, brief); // redact the OUTPUT too
  await persistBrief(vault, objective, safeObjective, safe);
  return safe;
}

/**
 * Co-investigator run briefing (video-review 2026-06-25): compose the conversational "here's where we stand
 * against your objective + bottom line + next move" reply the analyst sees the instant a run finishes — the
 * 4_points voice (ref: case-037 op log) that the old hardcoded count line ("N promoted, N leads") replaced.
 * FAIL-SOFT by contract (executable: the catch below returns "", unit-tested): returns "" on no-key /
 * no-evidence / any error, so the chat falls back to the
 * deterministic count summary — a briefing must NEVER block run completion or surface an error as the
 * result (the executable catch below is what holds this, not prose).
 * Same key hygiene as the brief path: findings redacted IN (deep), the model output redacted OUT.
 */
export async function runBriefingFor(
  vault: Vault,
  input: {
    objective: string;
    promoted: Finding[];
    leads: { finding: Finding; verdict: GateVerdict }[];
    steps?: Step[];
    stopReason?: string;
    pivots?: string[];
  },
  opts?: { fetchImpl?: FetchLike; signal?: AbortSignal },
): Promise<string> {
  try {
    if (!input.promoted.length && !input.leads.length) return ""; // nothing found — the count line is the honest reply
    const key = currentKeyOrNull(vault);
    if (!key) return ""; // no key → the deterministic summary stands (no spend, no block)
    const cmap = correctionMap(vault); // apply the analyst's TYPE corrections to a copy (grade/counts untouched)
    const client = new AnthropicClient(key, opts?.fetchImpl);
    const briefing = await composeRunBriefing({
      objective: redactProjectionText(vault, input.objective),
      promoted: redactProjectionDeep(vault, input.promoted.map((f) => correctFindingType(f, cmap))),
      leads: redactProjectionDeep(vault, input.leads.map((l) => ({ ...l, finding: correctFindingType(l.finding, cmap) }))),
      steps: redactProjectionDeep(vault, input.steps ?? []),
      stopReason: input.stopReason,
      pivots: input.pivots?.map((p) => redactProjectionText(vault, p)),
      client,
      signal: opts?.signal,
    });
    return redactProjectionText(vault, briefing); // redact the model OUTPUT too (executable belt)
  } catch {
    return ""; // fail-soft (executable catch, not prose) — run completion + count summary survive a briefing failure
  }
}

async function persistBrief(vault: Vault, lookupKey: string, objective: string, brief: string, builtOn?: number): Promise<void> {
  try {
    // sf-deliverables: builtOn = the run count the brief was synthesized over (for the /deliverables
    // stale banner). Stored as a RECORD FIELD, never as `---` frontmatter — a frontmatter count would
    // leak into the rendered body + the Download .md (review finding 1). The value carries the REDACTED
    // objective. This is the SINGLE writer of brief:<key> (page regen + the Process step both funnel here).
    const record = builtOn === undefined ? { objective, brief } : { objective, brief, builtOn };
    await vault.put(`brief:${lookupKey}`, record);
  } catch {
    /* best-effort */
  }
}

// INC-4b: the Process synthesize + dossiers steps (the last 2 of the 11 server steps).
export const CASE_BRIEF_KEY = "case"; // the cross-report case brief lookup key (brief:case)
export const DOSSIER_PREFIX = "dossier:";
const MAX_DOSSIER_ENTITIES = 24; // bound the batch (a case has a handful of high-value actors)
// profile.py: dossiers profile HIGH-VALUE entities (role operator | channel | ioc), not every entity.
const DOSSIER_ROLES = new Set(["operator", "channel", "ioc"]);

/**
 * INC-4b synthesize (synthesize.py): the cross-report CASE brief — aggregate every run's promoted +
 * leads + steps across the case into ONE synthesizeBrief call, persisted at brief:case. Key-redacted
 * IN + OUT exactly like generateBrief (the per-run brief); analyst TYPE corrections applied to a copy.
 * A case with no evidence persists a deterministic no-evidence brief without a model call.
 */
export async function synthesizeCaseBrief(vault: Vault, opts?: { fetchImpl?: FetchLike; signal?: AbortSignal }): Promise<string> {
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to synthesize the case.");
  const cmap = correctionMap(vault);
  const promoted: Finding[] = [];
  const leads: { finding: Finding; verdict: GateVerdict }[] = [];
  const steps: Step[] = [];
  // sf-deliverables: builtOn = the count of run objectives this brief aggregated (the client's "report
  // count" analog — there is no reports table). The stale banner compares it to the live run count.
  const runObjectives = objectivesUnder(vault, RUN_PREFIX);
  for (const objective of runObjectives) {
    let run: unknown;
    try {
      run = vault.get(`${RUN_PREFIX}${objective}`);
    } catch {
      continue;
    }
    if (!run || typeof run !== "object") continue;
    const rec = run as RunRecord;
    if (Array.isArray(rec.promoted)) for (const f of rec.promoted) promoted.push(correctFindingType(f, cmap));
    if (Array.isArray(rec.leads)) for (const l of rec.leads) leads.push({ ...l, finding: correctFindingType(l.finding, cmap) });
    if (Array.isArray(rec.steps)) for (const s of rec.steps) steps.push(s);
  }
  const builtOn = runObjectives.length;
  const objective = "the case";
  if (promoted.length === 0 && leads.length === 0) {
    const brief = `# Investigation brief\n\nNo evidence to brief yet for the case. Ingest reports + Process first.`;
    await persistBrief(vault, CASE_BRIEF_KEY, objective, brief, builtOn);
    return brief;
  }
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { brief, ok } = await synthesizeBrief({
    objective,
    promoted: redactProjectionDeep(vault, promoted),
    leads: redactProjectionDeep(vault, leads),
    steps: redactProjectionDeep(vault, steps),
    client,
    signal: opts?.signal,
  });
  const safe = redactProjectionText(vault, brief); // redact the OUTPUT too
  if (opts?.signal?.aborted) throw new SessionError("Processing was cancelled."); // codex S1: a superseded Process must NOT commit a stale brief
  // clu-error-output: a failed/empty LLM response must NOT be persisted as a finished deliverable — the
  // "brief-failure-persisted-as-success" bug. synthesizeBrief returns ok:false WITH a non-empty failure
  // string on max_tokens / retry exhaustion (e.g. "Brief truncated…", "Brief unavailable…"), so check
  // `ok` AND non-empty — a trim check alone would persist those strings and OVERWRITE a prior good brief
  // (codex). Throw so the caller surfaces it; leave any prior brief intact.
  if (!ok || !safe.trim()) {
    throw new SessionError("The brief failed or came back empty — not saved. Try Regenerate, or check your key on Account.");
  }
  await persistBrief(vault, CASE_BRIEF_KEY, objective, safe, builtOn);
  return safe;
}

/**
 * INC-4b dossiers (profile.py): for each PROMOTED entity in the case (bounded), generate + persist a
 * dossier:<canonKey> record. aiDossierFor already redacts IN + OUT (the on-demand drawer path); the
 * persist redacts again (belt) + uses the existing vault.put single-writer chokepoint. Fail-soft per
 * entity — one entity's failure never blocks the Process.
 */
export async function persistCaseDossiers(vault: Vault, opts?: { fetchImpl?: FetchLike; signal?: AbortSignal }): Promise<number> {
  const store = entityDbFor(vault, null);
  const targets = allEntities(store).filter((e) => DOSSIER_ROLES.has(e.role)).slice(0, MAX_DOSSIER_ENTITIES);
  let count = 0;
  for (const e of targets) {
    if (opts?.signal?.aborted) break;
    try {
      const dossier = await aiDossierFor(vault, e.ref.type, e.ref.value, { fetchImpl: opts?.fetchImpl, signal: opts?.signal });
      if (opts?.signal?.aborted) break; // codex S1: an abort during the LLM call must NOT commit a stale dossier
      if (!dossier) continue;
      await vault.put(`${DOSSIER_PREFIX}${canonKey(e.ref.type, e.ref.value)}`, {
        type: e.ref.type,
        value: redactProjectionText(vault, e.ref.value),
        dossier: redactProjectionText(vault, dossier),
      });
      count++;
    } catch {
      /* fail-soft per entity */
    }
  }
  return count;
}

// ---- PRD-6: runs / briefs history (read-only, secret-safe) ----

export interface RunSummary {
  objective: string;
  stopReason: string;
  promoted: number;
  leads: number;
}

const RUN_PREFIX = "run:";
const BRIEF_PREFIX = "brief:";

function currentKeyOrNull(vault: Vault): string | null {
  try {
    return getApiKey(vault);
  } catch {
    return null;
  }
}

/** Objectives stored under `prefix`, EXCLUDING any that name the secret namespace or contain ANY
 *  configured secret in any form (codex D2: generalized from the Anthropic key alone to every
 *  provider key + its derived forms, so a key accidentally embedded in an objective is dropped from
 *  history entirely — stronger than redacting, and the lookup round-trip stays intact for clean ones). */
function objectivesUnder(vault: Vault, prefix: string): string[] {
  let allKeys: string[];
  try {
    allKeys = vault.keys();
  } catch {
    return [];
  }
  const forms = configuredSecretForms(vault);
  return allKeys
    .filter((k) => k.startsWith(prefix))
    .map((k) => k.slice(prefix.length))
    .filter((obj) => {
      if (obj.startsWith(SECRET_PREFIX)) return false;
      const lower = obj.toLowerCase(); // swh-redact D4: case-insensitive — a lowercased key form must also drop the objective
      return !forms.some((f) => lower.includes(f.toLowerCase()));
    });
}

export function listRuns(vault: Vault): RunSummary[] {
  return objectivesUnder(vault, RUN_PREFIX).map((objective) => {
    let rec: Partial<RunRecord> = {};
    try {
      const v = vault.get(`${RUN_PREFIX}${objective}`);
      if (v && typeof v === "object") rec = v as Partial<RunRecord>;
    } catch {
      /* unreadable -> empty summary */
    }
    return {
      objective,
      stopReason: typeof rec.stopReason === "string" ? rec.stopReason : "?",
      promoted: Array.isArray(rec.promoted) ? rec.promoted.length : 0,
      leads: Array.isArray(rec.leads) ? rec.leads.length : 0,
    };
  });
}

export function listBriefs(vault: Vault): string[] {
  return objectivesUnder(vault, BRIEF_PREFIX);
}

export interface RunEntity {
  value: string;
  type: string;
  promoted: boolean;
  grade?: string;
}

/** The gated, KEY-REDACTED entities of ONE run (for the Runs & findings page). Reuses the
 *  same admission+promotion gate as the graph/entity DB; the live key is stripped first. */
export function runEntities(vault: Vault, objective: string): RunEntity[] {
  let rec: Partial<RunRecord> = {};
  try {
    const v = vault.get(`${RUN_PREFIX}${objective}`);
    if (v && typeof v === "object") rec = v as Partial<RunRecord>;
  } catch {
    return [];
  }
  const promoted = Array.isArray(rec.promoted) ? rec.promoted : [];
  const leads = Array.isArray(rec.leads) ? rec.leads : [];
  const ingest = runRecordToIngest(
    objective,
    redactProjectionDeep(vault, promoted),
    redactProjectionDeep(vault, leads),
  );
  return ingest.entities.map((e) => ({ value: e.value, type: e.type ?? "", promoted: e.promoted, grade: e.grade }));
}

// ---- r1-detail: the per-run trail projection (Runs & findings page) ----

/** True when an objective is secret-tainted — names the secret namespace OR contains any configured
 *  secret form (case-insensitive) — the SAME policy objectivesUnder applies. Factored out so runDetail
 *  enforces it DIRECTLY (codex D2) instead of trusting the caller to have filtered via listRuns. */
function objectiveTainted(vault: Vault, objective: string): boolean {
  if (objective.startsWith(SECRET_PREFIX)) return true;
  const lower = objective.toLowerCase();
  return configuredSecretForms(vault).some((f) => lower.includes(f.toLowerCase()));
}

export interface RunDetail {
  steps: DisplayStep[];
  findings: AttributedEntity[];
  bottomLine: string;
  promoted: number;
  leads: number;
  // sf-findings: PURE projections over the same redacted steps/findings (the Discovered-assets rollup +
  // the deterministic Next-moves pivots). No new persisted state — derived here, redacted-safe.
  assets: DiscoveredAsset[];
  pivots: Pivot[];
}

/** sf-findings: the agent's per-finding confidence + claim, keyed by value+type (canonical-ish), pulled
 *  from the RAW run record's promoted+leads Findings. runEntities drops these at its ingest projection,
 *  so runDetail re-reads them here and re-attaches by match. AGENT-only — a file-ingest finding has no
 *  claim, so the map simply has no entry for it (the row degrades gracefully). */
function metaKey(type: string | undefined, value: string): string {
  return `${(type ?? "").trim().toLowerCase()}\t${value.trim().toLowerCase()}`; // tab delimiter (no whitespace ambiguity)
}

function findingMetaMap(rec: Partial<RunRecord>): Map<string, { confidence?: string; claim?: string }> {
  const map = new Map<string, { confidence?: string; claim?: string }>();
  const add = (f: Finding | undefined): void => {
    if (!f || typeof f.entity !== "string") return;
    const key = metaKey(f.entity_type, f.entity);
    const confidence = typeof f.confidence === "string" ? f.confidence : undefined;
    const claim = typeof (f as { claim?: unknown }).claim === "string" ? ((f as { claim?: string }).claim) : undefined;
    if (confidence === undefined && claim === undefined) return;
    if (!map.has(key)) map.set(key, { confidence, claim }); // first writer wins (promoted before leads)
  };
  if (Array.isArray(rec.promoted)) for (const f of rec.promoted) add(f);
  if (Array.isArray(rec.leads)) for (const l of rec.leads) add(l?.finding);
  return map;
}

/**
 * The full trail of ONE run for the Runs & findings page (parity R1): the agent's real step trail
 * (capped, display-safe) + the gate-faithful findings, each ATTRIBUTED to the step that produced it
 * (entity-match against the step's emitted entities), + a deterministic bottom line. A READ projection
 * over the `run:` record — NO vault write (single-writer createWritable untouched). Returns null when
 * the objective is secret-tainted (D2) or the record is missing/malformed.
 *
 * Key hygiene (codex D1): steps AND findings are redacted via allSecretForms + redactFormsDeep — every
 * provider secret + the Anthropic key, in every form — BEFORE attribution/display, so a secret echoed
 * in a tool result / input / reasoning text never reaches the trail. Steps are redacted at write too
 * (runInvestigation), so this is defense-in-depth that also covers provider secrets the write path's
 * Anthropic-only redact missed.
 */
export function runDetail(vault: Vault, objective: string): RunDetail | null {
  if (objectiveTainted(vault, objective)) return null; // D2
  let rec: Partial<RunRecord> = {};
  try {
    const v = vault.get(`${RUN_PREFIX}${objective}`);
    if (!v || typeof v !== "object") return null;
    rec = v as Partial<RunRecord>;
  } catch {
    return null;
  }

  const forms = allSecretForms(vault); // D1: every secret form, not just the Anthropic key
  const rawSteps: Step[] = Array.isArray(rec.steps) ? rec.steps : [];
  const steps = forms.length ? redactFormsDeep(rawSteps, forms) : rawSteps;

  // gate-faithful findings (re-gated by runEntities), ENRICHED with the agent's confidence + claim from
  // the raw record (runEntities drops them at its ingest projection), THEN all-secret redacted as ONE
  // unit — so `claim` (a model-authored string that could echo a secret) is redacted exactly like the
  // steps, BEFORE it reaches the display layer (sf-findings; the order is load-bearing).
  const meta = findingMetaMap(rec);
  const entities = runEntities(vault, objective).map((e) => {
    const m = meta.get(metaKey(e.type, e.value));
    return m ? { ...e, confidence: m.confidence, claim: m.claim } : e;
  });
  const safeFindings = forms.length ? redactFormsDeep(entities, forms) : entities;

  const findings = attributeFindingsToSteps(steps, safeFindings);
  const promoted = findings.filter((f) => f.promoted).length;
  const leads = findings.length - promoted;
  return {
    steps: displayTrail(steps),
    findings,
    promoted,
    leads,
    // PURE projections over the SAME redacted steps/findings (no separate redaction path).
    assets: assetRollupFor(steps, safeFindings),
    pivots: pivotsFor(findings),
    bottomLine: bottomLine(
      promoted,
      leads,
      typeof rec.stopReason === "string" ? rec.stopReason : "?",
      typeof rec.worked === "boolean" ? rec.worked : undefined, // authoritative gate; legacy undefined ⇒ never degraded
      typeof rec.degradedReason === "string" ? rec.degradedReason : undefined,
    ),
  };
}

/** A saved brief's markdown, with the live key redacted from the body. Null if absent,
 *  malformed (not {brief:string}), or the objective names the secret namespace. */
export function getBrief(vault: Vault, objective: string): string | null {
  if (objectiveTainted(vault, objective)) return null; // names the secret namespace OR embeds any secret form
  let rec: unknown;
  try {
    rec = vault.get(`${BRIEF_PREFIX}${objective}`);
  } catch {
    return null;
  }
  if (!rec || typeof rec !== "object" || typeof (rec as { brief?: unknown }).brief !== "string") {
    return null;
  }
  const brief = (rec as { brief: string }).brief;
  return redactProjectionText(vault, brief); // every secret form, case-insensitive
}

/** sf-deliverables: the brief's built-on run count (the count it was synthesized over), or null if the
 *  brief is absent / predates the field / the objective is secret-tainted. Behind the SAME objectiveTainted
 *  guard as getBrief (review finding 3 — the meta read must not be a redaction-bypass surface). Pairs with
 *  liveReportCount to drive the /deliverables stale banner. */
export function getBriefMeta(vault: Vault, objective: string): { builtOn: number } | null {
  if (objectiveTainted(vault, objective)) return null;
  let rec: unknown;
  try {
    rec = vault.get(`${BRIEF_PREFIX}${objective}`);
  } catch {
    return null;
  }
  if (!rec || typeof rec !== "object") return null;
  const builtOn = (rec as { builtOn?: unknown }).builtOn;
  return typeof builtOn === "number" ? { builtOn } : null; // absent count → no banner (never a false stale)
}

/** sf-deliverables: the live count of run objectives (the client's "report count" analog — there is no
 *  reports table). The stale banner fires when a brief's builtOn is below this. */
export function liveReportCount(vault: Vault): number {
  return objectivesUnder(vault, RUN_PREFIX).length;
}

// ---- sf-briefs: grouped-relatedness briefs (the briefs.py engine port) ----

export const GROUPBRIEF_PREFIX = "groupbrief:";
const GROUPBRIEF_INDEX = "index"; // groupbrief:index — the pointer record (mirrors briefs.py INDEX.md)
// Bounds the LLM SPEND (the shared `summarized` counter across groups + standalones), NOT the group
// COUNT — every group/standalone is still persisted + indexed (with a deterministic fallback summary
// past the cap), matching briefs.py which summarizes+writes every group. Intended (impl-review #6): a
// case has a handful of reports; the bounded cost is the LLM calls, not the record writes.
export const MAX_GROUP_BRIEFS = 24; // mirrors MAX_DOSSIER_ENTITIES

export interface GroupBriefSummary {
  name: string; // "group-1" | "standalone"
  content: string; // the group markdown (the viewer parses + renders it)
}

/** Extract the file-ingest reports into the pure engine's ReportInput[] (the report→entities→clusters
 *  projection). The role for the role:noise + person_candidate-no-role filters comes from the entityDbFor
 *  store (runEntities has no role); the cluster set is the analyze clusters touching the report's keys. */
function buildReportInputs(vault: Vault): ReportInput[] {
  const store = entityDbFor(vault, null);
  const roleByKey = new Map<string, string>();
  for (const e of allEntities(store)) roleByKey.set(canonKey(e.ref.type, e.ref.value), e.role);
  const clusterByKey = new Map<string, string>();
  const analysis = analysisFor(vault);
  for (const c of analysis?.clusters ?? []) for (const mk of c.memberKeys) clusterByKey.set(mk, c.name);

  const inputs: ReportInput[] = [];
  for (const { objective } of listIngestedDocs(vault)) {
    const ents = runEntities(vault, objective);
    const raw = ents.map((e) => ({
      value: e.value,
      type: e.type,
      role: roleByKey.get(canonKey(e.type, e.value)) ?? "",
    }));
    const entityKeys = filterReportEntities(raw); // FILTERED — for Jaccard relatedness
    // codex impl-review #1: a report's cluster set is derived from ALL its entities (unfiltered),
    // mirroring briefs.py _report_clusters (a separate mentions→cluster_members join). Deriving it from
    // the FILTERED set would drop a cluster whose only in-report member is incidental/noise, silently
    // suppressing a real shared-cluster "strong" union.
    const clusterNames = new Set<string>();
    for (const e of ents) {
      const c = clusterByKey.get(canonKey(e.type, e.value));
      if (c) clusterNames.add(c);
    }
    let meta: ReportMeta = { objective, title: objective };
    try {
      const rec = vault.get(`${RUN_PREFIX}${objective}`) as Partial<RunRecord> | undefined;
      if (rec && typeof rec === "object") {
        meta = { objective, title: rec.title ?? objective, ingestedAt: rec.ingestedAt, sourceType: rec.sourceType };
      }
    } catch {
      /* missing/locked — keep the default meta */
    }
    inputs.push({ meta, entityKeys, clusterNames });
  }
  return inputs;
}

/**
 * Generate the grouped-relatedness briefs (the ./invctl briefs analog, button-triggered). Groups the
 * file-ingest reports (pure engine), writes one LLM summary per group + per orphan (BOUNDED at
 * MAX_GROUP_BRIEFS, sequential, abort-re-checked before each persist), and persists groupbrief:group-<n>
 * + groupbrief:standalone + groupbrief:index through the EXISTING single-writer (key-redacted IN + OUT).
 * The index record is the source of truth the viewer reads — stale group records from a prior (larger)
 * run are simply not referenced (the Vault has no delete; this mirrors briefs.py rewriting INDEX.md).
 */
export async function generateGroupBriefs(vault: Vault, opts?: { fetchImpl?: FetchLike; signal?: AbortSignal }): Promise<{ groups: number; standalone: number }> {
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to group related reports.");
  const inputs = buildReportInputs(vault);
  if (inputs.length === 0) {
    await vault.put(`${GROUPBRIEF_PREFIX}${GROUPBRIEF_INDEX}`, { groups: [], standalone: false, at: new Date().toISOString() });
    return { groups: 0, standalone: 0 };
  }
  const store = entityDbFor(vault, null);
  const entityList = allEntities(store).map((e) => ({ label: e.label, type: e.type, role: e.role, runs: e.runs }));
  const clusterKinds = new Map<string, string>(); // cluster name → kind, for the brief body (impl-review #8)
  for (const c of analysisFor(vault)?.clusters ?? []) clusterKinds.set(c.name, c.kind);
  const byId = new Map(inputs.map((r) => [r.meta.objective, r] as const));
  const { groups, edges } = groupReports(inputs);
  const client = new AnthropicClient(key, opts?.fetchImpl);

  const groupNames: string[] = [];
  const orphans: { meta: ReportMeta; entityCount: number; summary: string }[] = [];
  let groupIdx = 0;
  let summarized = 0;

  for (const g of groups) {
    if (opts?.signal?.aborted) throw new SessionError("Grouping was cancelled.");
    if (g.length === 1) {
      const r = byId.get(g[0])!;
      let summary = r.meta.title || r.meta.objective;
      if (summarized < MAX_GROUP_BRIEFS) {
        try {
          const payload = redactProjectionDeep(vault, { title: r.meta.title, source_type: r.meta.sourceType, entity_count: r.entityKeys.size });
          summary = redactProjectionText(vault, await synthesizeGroupSummary({ client, standalone: true, payload, signal: opts?.signal }));
          summarized++;
        } catch {
          /* fail-soft: keep the deterministic fallback */
        }
      }
      orphans.push({ meta: r.meta, entityCount: r.entityKeys.size, summary });
    } else {
      groupIdx++;
      const ctx = groupContext(g, byId, entityList, clusterKinds);
      const verdict = verdictForGroup(g, edges);
      let summary = `(verdict ${verdict}; ${ctx.crossEntities.length} shared entities — run with a key for an LLM summary)`;
      if (summarized < MAX_GROUP_BRIEFS) {
        try {
          const payload = redactProjectionDeep(vault, {
            verdict,
            reports: ctx.reports.map((m) => ({ title: m.title, source_type: m.sourceType, ingested_at: m.ingestedAt })),
            cross_entities: ctx.crossEntities.slice(0, 25),
            clusters: ctx.clusters,
            time_window: ctx.timeWindow,
          });
          summary = redactProjectionText(vault, await synthesizeGroupSummary({ client, standalone: false, payload, signal: opts?.signal }));
          summarized++;
        } catch {
          /* fail-soft */
        }
      }
      if (opts?.signal?.aborted) throw new SessionError("Grouping was cancelled.");
      const name = `group-${groupIdx}`;
      await vault.put(`${GROUPBRIEF_PREFIX}${name}`, { name, content: redactProjectionText(vault, formatGroupBrief(groupIdx, ctx, verdict, summary)) });
      groupNames.push(name);
    }
  }

  if (orphans.length) {
    if (opts?.signal?.aborted) throw new SessionError("Grouping was cancelled.");
    await vault.put(`${GROUPBRIEF_PREFIX}standalone`, { name: "standalone", content: redactProjectionText(vault, formatStandalone(orphans)) });
  }
  // post-audit issue 3: route the index names through redact too. They are synthetic (`group-N`) today so
  // this is a no-op, but it future-proofs the one projection write that wasn't redacted (defense-in-depth).
  await vault.put(`${GROUPBRIEF_PREFIX}${GROUPBRIEF_INDEX}`, { groups: groupNames.map((n) => redactProjectionText(vault, n)), standalone: orphans.length > 0, at: new Date().toISOString() });
  return { groups: groupNames.length, standalone: orphans.length };
}

function getGroupBriefRec(vault: Vault, name: string): GroupBriefSummary | null {
  try {
    const v = vault.get(`${GROUPBRIEF_PREFIX}${name}`);
    if (v && typeof v === "object" && typeof (v as { content?: unknown }).content === "string") {
      return { name, content: redactProjectionText(vault, (v as { content: string }).content) }; // belt: redact on read
    }
  } catch {
    /* locked/missing */
  }
  return null;
}

/** The grouped briefs the viewer renders: the groups named in groupbrief:index (in order) + the
 *  standalone bucket. Orphaned group records from a prior run are not referenced by the index. */
export function listGroupBriefs(vault: Vault): { groups: GroupBriefSummary[]; standalone: GroupBriefSummary | null } {
  let index: unknown;
  try {
    index = vault.get(`${GROUPBRIEF_PREFIX}${GROUPBRIEF_INDEX}`);
  } catch {
    return { groups: [], standalone: null };
  }
  if (!index || typeof index !== "object") return { groups: [], standalone: null };
  const names = Array.isArray((index as { groups?: unknown }).groups) ? ((index as { groups: unknown[] }).groups.filter((n): n is string => typeof n === "string")) : [];
  const groups: GroupBriefSummary[] = [];
  for (const name of names) {
    const rec = getGroupBriefRec(vault, name);
    if (rec) groups.push(rec);
  }
  const standalone = (index as { standalone?: unknown }).standalone ? getGroupBriefRec(vault, "standalone") : null;
  return { groups, standalone };
}

// ---- PRD-7: the findings graph model, key-redacted before it is built ----

/**
 * Build the findings-graph model for a run with the live Anthropic key redacted FIRST
 * (codex finding-2). The graph is rendered from the raw objective + result and exposed
 * via __kipi.graphModel(), so the key (which can appear in an objective or a
 * model-emitted entity/reason) must be stripped before the pure, vault-unaware
 * `buildGraphModel` ever sees it. A locked vault has no key to redact and is keyless.
 */
export function graphModelForRun(vault: Vault, objective: string, result: InvestigateResult): GraphModel {
  const safeObjective = redactProjectionText(vault, objective);
  const safeResult = redactProjectionDeep(vault, result);
  return finalizeModel(vault, buildGraphModel(safeObjective, safeResult));
}

/**
 * The FIRST in-session run paint as a NETWORK-only model (sp-77a52e2c): the run's findings as a
 * co-occurrence clique with NO objective hub — the SAME shape as the 2nd-run grow (growCaseNetwork) and
 * the remount (graphModelForCase). graphModelForRun (the objective-rooted single-run view) injected an
 * objective hub + star spokes that only vanished on remount — a transient hub the founder saw. The
 * home/case graph must be network-only on EVERY paint, so the first run folds into an empty network base
 * (the redacted objective is kept as the model's label field, never a node). graphModelForRun stays the
 * dedicated single-run projection for any future run-detail view.
 */
export function graphModelForRunNetwork(vault: Vault, objective: string, result: InvestigateResult): GraphModel {
  const base: GraphModel = { objective: redactProjectionText(vault, objective), nodes: [], edges: [] };
  return growCaseNetwork(vault, base, result); // redacts the result payload + finalizes (same path as the grow)
}

/**
 * THE graph-model finalization chokepoint (ca-analyze INC-3): compose the three read projections in
 * the ONE order the analyst-authority invariant requires, reading analysisFor + correctionMap once.
 *   applyCorrectionsToModel (OUTERMOST/last) > applyAnalysisToModel (AI roles) > applyClustersToModel
 * applyCorrectionsToModel MUST be outermost so an analyst role/type correction always wins over an AI
 * role (PRD D1, the analyst-is-top-authority scar). applyClustersToModel only sets node.cluster
 * (independent of role/type), so it wraps applyAnalysisToModel — both AI projections sit below
 * corrections. A new projection (INC-4 scores) is added HERE, never at the 4 call sites (the scar:
 * a divergence between graphModelForRun/Case/grow/expand is how a projection silently misses a path).
 */
function finalizeModel(vault: Vault, model: GraphModel): GraphModel {
  const rec = analysisFor(vault);
  // INC-4a adds three projections HERE (the chokepoint, never the call sites): scores (node sizing),
  // metrics (centrality/community), and typed_rel edges. Each sets an independent node field or ADDS
  // edges, so they layer below corrections; applyCorrectionsToModel stays OUTERMOST (analyst authority).
  const ai = applyRelationshipsToModel(
    applyMetricsToModel(applyScoresToModel(applyClustersToModel(applyAnalysisToModel(model, rec), rec), rec), rec),
    rec,
  );
  // analyst node-removal is the OUTERMOST layer (founder 2026-06-25): an excluded node + its edges drop AFTER
  // corrections, so the match is on what the analyst actually saw/removed (the corrected display type/value).
  return applyExclusionsToModel(applyCorrectionsToModel(ai, correctionMap(vault)), excludedKeys(vault));
}

/** Perf bound on the mount fold. If a vault holds more runs, the cap is SURFACED in the objective
 *  label ("All runs (N of M)") — never silently truncated (gh-case-model D9). No console (F5: zero
 *  console.* in src). RunRecord has no timestamp, so the cap is over the lexical sort, not newest-first. */
const CASE_GRAPH_MAX_RUNS = 50;

/** Every redactable secret form for this vault — the Anthropic key AND every configured provider
 *  key, in their encoded/case-insensitive forms, longest-first (gh-case-model D7). Shared by
 *  graphModelForCase (the mount fold) and growCaseGraph (the run-complete grow) so BOTH carry
 *  identical key hygiene; a divergence here is exactly how the run-complete path could leak a key
 *  the mount path scrubs. */
function allSecretForms(vault: Vault): string[] {
  const key = currentKeyOrNull(vault);
  const providerForms = configuredSecretForms(vault);
  return key
    ? [...new Set([...keyForms(key), ...providerForms])].sort((a, b) => b.length - a.length)
    : providerForms;
}

/**
 * THE redaction chokepoint for every session read projection + persist (m3-redact-hardening / codex
 * blockers D1, D2). It scrubs EVERY configured secret form — the Anthropic key AND every provider key,
 * in their encodeURIComponent + case-insensitive + Censys-half forms — not just the Anthropic key. The
 * scar: once a provider key can flow through the agent loop (enrich tools), an Anthropic-only redact
 * (`redactDeep(x, key)`) would let a provider-echoed key leak to the graph / entity DB / runs / brief /
 * Q&A / persisted record. Identity when the vault holds no secret. `runDetail` / `graphModelForCase` /
 * `growCaseGraph` already used `allSecretForms`; these helpers finish the set so the policy is uniform.
 */
function redactProjectionDeep<T>(vault: Vault, value: T): T {
  const forms = allSecretForms(vault);
  return forms.length ? redactFormsDeep(value, forms) : value;
}
function redactProjectionText(vault: Vault, text: string): string {
  const forms = allSecretForms(vault);
  return forms.length ? redactForms(text, forms) : text;
}

// ---- clu-chat-persist: the conversation survives refresh / nav / tab-switch ----
// Chat lived ONLY in the mountChatDock() closure with zero persistence, so every render()
// (refresh, hashchange-nav, bfcache restore) re-mounted an empty dock and the history was gone.
// The graph already solved this via the gh-hydrate read projection; chat never got it. Mirror the
// run-record pattern: ONE key-redacted, case-scoped array (scopedVault prefixes case:<id>:),
// written through a single writer and rehydrated on mount. Encryption is by construction — vault.put
// seals the whole doc via crypto.ts before persist(), so nothing reaches disk in plaintext.
const CHAT_KEY = "chat"; // scopedVault → case:<id>:chat; one ordered array per case
const MAX_CHAT_MESSAGES = 100; // retention cap: oldest dropped with a VISIBLE marker (never silent)

export type ChatRole = "you" | "agent" | "aside";
/** A persisted grounding citation (mirrors the dock's QaSource; defined here so the dock imports it
 *  and session.ts stays free of any dock dependency). */
export interface ChatSource {
  run: string;
  entity: string;
  entity_type: string;
  status: string;
}
export interface ChatMessage {
  role: ChatRole;
  text: string;
  sources?: ChatSource[]; // agent grounding citations, replayed on rehydrate
}

function isTrimMarker(m: ChatMessage): boolean {
  return m.role === "aside" && / earlier messages? trimmed$/.test(m.text);
}
function trimMarker(dropped: number): ChatMessage {
  return { role: "aside", text: `⋯ ${dropped} earlier message${dropped === 1 ? "" : "s"} trimmed` };
}
function isChatMessage(v: unknown): v is ChatMessage {
  if (!v || typeof v !== "object") return false;
  const m = v as ChatMessage;
  return (m.role === "you" || m.role === "agent" || m.role === "aside") && typeof m.text === "string";
}

/** Cap chat history to the last `max` real messages. On overflow, drop the oldest and keep ONE leading
 *  aside marker so the trim is VISIBLE, never silent ([[no-silent-caps]]). Pure + unit-tested. Any prior
 *  marker is stripped before counting so markers never stack. */
export function capChatHistory(messages: ChatMessage[], max: number = MAX_CHAT_MESSAGES): ChatMessage[] {
  const real = messages.filter((m) => !isTrimMarker(m)); // a previous marker is not a real message
  if (real.length <= max) return real;
  const kept = real.slice(real.length - max);
  return [trimMarker(real.length - max), ...kept];
}

/** Rehydrate the active case's chat history (key-redacted, defense-in-depth — the stored copy is already
 *  redacted at write). Returns [] when none exists or the vault is locked. */
export function loadChatHistory(vault: Vault): ChatMessage[] {
  let raw: unknown;
  try {
    raw = vault.get(CHAT_KEY);
  } catch {
    return []; // locked
  }
  if (!Array.isArray(raw)) return [];
  const msgs = raw.filter(isChatMessage);
  return redactProjectionDeep(vault, msgs);
}

/** The SINGLE writer of the chat key. Caps + redacts every secret form (mirror run: persist) + seals.
 *  Callers guard a null/locked vault (app.ts no-ops when no case is active). */
export async function saveChatHistory(vault: Vault, messages: ChatMessage[]): Promise<void> {
  const capped = capChatHistory(messages);
  await vault.put(CHAT_KEY, redactProjectionDeep(vault, capped)); // single-writer; redact BEFORE disk
}

// ---- hydra ISSUE-1 + ISSUE-5 run journal (founder 2026-07-07) ----
// The live investigation graph is grown IN MEMORY only (app.ts liveGrowObserved) and made durable ONLY at
// finalize (the run: persist above). An abort SKIPS finalize and a reload KILLS the JS context, so the whole
// in-flight graph is lost — the founder sees the graph snap back to "Start here" mid-run, and a refresh wipes
// it. These journal the CURRENT live model to a durable, case-scoped key AS it grows: app.ts calls
// persistLiveRun (throttled) from liveGrowObserved and flushes it on abort; hydrateCaseGraph reads it back when
// no finalized run covers the in-flight work; a CLEAN finalize supersedes it and clears it. Single durable
// writer + redact-deep, mirroring the run: persist (the model already carries redacted content — redact again
// defensively, since a tool value could echo a key).
const LIVE_RUN_KEY = "run-live"; // case-scoped via scopedVault → case:<id>:run-live. ONE live run per case at a time.
// hydra reload-survival (founder 2026-07-08): the STEP TRAIL is journaled next to the graph, under its OWN
// case-scoped key (NOT folded into run-live, whose reader validates a raw GraphModel — a wrapper would break
// graph hydration). Same lifecycle: written by the same throttle/flush, cleared by the same clearLiveRun. A
// reload wipes the in-memory run-store, so #trail replays from here; redact-deep on write AND read because a
// tool result can echo a key (zero-retention posture, mirroring persistLiveRun).
const LIVE_RUN_STEPS_KEY = "run-live-steps";

/** Journal the current live-run graph so it survives an abort / reload before finalize. Single durable writer. */
export async function persistLiveRun(vault: Vault, model: GraphModel): Promise<void> {
  await vault.put(LIVE_RUN_KEY, redactProjectionDeep(vault, model));
}

/** The journaled live-run graph, or null when none is in flight (cleared by a clean finalize, or never set).
 *  Pure read; redact-on-read for defense-in-depth. */
export function readLiveRun(vault: Vault): GraphModel | null {
  let raw: unknown;
  try {
    raw = vault.get(LIVE_RUN_KEY);
  } catch {
    return null; // locked / missing
  }
  if (!raw || typeof raw !== "object" || !Array.isArray((raw as GraphModel).nodes)) return null; // null tombstone → absent
  return redactProjectionDeep(vault, raw) as GraphModel;
}

/** Drop the live journal — called on a CLEAN finalize, where the durable run: record supersedes it. Tombstone
 *  via the single put writer (the vault exposes no single-key delete; a null value reads back as absent). */
export async function clearLiveRun(vault: Vault): Promise<void> {
  await vault.put(LIVE_RUN_KEY, null);
  // NOTE: the STEP journal is deliberately NOT cleared here. A clean finalize drops the graph journal because
  // the durable run: record re-folds the graph on load — but nothing re-folds the step trail into #trail, so
  // clearing it would make a FINISHED run's log vanish on refresh (the common case). The step journal persists
  // as "the last run's trail" (case-scoped) and is overwritten when the next run streams. See persistLiveRunSteps.
}

/** Journal the live-run STEP TRAIL so #trail survives a reload. Single durable writer; redact-deep (a step's
 *  tool result can echo a key), mirroring persistLiveRun. Case-scoped via scopedVault. */
export async function persistLiveRunSteps(vault: Vault, steps: Step[]): Promise<void> {
  await vault.put(LIVE_RUN_STEPS_KEY, redactProjectionDeep(vault, steps));
}

/** The journaled step trail, or [] when none is in flight (cleared by a clean finalize, or never set).
 *  Redact-on-read for defense-in-depth. */
export function readLiveRunSteps(vault: Vault): Step[] {
  let raw: unknown;
  try {
    raw = vault.get(LIVE_RUN_STEPS_KEY);
  } catch {
    return []; // locked / missing
  }
  if (!Array.isArray(raw)) return []; // null tombstone / absent → empty
  return redactProjectionDeep(vault, raw) as Step[];
}

/**
 * The WHOLE-CASE graph model (gh-case-model / parity G1): a READ-ONLY projection folding every run:
 * record into one objective-rooted model via the gate-faithful mergeGraphModel, so a returning user's
 * home graph shows the ACCUMULATED findings instead of a blank canvas. Redaction is at the session
 * layer and covers ALL configured secrets — the Anthropic key AND every provider key, in their
 * encoded/case-insensitive forms (codex D7) — because a forged/imported/old record could carry a
 * provider secret; the objective + each run's findings are scrubbed BEFORE the pure fold. Objectives
 * are sorted for a deterministic fold (D8); steps are NOT folded (perf, D9). Returns null on zero runs.
 * NO vault write (single-writer untouched — this is a read projection, like the entity DB).
 */
export function graphModelForCase(vault: Vault): GraphModel | null {
  const objectives = [...objectivesUnder(vault, RUN_PREFIX)].sort();
  const total = objectives.length;
  if (total === 0) return null;
  const capped = objectives.slice(0, CASE_GRAPH_MAX_RUNS);

  // Read each record once, then partition agent runs vs file ingests. clu-graph-topology: the run:
  // namespace is dual-use (file reports + agent runs); sourceKind is the non-forgeable split (D4). A
  // file-only case must NOT read "All runs (N)" — that hub label is what made the home graph look wrong.
  const records: (Partial<RunRecord> & { sourceKind?: string })[] = [];
  for (const objective of capped) {
    try {
      const v = vault.get(`${RUN_PREFIX}${objective}`);
      if (v && typeof v === "object") records.push(v as Partial<RunRecord> & { sourceKind?: string });
      else records.push({});
    } catch {
      /* unreadable record: skip */
    }
  }
  // "Has any agent run?" must scan ALL objectives, not just the capped fold (codex): a case with >cap
  // lexically-earlier file ingests plus one agent run beyond the cap must still NOT be labeled file-only.
  let hasAgentRun = false;
  for (const objective of objectives) {
    try {
      const v = vault.get(`${RUN_PREFIX}${objective}`);
      if (v && typeof v === "object" && (v as { sourceKind?: string }).sourceKind !== FILE_SOURCE_KIND) {
        hasAgentRun = true;
        break; // short-circuit on the first agent run
      }
    } catch {
      /* unreadable record: skip */
    }
  }
  const label =
    !hasAgentRun
      ? "Case graph" // no agent runs (file-only): the entity network is the subject, not "runs"
      : total === 1
        ? objectives[0]
        : total > capped.length
          ? `All runs (${capped.length} of ${total})`
          : `All runs (${total})`;

  // Every secret form (provider keys + the Anthropic key), longest-first, case-insensitive (D7).
  const allForms = allSecretForms(vault);

  let model = emptyObjectiveGraphModel(label);
  const objId = model.nodes[0].id; // the objective node id (OBJECTIVE_ID stays private in model.ts)

  for (const rec of records) {
    // clu-graph-node-parity: provenance for the node border — a file-ingest record is "intake", an agent
    // run is "osint" (the non-forgeable sourceKind split, D4). The original encodes this as the border style.
    const origin = rec.sourceKind === FILE_SOURCE_KIND ? "intake" : "osint";
    // d2b98925 (discovery-grow, founder 2026-06-25): an intake (file_ingest) record contributes ONLY its
    // PROMOTED (high-confidence) entities to the graph — NOT its leads. Raw extraction puts nearly every
    // entity in `leads` (confidence "low", source_count 1), so folding leads here dumped the whole file as
    // nodes (graph = extraction state, not investigation state — the bug). Under discovery-grow the graph
    // grows from the DIG: an intake lead stays in the data (/reports + /entities) and becomes a node when an
    // agent run promotes it. Agent runs (osint) keep BOTH promoted + leads — their leads ARE the live dig
    // growth (keep-all, [[no-cooccurrence-edges]]).
    const recLeads = origin === "intake" ? [] : (Array.isArray(rec.leads) ? rec.leads : []);
    const payload = {
      promoted: Array.isArray(rec.promoted) ? rec.promoted : [],
      leads: recLeads,
    };
    const safe = allForms.length ? redactFormsDeep(payload, allForms) : payload;
    model = mergeGraphModel(model, objId, { promoted: safe.promoted, leads: safe.leads } as InvestigateResult, origin);
  }

  // clu-graph-topology: layer the entity↔entity NETWORK (co-occurrence + linked) onto the objective-rooted
  // model so the home graph reads as a web, not a star off the hub (the original tool's shape). The
  // structural connections come from entityDbFor, which already key-redacts every secret form + applies the
  // analysis/correction overlays — finalizeModel stays the single overlay chokepoint (this only adds edges).
  model = withEntityNetworkEdges(vault, model, objId);

  // cg-network (PRD prd-case-graph-2026-06-22): strip the objective hub + its star spokes so the
  // home/case graph is a pure entity↔entity web — the original api_graph shape. The FIFA real-case
  // model diff proved the hub+spokes were a divergence (clone 9/36 vs original 8/28 on identical
  // input). The entity network edges withEntityNetworkEdges just added do NOT touch the hub, so they
  // survive the strip; only the hub node + objective→entity spokes are removed.
  return finalizeModel(vault, stripObjective(model));
}

/** clu-graph-topology: add deduped entity↔entity `linked` edges from the entity DB's connections to an
 *  objective-rooted model. (D2/finding-3: intake `co_occurs` proximity edges are NO LONGER folded — they
 *  were the ingest hairball; see the per-line note below.) Each model entity node is matched to its entity-DB key by
 *  display type|label (both derive from the SAME redacted run records). surfaced_in is skipped — that is
 *  the objective spoke the star already draws. One network edge per pair (linked wins over co_occurs via
 *  the entity DB's connection sort). Pure: reads structural connections only, mutates nothing. */
function withEntityNetworkEdges(vault: Vault, model: GraphModel, objId: string): GraphModel {
  const store = entityDbFor(vault);
  // (co_occurs render REMOVED — founder 2026-06-24 [[no-cooccurrence-edges]]: co-occurrence is not an edge.
  // The intake-vs-agent co_occurs distinction no longer matters because NO co_occurs reaches the render.)
  // Match each model node to its entity-DB key by the CANONICAL key (canonKey == entityKey of canonRef),
  // NOT the overlaid display type/label (codex: a Process type overlay / analyst type correction would
  // otherwise drop every edge touching that node). store.connections keys + entityKey(c.other) are this
  // same canonical form. The entity DB reflects the WHOLE case (consistent with /entities); output is
  // bounded by MAX_NETWORK_EDGES.
  const nodeIdByKey = new Map<string, string>();
  for (const n of model.nodes) {
    if (n.kind === "objective") continue;
    nodeIdByKey.set(canonKey(n.entityType ?? "", n.label), n.id);
  }
  const edges = model.edges.slice();
  const seen = new Set<string>(); // one network edge per unordered node pair
  let added = 0;
  // clu-graph-fit-cap: iterate owners (and each owner's connections) in a CANONICAL sorted order so the
  // MAX_NETWORK_EDGES cap keeps the SAME edges regardless of vault write/import order (codex on f8c2d845:
  // the prior Object.entries insertion order made the surviving edge set depend on import order). The
  // secondary sort preserves "linked wins over co_occurs" for a pair (linked ranks before co_occurs).
  const linkFirst = (rt: string): number => (rt === "linked" ? 0 : 1);
  const ownerEntries = Object.entries(store.connections).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [ownerKey, conns] of ownerEntries) {
    if (added >= MAX_NETWORK_EDGES) break; // deterministic cap (owners iterated in sorted key order)
    const fromId = nodeIdByKey.get(ownerKey);
    if (!fromId) continue;
    const sortedConns = conns.slice().sort((x, y) => {
      const kx = entityKey(x.other), ky = entityKey(y.other);
      if (kx !== ky) return kx < ky ? -1 : 1;
      return linkFirst(x.relType) - linkFirst(y.relType);
    });
    for (const c of sortedConns) {
      // founder 2026-06-24 ([[no-cooccurrence-edges]]): render ONLY real typed `linked` relationships as
      // graph edges. co_occurs (co-occurrence) and surfaced_in (the objective spoke) are NOT edges — two
      // entities surfacing in the same run/doc is not a relationship, so they are not connected. The
      // co_occurs SIGNAL still lives on the entity DB (clusters, dossiers, Q&A relatedness, the agent's
      // suggested-links hint) — it just never becomes a graph edge (the all-pairs hairball is gone).
      if (c.relType !== "linked") continue;
      const toId = nodeIdByKey.get(entityKey(c.other));
      if (!toId || toId === fromId || toId === objId || fromId === objId) continue;
      const [lo, hi] = fromId < toId ? [fromId, toId] : [toId, fromId];
      const sig = `${lo} ${hi}`;
      if (seen.has(sig)) continue;
      seen.add(sig);
      edges.push({ from: lo, to: hi, kind: c.relType, confidence: c.confidence });
      if (++added >= MAX_NETWORK_EDGES) break; // cap network edges so a huge case can't blow up cytoscape
    }
  }
  return { ...model, edges };
}

// clu-graph-topology: bound the entity↔entity network edges. Per-run co-occurrence is ALSO bounded
// upstream by MAX_COOCCUR_ENTITIES (entity DB sets cooccurTruncated), so this is the case-level backstop.
const MAX_NETWORK_EDGES = 2000;

/**
 * gh-hydrate D5/D6: fold a JUST-COMPLETED run's IN-MEMORY result into the accumulated case graph,
 * returning the grown model. The result is redacted at the SESSION layer (every secret form — the
 * Anthropic key AND provider keys, D7) BEFORE the pure, gate-faithful mergeGraphModel re-gates +
 * dedups it against `base`, so the run-complete grow carries the SAME key hygiene as the mount fold
 * (graphModelForCase) and the run-replace path (graphModelForRun). Growing from the in-memory result
 * — NOT a re-read of run: records — means a best-effort persist failure (runInvestigation's put is
 * try/caught) never drops the just-finished run from the graph (D6). NO vault write: a read
 * projection, like graphModelForCase. `fromNodeId` is the base's objective node id (base.nodes[0].id).
 */
export function growCaseGraph(vault: Vault, base: GraphModel, fromNodeId: string, result: InvestigateResult): GraphModel {
  const forms = allSecretForms(vault);
  const payload = {
    promoted: Array.isArray(result?.promoted) ? result.promoted : [],
    leads: Array.isArray(result?.leads) ? result.leads : [],
  };
  const safe = forms.length ? redactFormsDeep(payload, forms) : payload;
  return finalizeModel(vault, mergeGraphModel(base, fromNodeId, { promoted: safe.promoted, leads: safe.leads } as InvestigateResult)); // D10 + pf-process D4
}

/**
 * cg-network (PRD prd-case-graph-2026-06-22): the run-complete grow into the entity↔entity NETWORK
 * home graph. Same key hygiene as growCaseGraph (redact every secret form BEFORE the pure merge),
 * but folds the run's findings as a co-occurrence clique with NO objective hub / NO spokes — so a
 * returning user's network case graph (graphModelForCase) stays a web when an in-session run grows
 * into it. Used by renderRunGraph; growCaseGraph stays for the per-node transform/expand path where
 * the new findings legitimately spoke off the source ENTITY (an entity↔entity edge, not a hub).
 * No fromNodeId: the network has no hub anchor; placement is the caller's cyGraph.grow concern.
 */
export function growCaseNetwork(vault: Vault, base: GraphModel, result: InvestigateResult, origin: string = "osint"): GraphModel {
  const forms = allSecretForms(vault);
  const payload = {
    promoted: Array.isArray(result?.promoted) ? result.promoted : [],
    leads: Array.isArray(result?.leads) ? result.leads : [],
    // PRD-B (RCA item 3): carry the run's LIVE relationships into the grow so the agent's typed edges paint
    // the moment the run completes, not only on a remount (codex issue-6 C2). Redacted with the rest.
    relationships: Array.isArray(result?.relationships) ? result.relationships : [],
  };
  const safe = forms.length ? redactFormsDeep(payload, forms) : payload;
  // sp-9ef4fa65: pass the case-level edge backstop (MAX_NETWORK_EDGES) so the grow/first-paint matches at
  // scale. (sp-4285b671: the former MAX_COOCCUR_ENTITIES pass was removed — mergeNetworkModel no longer caps
  // a co-occurrence clique, so it was dead; the live entity-DB cap in db.ts is unaffected.)
  return finalizeModel(vault, mergeNetworkModel(
    base,
    { promoted: safe.promoted, leads: safe.leads, relationships: safe.relationships } as InvestigateResult,
    { maxNetworkEdges: MAX_NETWORK_EDGES },
    origin,
  ));
}

// ---- ed-session: the entity DB — a read-only, key-redacted projection over runs ----

// ---- ca-session: analyst corrections — the top-authority override (single-writer, projected everywhere) ----

const CORRECTION_PREFIX = "correction:"; // correction:<predicate>:<canonKey>  (predicate first: it has no ':')
const ANALYST_KEY = "setting:analyst";
const MAX_ANALYST_NAME = 40;

/** The analyst's display name (local attribution only, NOT auth). Redacted + capped on write (codex D5). */
export async function setAnalyst(vault: Vault, name: string): Promise<void> {
  const clean = redactProjectionText(vault, (name ?? "").trim()).slice(0, MAX_ANALYST_NAME);
  try {
    await vault.put(ANALYST_KEY, { name: clean });
  } catch {
    throw new SessionError("Unlock your vault to set your name.");
  }
}
export function getAnalyst(vault: Vault): string {
  try {
    const v = vault.get(ANALYST_KEY);
    if (v && typeof v === "object" && typeof (v as { name?: unknown }).name === "string") {
      const n = (v as { name: string }).name.trim();
      if (n) return n;
    }
  } catch {
    /* locked or unset */
  }
  return "analyst";
}

/** Apply an analyst override (role | type) to an entity. The vault key is built from the REDACTED
 *  type/value and REJECTED if it contains [REDACTED] (codex D5: you cannot correct a secret-tainted
 *  entity). Single-writer vault.put; awaits + throws on failure (codex D8). */
export async function applyCorrection(
  vault: Vault,
  type: string,
  value: string,
  predicate: string,
  newValue: string,
): Promise<void> {
  if (!isValidCorrection(predicate, newValue)) throw new SessionError("Not a valid correction.");
  // D5: redact the type/value FIRST and reject a secret-tainted entity BEFORE canonKey lowercases the
  // [REDACTED] marker (a lowercased "[redacted]" would slip a case-sensitive post-key check).
  const safeType = redactProjectionText(vault, type);
  const safeValue = redactProjectionText(vault, value);
  if (safeType.includes("[REDACTED]") || safeValue.includes("[REDACTED]")) {
    throw new SessionError("Cannot correct a secret-tainted entity.");
  }
  const key = canonKey(safeType, safeValue);
  // post-audit issue 3: redact the analyst-typed corrected value OUT too (defense-in-depth — every other
  // projection write routes through redactProjectionText; a pasted secret in a correction must not persist).
  const record = { value: redactProjectionText(vault, newValue), predicate, author: getAnalyst(vault), at: new Date().toISOString(), deleted: false };
  try {
    await vault.put(`${CORRECTION_PREFIX}${predicate}:${key}`, record); // the ONE write path
  } catch {
    throw new SessionError("Unlock your vault to apply a correction.");
  }
}

/** Revert a correction via a tombstone (codex D7: Vault has no delete; never put(undefined)). */
export async function revertCorrection(vault: Vault, canonicalKey: string, predicate: string): Promise<void> {
  if (predicate !== "role" && predicate !== "type") throw new SessionError("Not a valid predicate.");
  const record = { value: "", predicate, author: getAnalyst(vault), at: new Date().toISOString(), deleted: true };
  try {
    await vault.put(`${CORRECTION_PREFIX}${predicate}:${canonicalKey}`, record);
  } catch {
    throw new SessionError("Unlock your vault to revert.");
  }
}

// ---- analyst node-removal (founder 2026-06-25): a REVERSIBLE "exclude" — the analyst removes a node + its
// edges from the graph AND /entities, undoable, data never destroyed (the no-delete vault, [[analyst-is-top-
// authority]]). It rides the SAME single-writer correction-key infrastructure under a dedicated `excluded`
// predicate (parseCorrectionKey ignores any non role/type predicate, so it never pollutes the role/type map).
// Active record = excluded; a tombstone (deleted:true) = restored. Both projection chokepoints (finalizeModel
// for the graph, entityDbFor for /entities) drop excluded keys, so the node + every edge touching it vanish.
const EXCLUDED_PREDICATE = "excluded";

/** Exclude (analyst-remove) an entity from the case projections. Reversible. Redact-and-reject a secret-
 *  tainted entity exactly like applyCorrection. Single-writer vault.put. Returns the canonical key (for Undo). */
export async function excludeEntity(vault: Vault, type: string, value: string): Promise<string> {
  const safeType = redactProjectionText(vault, type);
  const safeValue = redactProjectionText(vault, value);
  if (safeType.includes("[REDACTED]") || safeValue.includes("[REDACTED]")) {
    throw new SessionError("Cannot remove a secret-tainted entity.");
  }
  const key = canonKey(safeType, safeValue);
  const record = { predicate: EXCLUDED_PREDICATE, author: getAnalyst(vault), at: new Date().toISOString(), deleted: false };
  try {
    await vault.put(`${CORRECTION_PREFIX}${EXCLUDED_PREDICATE}:${key}`, record); // the ONE write path
  } catch {
    throw new SessionError("Unlock your vault to remove the node.");
  }
  return key;
}

/** Restore an excluded entity (Undo) via a tombstone — the no-delete vault keeps the original write (D7). */
export async function restoreEntity(vault: Vault, canonicalKey: string): Promise<void> {
  const record = { predicate: EXCLUDED_PREDICATE, author: getAnalyst(vault), at: new Date().toISOString(), deleted: true };
  try {
    await vault.put(`${CORRECTION_PREFIX}${EXCLUDED_PREDICATE}:${canonicalKey}`, record);
  } catch {
    throw new SessionError("Unlock your vault to restore the node.");
  }
}

/** The canonical keys the analyst has EXCLUDED (active, non-tombstoned). The graph + entity-DB projections
 *  skip these; an edge touching an excluded node drops because the node is gone. */
export function excludedKeys(vault: Vault): Set<string> {
  const out = new Set<string>();
  let keys: string[];
  try { keys = vault.keys(); } catch { return out; }
  const prefix = `${CORRECTION_PREFIX}${EXCLUDED_PREDICATE}:`;
  for (const k of keys) {
    if (!k.startsWith(prefix)) continue;
    let rec: unknown;
    try { rec = vault.get(k); } catch { continue; }
    if (!rec || typeof rec !== "object") continue;
    if ((rec as { deleted?: unknown }).deleted === true) continue; // tombstone -> restored (active again)
    out.add(k.slice(prefix.length));
  }
  return out;
}

/** Drop analyst-EXCLUDED nodes (and every edge touching them) from a graph model. Matches a node by the same
 *  canonical key the rest of the projection uses — canonKey(entityType, label) — so it agrees with what the
 *  node card / chat excluded. The objective node has no entity key and is never excluded. Pure. */
function applyExclusionsToModel(model: GraphModel, excluded: Set<string>): GraphModel {
  if (!excluded.size) return model;
  const removedIds = new Set<string>();
  const nodes = model.nodes.filter((n) => {
    if (n.kind === "objective") return true;
    if (excluded.has(canonKey(n.entityType ?? "", n.label))) { removedIds.add(n.id); return false; }
    return true;
  });
  if (!removedIds.size) return model;
  const edges = model.edges.filter((e) => !removedIds.has(e.from) && !removedIds.has(e.to));
  return { ...model, nodes, edges };
}

/** Drop analyst-EXCLUDED entities (and connections to/from them) from an entity store — the /entities + the
 *  graph network-edge source. Keyed by canonKey, the same key excludeEntity wrote. Pure. */
function applyExclusionsToStore(store: EntityStore, excluded: Set<string>): EntityStore {
  if (!excluded.size) return store;
  const entities: Record<string, EntityRecord> = {};
  for (const [k, rec] of Object.entries(store.entities)) if (!excluded.has(k)) entities[k] = rec;
  const connections: Record<string, Connection[]> = {};
  for (const [k, conns] of Object.entries(store.connections)) {
    if (excluded.has(k)) continue;
    const kept = conns.filter((c) => !excluded.has(entityKey(c.other)));
    if (kept.length) connections[k] = kept;
  }
  return { ...store, entities, connections };
}

/** Parse a correction: key into {predicate, canonKey}. predicate is first (no ':'), so the FIRST ':'
 *  after the prefix is the separator; the canonKey (a JSON tuple that may contain ':') is the remainder. */
function parseCorrectionKey(k: string): { predicate: string; canonicalKey: string } | null {
  const rest = k.slice(CORRECTION_PREFIX.length);
  const sep = rest.indexOf(":");
  if (sep < 0) return null;
  const predicate = rest.slice(0, sep);
  if (predicate !== "role" && predicate !== "type") return null;
  return { predicate, canonicalKey: rest.slice(sep + 1) };
}

/** The ACTIVE correction map (non-tombstoned, allowlisted values only) keyed by canonKey. */
export function correctionMap(vault: Vault): CorrectionMap {
  let keys: string[];
  try {
    keys = vault.keys();
  } catch {
    return {};
  }
  const map: CorrectionMap = {};
  for (const k of keys) {
    if (!k.startsWith(CORRECTION_PREFIX)) continue;
    const parsed = parseCorrectionKey(k);
    if (!parsed) continue;
    let rec: unknown;
    try {
      rec = vault.get(k);
    } catch {
      continue;
    }
    if (!rec || typeof rec !== "object") continue;
    const r = rec as { value?: unknown; deleted?: unknown };
    if (r.deleted === true) continue; // tombstone -> not active (D7)
    const value = typeof r.value === "string" ? r.value : "";
    if (!isValidCorrection(parsed.predicate, value)) continue;
    (map[parsed.canonicalKey] ??= {})[parsed.predicate as "role" | "type"] = value;
  }
  return map;
}

export interface CorrectionRow {
  canonicalKey: string;
  label: string;
  predicate: string;
  value: string;
  author: string;
  active: boolean; // false when the entity no longer exists (codex D4 orphan)
}

/** The corrections for the audit page: active first; an orphaned correction (its entity is gone) is
 *  flagged inactive (codex D4). Labels + authors are redacted (codex D5). */
export function listCorrections(vault: Vault): CorrectionRow[] {
  const present = entityDbFor(vault).entities; // corrections don't rekey (D2) -> the key set is the identity set
  const rows: CorrectionRow[] = [];
  let keys: string[];
  try {
    keys = vault.keys();
  } catch {
    return [];
  }
  for (const k of keys) {
    if (!k.startsWith(CORRECTION_PREFIX)) continue;
    const parsed = parseCorrectionKey(k);
    if (!parsed) continue;
    let rec: unknown;
    try {
      rec = vault.get(k);
    } catch {
      continue;
    }
    if (!rec || typeof rec !== "object") continue;
    const r = rec as { value?: unknown; deleted?: unknown; author?: unknown };
    if (r.deleted === true) continue; // tombstones are not shown
    const value = typeof r.value === "string" ? r.value : "";
    if (!isValidCorrection(parsed.predicate, value)) continue;
    const entity = present[parsed.canonicalKey];
    const label = entity ? entity.label : decodeCanonKeyValue(parsed.canonicalKey);
    rows.push({
      canonicalKey: parsed.canonicalKey,
      label: redactProjectionText(vault, label),
      predicate: parsed.predicate,
      value,
      author: redactProjectionText(vault, typeof r.author === "string" ? r.author : "analyst"),
      active: !!entity,
    });
  }
  return rows;
}

/** The display value out of a canonKey JSON tuple `["type","value"]`, or the raw key on a parse miss. */
function decodeCanonKeyValue(canonicalKey: string): string {
  try {
    const t = JSON.parse(canonicalKey);
    if (Array.isArray(t) && typeof t[1] === "string") return t[1];
  } catch {
    /* not a tuple */
  }
  return canonicalKey;
}

/** Apply the vault's corrections to a finding's display type (codex D9 — the brief reads entity_type). */
function correctFindingType(f: Finding, map: CorrectionMap): Finding {
  const corr = map[canonKey(f.entity_type, f.entity)];
  return corr?.type ? { ...f, entity_type: corr.type } : f;
}

// ---- pf-process (INC-1): the analysis: record + auto-schema + the Process orchestration runner ----
//
// The Process pipeline turns raw ingest into an analyzed case. Its OUTPUT (the auto-modeled schema +
// per-entity AI roles/types — later increments add edges/clusters/scores) is persisted in ONE
// `analysis:<case>` vault record, written ONLY through the existing single-writer vault.put. The
// projections (entityDbFor + the graph chokepoints) read THROUGH the PURE applyAnalysis overlay,
// layered BELOW corrections, so an analyst correction always wins (analyst is top authority, PRD D1).

const ANALYSIS_PREFIX = "analysis:";
// The Process-output record lives at a FIXED inner key per case. "default" here is the RECORD SLUG, NOT a
// case dimension (there is no implicit "default" case anymore) — scopedVault namespaces it to
// case:<id>:analysis:default. The wrapper (scopedVault) is the SINGLE per-case isolation chokepoint.
const ANALYSIS_SLUG = "default";
const ANALYSIS_KEY = `${ANALYSIS_PREFIX}${ANALYSIS_SLUG}`;

// ---- sf-cases: real multi-case (one vault per user; cases = a key-namespace dimension; docs/17) ----

const SETTING_PREFIX = "setting:";
const CASE_PREFIX = "case:"; // reserved — no base DATA key starts with it
const ACTIVE_CASE_KEY = `${SETTING_PREFIX}active_case`;
const CASES_KEY = `${SETTING_PREFIX}cases`;
const MAX_CASE_NAME = 80;

// A GLOBAL key (per-USER, shared across cases): the Anthropic + provider keys (secret:) and the settings
// (analyst / worker_url / onboarded / active_case / cases). EVERYTHING else is a DATA key (a CATCH-ALL,
// safer than an allowlist — it auto-scopes run:/brief:/groupbrief:/correction:/analysis:/entity:/dossier:/
// alert:/report:/pivot: AND any future prefix, so no data class can be missed → no cross-case bleed).
function isGlobalKey(key: string): boolean {
  return key.startsWith(SECRET_PREFIX) || key.startsWith(SETTING_PREFIX);
}

/**
 * sf-cases: a per-case VIEW of the vault — the SINGLE isolation chokepoint. A DATA key is transparently
 * scoped to `caseId`; a GLOBAL key passes through unchanged. EVERY projection/writer takes `vault: Vault`,
 * so passing the scoped view scopes them all — no call site can miss (the per-call-site-edit bleed risk is
 * eliminated). EVERY case is `case:<id>:` prefixed (no implicit-default un-prefixed root); a case sees ONLY
 * its own `case:<id>:*` keys + the GLOBAL secret:/setting: keys. Never call with an empty id (it throws).
 * Implemented as a Proxy: get/put/keys are scoped; the classified non-key-addressed members
 * (lock/changePassword/...) forward bound to the real vault; an UNCLASSIFIED Vault function member (a
 * future delete/clear/rename) THROWS — an allowlist, not a denylist, so a new key-addressed mutator
 * cannot silently bypass case-scoping (codex). Symbols + non-function props + Object.prototype builtins
 * always pass through so Promise/JSON/inspect probes never break.
 */
// The scopedVault allowlist: CURRENT non-key-addressed Vault members that forward to the raw vault
// unchanged. get/put/keys are scoped separately. A future key-addressed mutator is NOT here, so the
// Proxy throws instead of binding it to the un-scoped vault (the cross-case-bleed tripwire).
const VAULT_PASS_THROUGH = new Set(["changePassword", "lock", "persist", "changePasswordUnlocked"]);
export function scopedVault(vault: Vault, caseId: string): Vault {
  if (!caseId) throw new SessionError("scopedVault: no active case to scope to"); // never scope with an empty id
  const prefix = `${CASE_PREFIX}${caseId}:`;
  const enc = (key: string): string => (isGlobalKey(key) ? key : prefix + key);
  // a key is VISIBLE to this case iff: it's global, OR it's under THIS case's prefix. dec strips the prefix
  // back to the base key. EVERY case is prefixed now — there is no un-prefixed (implicit-default) data class.
  const visible = (k: string): boolean => isGlobalKey(k) || k.startsWith(prefix);
  const dec = (k: string): string => (isGlobalKey(k) ? k : k.slice(prefix.length));
  return new Proxy(vault, {
    get(target, prop) {
      if (prop === "put") return (k: string, v: unknown) => target.put(enc(k), v);
      if (prop === "get") return (k: string) => target.get(enc(k));
      if (prop === "keys") return () => target.keys().filter(visible).map(dec);
      if (typeof prop === "symbol") return Reflect.get(target, prop, target); // Symbol.* probes pass through
      // OWN data fields (storage/file/dataKeyBytes/dataKey/doc, set in the constructor) are internal — never
      // expose them through the case view: JSON.stringify / Object.entries would otherwise serialize the RAW
      // unscoped document (every case + every secret). TS `private` is enumerable at runtime, so this MUST be
      // blocked at the proxy, not assumed (codex). Only the public prototype API is reachable.
      if (Object.prototype.hasOwnProperty.call(target, prop)) return undefined;
      const val = Reflect.get(target, prop, target);
      if (typeof val !== "function") return val; // the `locked` getter (prototype) + undefined probes (then/toJSON)
      // Object.prototype builtins (constructor/toString…) + the classified non-key-addressed Vault methods
      // forward bound to the raw vault.
      if (prop in Object.prototype || VAULT_PASS_THROUGH.has(prop)) return val.bind(target);
      // an UNCLASSIFIED Vault function member (a future delete/clear/rename) → refuse, so it can't bind to
      // the un-scoped vault and bleed across cases. Classify it (scoped vs pass-through) before use.
      throw new Error(`scopedVault: unhandled Vault member '${String(prop)}'`);
    },
    getOwnPropertyDescriptor(target, prop) {
      // mirror the get-trap own-field block for DESCRIPTOR reads (util.inspect / console.log / Object.entries
      // / getOwnPropertyDescriptor read the value off the descriptor, bypassing [[Get]]). The Vault's own
      // fields are configurable, so reporting them non-existent is invariant-safe; only the prototype API
      // (methods + the `locked` getter) stays visible (codex).
      if (typeof prop === "string" && Object.prototype.hasOwnProperty.call(target, prop)) return undefined;
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
  }) as Vault;
}

export interface CaseInfo {
  id: string;
  name: string;
  createdAt: string;
  active: boolean;
}

/** The active case id (a GLOBAL setting), or "" when no case is active (a fresh vault, or the last case was
 *  deleted). A stored id that no longer exists in the case list reads as "" — a stale pointer shows the
 *  empty state, never a phantom case. There is NO implicit "default" fallback anymore. */
export function activeCaseId(vault: Vault): string {
  let id = "";
  try {
    const v = vault.get(ACTIVE_CASE_KEY);
    if (v && typeof v === "object" && typeof (v as { id?: unknown }).id === "string") id = (v as { id: string }).id;
  } catch {
    return ""; // locked
  }
  if (!id) return "";
  return storedCases(vault).some((c) => c.id === id) ? id : ""; // stale pointer → no active case
}

/** The stored cases (a GLOBAL setting:cases index), redacted. EVERY case is here — there is no implicit case. */
function storedCases(vault: Vault): { id: string; name: string; createdAt: string }[] {
  let v: unknown;
  try {
    v = vault.get(CASES_KEY);
  } catch {
    return [];
  }
  const arr = Array.isArray(v) ? v : [];
  const out: { id: string; name: string; createdAt: string }[] = [];
  for (const c of arr) {
    if (!c || typeof c !== "object") continue;
    const id = (c as { id?: unknown }).id;
    const name = (c as { name?: unknown }).name;
    const createdAt = (c as { createdAt?: unknown }).createdAt;
    if (typeof id !== "string" || !id) continue;
    out.push({
      id, // an opaque uuid (never name-derived) — no redaction needed, but it can't carry a secret by construction
      name: redactProjectionText(vault, typeof name === "string" ? name : "Untitled case"), // match createCase's default
      createdAt: typeof createdAt === "string" ? createdAt : "",
    });
  }
  return out;
}

/** The full case list, the active one flagged. EMPTY on a fresh vault (no implicit "Default case" row). */
export function listCases(vault: Vault): CaseInfo[] {
  const active = activeCaseId(vault);
  return storedCases(vault).map((c) => ({ ...c, active: c.id === active }));
}

/** Create a NEW case. The id is an OPAQUE crypto.randomUUID() (NEVER name-derived — a slug could embed a
 *  pasted key/sensitive name into the raw case:<id>: key). setting:cases stores only the redacted+capped name. */
export async function createCase(vault: Vault, name: string): Promise<string> {
  const id = `c-${crypto.randomUUID()}`; // opaque; never contains a name
  const safeName = redactProjectionText(vault, (name ?? "").trim()).slice(0, MAX_CASE_NAME) || "Untitled case";
  const existing = storedCases(vault);
  const next = [...existing, { id, name: safeName, createdAt: new Date().toISOString() }];
  try {
    await vault.put(CASES_KEY, next); // GLOBAL setting: key — single-writer vault.put
  } catch {
    throw new SessionError("Unlock your vault to create a case.");
  }
  return id;
}

/** Set the active case (a GLOBAL setting). "" clears the active case (the empty state); any other id must be
 *  a known case (no arbitrary id). */
export async function setActiveCase(vault: Vault, id: string): Promise<void> {
  const known = id === "" || storedCases(vault).some((c) => c.id === id);
  if (!known) throw new SessionError("Unknown case.");
  try {
    await vault.put(ACTIVE_CASE_KEY, { id });
  } catch {
    throw new SessionError("Unlock your vault to switch cases.");
  }
}

/** One-time legacy-data migration. A pre-cases vault stored its data UN-PREFIXED (the old implicit "default"
 *  case). With the default concept gone, that data is owned by no case — move it into ONE real case so nothing
 *  orphans. Idempotent: after the move no un-prefixed data remains, so a second unlock is a no-op. Only adopts
 *  the migrated case as active when there is no active case (an existing named active case is preserved). RAW
 *  vault only — the keys are absolute. */
export async function migrateLegacyData(vault: Vault): Promise<void> {
  let keys: string[];
  try {
    keys = vault.keys();
  } catch {
    return; // locked
  }
  const legacy = keys.filter((k) => !isGlobalKey(k) && !k.startsWith(CASE_PREFIX));
  if (legacy.length === 0) return; // nothing un-prefixed → already migrated / fresh vault
  const id = await createCase(vault, "My case");
  const mapping: Record<string, string> = {};
  for (const k of legacy) mapping[k] = `${CASE_PREFIX}${id}:${k}`;
  await vault.rekey(mapping); // move every legacy data key under the new case (one persist)
  if (activeCaseId(vault) === "") await setActiveCase(vault, id); // adopt it only if nothing else is active
}

/** Permanently delete a case and ALL its data — every `case:<id>:*` key (runs, briefs, entities, analysis,
 *  dossiers, alerts, …). Refuses the ACTIVE case (the caller switches away first — app.ts switches to another
 *  case, or to the empty state when this was the last one). Takes the RAW vault: the keys are ABSOLUTE
 *  `case:<id>:` names, so this must NOT run through scopedVault (which would double-prefix and delete nothing).
 *  The setting:cases index update is the single-writer vault.put. */
export async function deleteCase(vault: Vault, id: string): Promise<void> {
  if (!id) throw new SessionError("Unknown case.");
  if (activeCaseId(vault) === id) throw new SessionError("Switch to another case before deleting this one.");
  const existing = storedCases(vault);
  if (!existing.some((c) => c.id === id)) throw new SessionError("Unknown case.");
  try {
    await vault.deleteByPrefix(`${CASE_PREFIX}${id}:`); // drop every data key for this case
    await vault.put(CASES_KEY, existing.filter((c) => c.id !== id)); // GLOBAL setting: index — single-writer put
  } catch (err) {
    if (err instanceof SessionError) throw err;
    throw new SessionError("Unlock your vault to delete a case.");
  }
}

/** The current case's Process-output record, validated + safe, or null when none/locked. Read-only.
 *  The stored record was already redacted on write; validateAnalysisRecord coerces a forged/imported
 *  record to a safe shape so a malformed value can never break a render/load (fable-discipline). */
export function analysisFor(vault: Vault): AnalysisRecord | null {
  let raw: unknown;
  try {
    raw = vault.get(ANALYSIS_KEY);
  } catch {
    return null; // locked
  }
  if (!raw || typeof raw !== "object") return null;
  return validateAnalysisRecord(raw, ANALYSIS_SLUG);
}

/**
 * THE write chokepoint for the analysis record (PRD D5/D7). It (1) VALIDATES the record into a safe
 * typed shape (drops non-allowlisted role/type overlays + coerces the schema), then (2) REDACTS every
 * secret form out of the whole record BEFORE vault.put — exactly the consolidate discipline (never
 * persist-then-redact). The overlay keys already come from the key-redacted entityDbFor, and the
 * schema is redacted in autoModelSchema; this is defense in depth at the persistence boundary.
 */
export async function putAnalysis(vault: Vault, rec: AnalysisRecord, signal?: AbortSignal): Promise<void> {
  const validated = validateAnalysisRecord({ ...rec, updatedAt: new Date().toISOString() }, rec.case || ANALYSIS_SLUG);
  const safe = redactProjectionDeep(vault, validated);
  // codex BLOCKER (D8): fence the write right before vault.put — a Process run superseded (its signal
  // aborted) between the runner's ensureLive() check and here must NOT land stale analysis over the
  // fresh run's output. vault.put is the last abortable point.
  if (signal?.aborted) throw new SessionError("Processing was cancelled.");
  try {
    await vault.put(ANALYSIS_KEY, safe); // the ONE write path (single-writer createWritable in store.ts)
  } catch {
    throw new SessionError("Unlock your vault to process the case.");
  }
}

// ---- cap-understand-schema: the REAL LLM understand pass (port of understand.py:discover_schema) ----

// understand.py SYSTEM — the senior-analyst data-model designer. NOT a typedetect+DEFAULT_SCHEMA
// stopgap (PRD D6): the model READS the case and proposes the entity types / roles / sub-roles / noise
// rules that fit THIS domain, seeded (not forced) by the deterministic type detection.
const SCHEMA_SYSTEM = [
  "You are a senior intelligence analyst designing the data model for a NEW investigation. You are",
  "handed (1) the analyst's objective(s), and (2) the entities a regex extractor pulled out, grouped by",
  "its crude type with counts and sample values.",
  "",
  "Your job: propose the ENTITY TYPES, ROLES, SUB-ROLES, and NOISE rules that fit THIS case's domain.",
  "Do not force a generic threat-network template. A crypto rug-pull is not a hacktivist crew is not a",
  "disinfo network — each needs its own buckets. Model what the case is ACTUALLY about.",
  "",
  "- entity_types: the kinds of things that matter here (wallet, smart_contract, exchange, persona,",
  "  outlet, org…). For fraud/web/financial cases, SPLIT the shared fingerprints (analytics/tracking",
  "  tags, SaaS widget IDs, registrant emails, registrars, nameservers, hosting/ASN), the money/assets",
  "  (wallets w/ chain, contracts, tokens, exchange accounts, mixers), and SPLIT a document-confirmed",
  "  natural person from an unconfirmed operator persona — each is a different pivot/confidence.",
  "- roles: the 4-8 investigation buckets every entity gets sorted into. ALWAYS include a 'noise' role.",
  "  Mark actor=true for a human/persona/account with a FUNCTION (those get a sub_role); actor=false for",
  "  things (indicators, infra, channels, sources, assets). weight 0-5 = how central to the case (prime",
  "  actors=5, indicators~4, infra~1, sources/noise=0). Weight drives the threat-score ranking.",
  "- sub_roles: the FUNCTION categories for the actor roles (who leads, builds, promotes, launders,",
  "  recruits). Invent the set that fits this domain.",
  "- noise_notes: one or two sentences on what to treat as noise here.",
  "",
  "Output strict JSON only. No prose.",
].join("\n");

const SCHEMA_CORPUS_BUDGET = 60000; // chars of sample finding text — matches understand.py CORPUS_CHAR_BUDGET (codex S2: no corpus divergence)
const SCHEMA_SAMPLES_PER_TYPE = 6;

// A compact role seed per detected type (the understand.py seed_roles_for analog): the discovery
// starts WARM with a domain hint instead of cold, but the model adapts it to the evidence (D6).
const SCHEMA_SEED_ROLES: Record<string, string> = {
  "crypto-fraud": "promoter, developer, wallet, smart_contract, exchange, mixer",
  "disinfo": "persona, amplifier, outlet, bot_network",
  "hacktivist": "operator, channel, defacer, recruiter, infra_provider",
  "financial-fraud": "mule, shell_company, launderer, recruiter",
  "intrusion-apt": "operator, c2, malware_family, infrastructure",
  "person-of-interest": "subject, associate, employer, residence",
};

/** Build the understand corpus from what kipi-web actually has: the analyst objectives (the scope
 *  anchor) + the entity histogram (crude type → count → samples) + the detected type seed. The store
 *  is already key-redacted (entityDbFor redacts every input). */
function buildSchemaPrompt(vault: Vault): string {
  const store = entityDbFor(vault, null);
  const byType = new Map<string, { count: number; samples: string[] }>();
  let signalText = "";
  for (const e of allEntities(store)) {
    const t = e.type || "unknown";
    const b = byType.get(t) ?? { count: 0, samples: [] };
    b.count++;
    if (b.samples.length < SCHEMA_SAMPLES_PER_TYPE) b.samples.push(e.label);
    byType.set(t, b);
    if (signalText.length < SCHEMA_CORPUS_BUDGET) signalText += `${e.label} `;
  }
  const objectives = objectivesUnder(vault, RUN_PREFIX).map((o) => redactProjectionText(vault, o));
  const detected = detectRunType(objectives.join(" "), allEntities(store).map((e) => ({ value: e.label, type: e.type })));
  const seedRoles = SCHEMA_SEED_ROLES[detected.type];
  const seedHint = isSpecificType(detected.type)
    ? `\n\nDETECTED INVESTIGATION TYPE: ${detected.type} (confidence ${detected.confidence}). ` +
      (seedRoles ? `Typical roles for this type: ${seedRoles}. ` : "") +
      "Use this as a STARTING POINT and adapt it to what this case actually shows — don't force it if the evidence differs."
    : "";

  const histLines = [...byType.entries()]
    .sort((a, b) => b[1].count - a[1].count)
    .map(([t, b]) => `  ${t}: ${b.count} entities — e.g. ${b.samples.join(", ")}`);
  const histogram = histLines.join("\n") || "  (no entities extracted yet)";
  const objectiveBlock = objectives.length
    ? `ANALYST OBJECTIVE(S) — the schema must be scoped to answer THESE:\n  ${objectives.join("\n  ")}\n\n`
    : "";

  return (
    objectiveBlock +
    `REGEX-EXTRACTED ENTITIES (crude type → count → samples):\n${histogram}\n\n` +
    'Propose the schema for THIS case. Return JSON with this exact shape:\n' +
    '{"domain":"<short label>","summary":"<1-2 lines>","entity_types":[{"name":"<str>","description":"<str>"}],' +
    '"roles":[{"name":"<str>","description":"<str>","actor":true,"weight":0}],"sub_roles":[{"name":"<str>","description":"<str>"}],' +
    '"noise_notes":"<str>"}\n\n' +
    "Rules: 4-8 roles; ALWAYS include a role named 'noise' with actor=false; at least one role actor=true; " +
    "model what the case is ACTUALLY about, don't copy a generic template." +
    seedHint
  );
}

/**
 * The auto-modeled per-case schema: a REAL LLM understand pass (PRD D6), key-redacted IN + OUT, then
 * checked by the validateCaseSchema validator (a noise role + an actor role). Auto-approved inline — no
 * /schema tab, no analyst bounce (per the per-case-schema-gate decision). Throws SessionError if the
 * vault is locked / no key.
 */
export async function autoModelSchema(vault: Vault, opts?: AiPassOpts): Promise<CaseSchema> {
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to model the case schema.");
  const prompt = redactProjectionText(vault, buildSchemaPrompt(vault));
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { text } = await client.complete({
    system: SCHEMA_SYSTEM,
    messages: [{ role: "user", content: prompt }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? 1600,
    signal: opts?.signal,
  });
  const parsed = extractSchemaJson(redactProjectionText(vault, text)); // redact OUT before parse
  return validateCaseSchema(parsed) ?? validateCaseSchema({})!; // never null: an empty schema is still valid (noise+actor guaranteed)
}

/** The LAST balanced {...} block of the model output (mirrors consolidate.extractJsonObject). */
function extractSchemaJson(text: string): unknown {
  const s = (text ?? "").trim();
  const end = s.lastIndexOf("}");
  if (end < 0) return null;
  let depth = 0;
  for (let i = end; i >= 0; i--) {
    const ch = s[i];
    if (ch === "}") depth++;
    else if (ch === "{") {
      depth--;
      if (depth === 0) {
        try {
          return JSON.parse(s.slice(i, end + 1));
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

// ---- the Process orchestration runner (PRD: sequential, onStep callbacks, AbortSignal) ----

export type ProcessStepStatus = "pending" | "running" | "ok" | "skipped" | "error";

export interface ProcessStepDef {
  key: string;
  label: string;
}

/** The INC-1 step manifest (auto-schema → consolidate → typing). INC-2/3/4 append correlate /
 *  cross_domain / analyze / score / metrics / synthesize / dossiers. The UI renders this manifest. */
export const PROCESS_STEPS: ProcessStepDef[] = [
  { key: "schema", label: "Model the case schema" },
  { key: "consolidate", label: "Consolidate + role entities" },
  { key: "typing", label: "Refine entity types" },
  { key: "correlate", label: "Correlate across reports" },
  { key: "cross_domain", label: "Find cross-type links" },
  { key: "analyze", label: "Cluster + relate entities" },
  { key: "score", label: "Score threat" },
  { key: "graph_metrics", label: "Compute graph metrics" },
  { key: "synthesize", label: "Synthesize the case brief" },
  { key: "dossiers", label: "Profile the key actors" },
];

/** Per-step scripted-LLM wires (smoke only; production leaves all undefined → real fetch). */
export interface ProcessWire {
  schemaFetch?: FetchLike;
  consolidateFetch?: FetchLike;
  typeFetch?: FetchLike;
  analyzeFetch?: FetchLike;
  synthesizeFetch?: FetchLike; // INC-4b: scripted case-brief wire (smoke); production = real fetch
  dossierFetch?: FetchLike; // INC-4b: scripted dossier wire (smoke); production = real fetch
}

export interface RunProcessOpts {
  onStep?: (key: string, status: ProcessStepStatus) => void;
  onLog?: (line: string) => void;
  signal?: AbortSignal;
  wire?: ProcessWire;
}

/**
 * Run the Process pipeline (INC-1: schema → consolidate → typing) sequentially over the current case,
 * accumulating its output into the analysis record. AbortSignal-cancellable: signal.aborted is checked
 * after every await + before every putAnalysis, so a superseding Process click (the app-level run
 * fence, PRD D8) stops the prior run before it writes stale output. consolidate/typing read entityDbFor
 * (now THROUGH applyAnalysis), so each step sees the prior step's overlay. Requires a key.
 */
export async function runProcess(vault: Vault, opts: RunProcessOpts = {}): Promise<void> {
  const { onStep, onLog, signal, wire } = opts;
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to process the case.");
  const log = (s: string): void => onLog?.(redactProjectionText(vault, s)); // redact log lines (defense in depth)
  const ensureLive = (): void => {
    if (signal?.aborted) throw new SessionError("Processing was cancelled.");
  };

  let rec = analysisFor(vault) ?? emptyAnalysis(ANALYSIS_SLUG);

  // (1) schema — the real understand pass, auto-approved inline into the record.
  onStep?.("schema", "running");
  ensureLive();
  const schema = await autoModelSchema(vault, { fetchImpl: wire?.schemaFetch, signal });
  ensureLive();
  rec = { ...rec, schema };
  await putAnalysis(vault, rec, signal);
  log(`schema: ${schema.domain} — ${schema.roles.length} roles, ${schema.entityTypes.length} entity types`);
  onStep?.("schema", "ok");

  // (2) consolidate — merge/role suggestions, auto-applied as AI role overlays (analyst can override).
  onStep?.("consolidate", "running");
  ensureLive();
  const merges = await consolidateEntities(vault, { fetchImpl: wire?.consolidateFetch, current: null, signal });
  ensureLive();
  const roles = { ...rec.roles };
  const subRoles = { ...(rec.subRoles ?? {}) };
  let roleCount = 0;
  for (const s of merges) {
    for (const m of s.members) {
      const k = canonKey(m.ref.type, m.ref.value);
      // ROLE DECISION (founder 2026-06-24): an infra-typed entity (domain/IP/URL/…) is NEVER `operator` from
      // the AI pass — a domain is infrastructure, not a human operator. roleForType coerces operator→infra
      // by surface type (reverses the squares→circles over-correction that made a FIFA case all-operator).
      const role = roleForType(s.role, m.ref.type);
      roles[k] = role;
      if (role === "operator" && s.subRole) subRoles[k] = s.subRole; // A1: the operator's network function — only on a node that stays operator
      roleCount++;
    }
  }
  rec = { ...rec, roles, subRoles };
  await putAnalysis(vault, rec, signal);
  log(`consolidate: ${merges.length} group(s), ${roleCount} role(s) assigned`);
  onStep?.("consolidate", merges.length ? "ok" : "skipped");

  // (3) typing — surface-type refinements, auto-applied as AI type overlays.
  onStep?.("typing", "running");
  ensureLive();
  const types = await typeEntities(vault, { fetchImpl: wire?.typeFetch, current: null, signal });
  ensureLive();
  const typeMap = { ...rec.types };
  // PRD-B typing-case-type: persist the per-case ANALYTIC type alongside the surface-type overlay, so the
  // re-bucketing typing.py performs is APPLIED (overlaid onto EntityRecord.caseType), not just emitted.
  const caseTypeMap: Record<string, string> = { ...(rec.caseTypes ?? {}) };
  let caseTypeCount = 0;
  for (const t of types) {
    const k = canonKey(t.ref.type, t.ref.value);
    typeMap[k] = t.toType;
    if (t.caseType) {
      caseTypeMap[k] = t.caseType;
      caseTypeCount++;
    }
  }
  rec = { ...rec, types: typeMap, caseTypes: caseTypeMap };
  await putAnalysis(vault, rec, signal);
  log(`typing: ${types.length} type change(s), ${caseTypeCount} case_type(s)`);
  onStep?.("typing", types.length ? "ok" : "skipped");

  // (4) correlate — cross-report overlap (crossRunEntities) + alias links (auto_link_aliases port).
  // Both are PURE LIVE VIEWS in the client (ca-correlate D1/D5): no persistence, always current — the
  // step surfaces their counts so the analyst sees the correlation pass ran. computeAliasLinks is
  // person-only + capped at 600 (db.ts ALIAS_MAX_PERSONS) so this stays a bounded synchronous pass.
  onStep?.("correlate", "running");
  ensureLive();
  const store = entityDbFor(vault, null); // already key-redacted before the pure db sees it
  const overlap = crossRunEntities(store).length;
  const aliasMap = computeAliasLinks(store);
  const aliasLinks = Object.values(aliasMap).reduce((n, list) => n + list.length, 0);
  log(`correlate: ${overlap} cross-report entit${overlap === 1 ? "y" : "ies"}, ${aliasLinks} alias link(s)`);
  onStep?.("correlate", "ok");

  // (5) cross_domain — entities spanning >= 2 specific investigation types (crossDomainEntities).
  // A live projection (the server writes fingerprint links; the client computes the same links on
  // read — the established INC-1 pure-projection divergence). Log-only here; /cross-domain renders it.
  onStep?.("cross_domain", "running");
  ensureLive();
  const crossDomain = crossDomainEntities(vault).length;
  log(`cross_domain: ${crossDomain} cross-type link(s)`);
  onStep?.("cross_domain", "ok");

  // (6) analyze — the LLM pass: the REAL analytic clusters + typed relationships (ca-analyze INC-3).
  // The clusters color the graph (cap-cluster-colors); the relationships are persisted for a later inc.
  // A salvage parse keeps whatever survived a truncated response; an empty result leaves the slate
  // fallback (never a crash). putAnalysis writes the whole record atomically (no half-written record).
  onStep?.("analyze", "running");
  ensureLive();
  const analyzed = await analyzeCase(vault, { fetchImpl: wire?.analyzeFetch, current: null, signal });
  ensureLive();
  // INC-4a: persist BOTH clusters AND the vocab-gated typed relationships (analyze.ts ran normalizeRel
  // before they reached here). The relationships render as entity↔entity typed_rel edges (finalizeModel)
  // and feed the score/metrics adjacency below. Atomic putAnalysis (never a half-written record).
  rec = { ...rec, clusters: analyzed.clusters, relationships: analyzed.relationships };
  await putAnalysis(vault, rec, signal);
  log(`analyze: ${analyzed.clusters.length} cluster(s), ${analyzed.relationships.length} typed relationship(s)`);
  onStep?.("analyze", analyzed.clusters.length || analyzed.relationships.length ? "ok" : "skipped");

  // (7) score — compute_threat_scores over the persisted typed_relationships adjacency. Seeds = promoted
  // findings @ weight 1.0 (codex P2). Role weights = generic defaults overlaid with the schema (max wins).
  onStep?.("score", "running");
  ensureLive();
  const scoreStore = entityDbFor(vault, null);
  const scoreEntities = allEntities(scoreStore).map((e) => ({
    key: canonKey(e.ref.type, e.ref.value),
    role: e.role,
    reportCount: e.runs.length, // distinct reports/runs that surfaced it (Python report_count analog)
  }));
  const adjacency = rec.relationships.map((r) => ({ src: r.srcKey, dst: r.dstKey }));
  const seedWeights = new Map<string, number>();
  for (const e of allEntities(scoreStore)) {
    if (e.promoted) seedWeights.set(canonKey(e.ref.type, e.ref.value), 1.0); // promoted = seed @ 1.0
  }
  const schemaRoleWeights: Record<string, number> = {};
  for (const role of rec.schema?.roles ?? []) schemaRoleWeights[role.name] = role.weight;
  const scores = computeThreatScores(scoreEntities, adjacency, seedWeights, mergeRoleWeights(schemaRoleWeights));
  const entityScores: Record<string, EntityScoreRecord> = {};
  for (const [k, s] of scores) entityScores[k] = s;
  rec = { ...rec, entityScores };
  await putAnalysis(vault, rec, signal);
  log(`score: ${scores.size} entity score(s) over ${adjacency.length} typed edge(s)`);
  onStep?.("score", scores.size ? "ok" : "skipped");

  // (8) graph_metrics — degree_centrality + betweenness + eigenvector + Louvain community over the same
  // typed_relationships adjacency (deterministic, no LLM; bundled graphology). Degenerate → empty.
  onStep?.("graph_metrics", "running");
  ensureLive();
  const metricNodes = scoreEntities.map((e) => e.key);
  const metricsMap = computeGraphMetrics(metricNodes, adjacency);
  // PRD-B graph-path-confidence (resolve sp-904eae51): grade each node's attribution chain back to a case
  // SEED over the confidence-weighted typed-rel adjacency (widest-bottleneck), so the graph distinguishes a
  // node on a strong chain from one hanging off a weak bridge. Seeds = the promoted entities (seedWeights).
  const pathConf = computePathConfidence(
    metricNodes,
    rec.relationships.map((r) => ({ src: r.srcKey, dst: r.dstKey, confidence: r.confidence })),
    [...seedWeights.keys()],
  );
  // Merge over the UNION of centrality keys + path_confidence keys (codex issue-7 C1): a degenerate graph
  // (0 typed edges → computeGraphMetrics returns empty) can still anchor seeds at pathConfidence 1.0; iterating
  // metricsMap alone would drop those. A path-only (isolated) node gets zero centrality — CORRECT for an
  // isolated node (degree 0, no betweenness), not a 0-fake; its pathConfidence carries the real signal.
  const nodeMetrics: Record<string, NodeMetricRecord> = {};
  const ZERO_CENTRALITY = { degreeCentrality: 0, betweenness: 0, eigenvector: 0, community: 0 };
  for (const k of new Set([...metricsMap.keys(), ...pathConf.keys()])) {
    const m = metricsMap.get(k) ?? ZERO_CENTRALITY;
    const pc = pathConf.get(k);
    nodeMetrics[k] = pc !== undefined ? { ...m, pathConfidence: pc } : m;
  }
  rec = { ...rec, nodeMetrics };
  await putAnalysis(vault, rec, signal);
  const scored = [...metricsMap.keys()].filter((k) => pathConf.get(k) !== undefined).length;
  log(`graph_metrics: ${metricsMap.size} node metric(s) (centrality + community), ${scored} path_confidence`);
  onStep?.("graph_metrics", metricsMap.size ? "ok" : "skipped");

  // (9) synthesize — the cross-report CASE brief (synthesize.py). Persists brief:case. Offline-seamed;
  // a failure (no key surfaced earlier; a model error) degrades to "skipped", never a half-Process.
  onStep?.("synthesize", "running");
  ensureLive();
  try {
    await synthesizeCaseBrief(vault, { fetchImpl: wire?.synthesizeFetch, signal });
    log(`synthesize: case brief generated`);
    onStep?.("synthesize", "ok");
  } catch {
    log(`synthesize: skipped`);
    onStep?.("synthesize", "skipped");
  }
  ensureLive();

  // (10) dossiers — per-promoted-entity actor profiles (profile.py), bounded + fail-soft per entity.
  onStep?.("dossiers", "running");
  ensureLive();
  let dossierCount = 0;
  try {
    dossierCount = await persistCaseDossiers(vault, { fetchImpl: wire?.dossierFetch, signal });
  } catch {
    /* fail-soft — the batch never blocks the Process */
  }
  log(`dossiers: ${dossierCount} dossier(s) generated`);
  onStep?.("dossiers", dossierCount ? "ok" : "skipped");
  ensureLive(); // codex S1: a Process aborted during the dossier batch must not report done
}

/**
 * Build the client entity DB for the current vault: a READ-ONLY projection over the
 * `run:` records (+ an optional current GraphModel for in-session expansions). It
 * issues NO vault write — the single-writer `createWritable` chokepoint stays solely
 * in src/vault/store.ts (codex D-singlewriter). Key hygiene mirrors graphModelForRun
 * but is UNCONDITIONAL on EVERY input (codex D2): the exact live key is redacted out
 * of each run record AND the passed-in model BEFORE the pure db sees them, so a caller
 * who passes an unredacted model can never leak the key into the store / __kipi / a
 * card / the DOM. Tainted/secret objectives are dropped via the objectivesUnder
 * contract (shared with listRuns/listBriefs).
 */
/** PRD-B (RCA item 3): map the agent's live-emitted relationships to typed graph LINKS. The endpoint set
 *  is the ADMITTED (gated) entities of this run — BOTH endpoints of a relationship must resolve there, else
 *  it is DROPPED (codex issue-6 C1: a relationship to an un-admitted value would otherwise surface a forged
 *  endpoint as a phantom connection/dossier label on a real entity). Endpoint types come from the admitted
 *  entity. promoted = a high-confidence link (drives the edge kind). Pure; inputs already redacted. */
export function agentRelationshipsToLinks(rels: AgentRelationship[], admitted: IngestEntity[]): IngestLink[] {
  if (!Array.isArray(rels) || rels.length === 0) return [];
  const typeOf = new Map<string, string>();
  for (const e of Array.isArray(admitted) ? admitted : []) {
    if (e && typeof e.value === "string" && e.value.trim()) typeOf.set(e.value.trim().toLowerCase(), e.type ?? "");
  }
  const links: IngestLink[] = [];
  for (const r of rels) {
    const from = (r?.src ?? "").trim();
    const to = (r?.dst ?? "").trim();
    if (!from || !to || from.toLowerCase() === to.toLowerCase()) continue;
    const fromType = typeOf.get(from.toLowerCase());
    const toType = typeOf.get(to.toLowerCase());
    if (fromType === undefined || toType === undefined) continue; // BOTH endpoints must be admitted (no phantom node)
    links.push({ fromValue: from, fromType: fromType || undefined, toValue: to, toType: toType || undefined, promoted: r.confidence === "high" });
  }
  return links;
}

export function entityDbFor(vault: Vault, current?: GraphModel | null): EntityStore {
  const runs: IngestRun[] = [];

  for (const objective of objectivesUnder(vault, RUN_PREFIX)) {
    let rec: Partial<RunRecord> = {};
    try {
      const v = vault.get(`${RUN_PREFIX}${objective}`);
      if (v && typeof v === "object") rec = v as Partial<RunRecord>;
    } catch {
      /* unreadable record: skip */
    }
    const safeObjective = redactProjectionText(vault, objective);
    const promoted = Array.isArray(rec.promoted) ? rec.promoted : [];
    const leads = Array.isArray(rec.leads) ? rec.leads : [];
    const safePromoted = redactProjectionDeep(vault, promoted);
    const safeLeads = redactProjectionDeep(vault, leads);
    const ingestRun = runRecordToIngest(
      safeObjective,
      safePromoted,
      safeLeads,
      // prd-parity-graph-faithful: the proximity pairs (text ingest) drive a SPARSE co_occurs;
      // undefined on agent/legacy runs → all-pairs fallback. Redacted with the rest of the record.
      Array.isArray(rec.coOccur) ? (redactProjectionDeep(vault, rec.coOccur) as Array<[string, string]>) : undefined,
    );
    // PRD-B (RCA item 3): inject the agent's LIVE-emitted relationships as TYPED graph links, so the
    // network is drawn from what the agent established (a domain→ip resolve) rather than all-pairs
    // co-occurrence. Endpoint types resolve from this run's findings; values redacted with the record.
    const safeRels = redactProjectionDeep(vault, Array.isArray(rec.agentRelationships) ? rec.agentRelationships : []);
    ingestRun.links = agentRelationshipsToLinks(safeRels, ingestRun.entities); // both endpoints must be admitted (codex C1)
    runs.push(ingestRun);
  }

  // Fold the current graph model — redact it ourselves; never trust it pre-redacted (D2).
  if (current) {
    runs.push(graphModelToIngest(redactProjectionDeep(vault, current)));
  }

  // ca-session D10 + pf-process: apply the Process AI roles/types (applyAnalysis) FIRST, then analyst
  // corrections (applyCorrections) on top, at THIS chokepoint — so every projection that reads through
  // entityDbFor (clusters, cross-domain, AI dossier, semantic relations, node drawer, ⌘K search, /entities)
  // inherits BOTH overlays. Order is the proof of the top-authority invariant (PRD D1): corrections run
  // LAST, so an analyst override always wins over the AI role/type. Neither overlay rekeys (the map key is
  // the stable identity), so the store's identity set is unchanged.
  // analyst node-removal (founder 2026-06-25): drop excluded entities + their connections at THIS chokepoint
  // too, so /entities, clusters, dossiers, and the graph network edges all agree the node is gone (reversible).
  return applyExclusionsToStore(applyCorrections(applyAnalysis(buildEntityDb(runs), analysisFor(vault)), correctionMap(vault)), excludedKeys(vault));
}

// ---- ig-ingest: file ingestion — extract → gated findings → a run: record (the existing writer) ----

const HARD_FACT_TYPES_INGEST = new Set(["ip", "ip_address", "email", "wallet", "crypto_wallet", "date"]);

export interface IngestResult {
  count: number;
  objective: string;
}

const RUN_RECORD_STOP = "ingested";
export const FILE_SOURCE_KIND = "file_ingest";

/**
 * Ingest a document's text: extract gated entities and store them as a sanitized run: record through
 * the EXISTING vault.put chokepoint (createWritable stays solely in src/vault/store.ts — NO new write
 * path). Key hygiene (codex D3): the live key is redacted from the name + the text BEFORE extraction
 * and from the whole record BEFORE the write, so a document that contains the key cannot leak it.
 * Ingested entities are the document's evidence: source_count 1, infra 0, claim_unverified for hard
 * facts — graded by promotionGate (mostly leads, no overclaim — D11). A collision-safe unique key
 * (D5) + a non-forgeable sourceKind (D4) distinguish a file ingest from an agent run.
 */
export async function ingestText(vault: Vault, name: string, text: string, structured: ExtractedEntity[] = []): Promise<IngestResult> {
  const safeName = redactProjectionText(vault, name).trim() || "untitled";
  const safeText = redactProjectionText(vault, text); // redact every secret form OUT of the doc text first

  // ig-record: structured CSV/XLSX column-typed entities (e.g. a 'Full Name' / 'username' / 'phone'
  // column the flat regex has no signature for). recordEntities ALREADY applied the admission contract
  // with the correct per-column prevalidation, so DON'T re-gate here (a re-gate without prevalidation
  // would drop a header-typed bare phone — codex). The only added hygiene: redact each value like the
  // text; a value the redactor CHANGES held a secret (an API key pasted in a cell) → drop it. Then
  // union (deduped) with the flat path — strictly additive, so a free-text column's IOC is never lost.
  const structuredSafe = structured
    .map((e) => ({ value: redactProjectionText(vault, e.value), type: e.type, raw: e.value }))
    .filter((e) => e.value === e.raw) // unchanged by redaction → no secret; recordEntities already gated it
    .map((e) => ({ value: e.value, type: e.type }));
  const extracted = mergeEntities(structuredSafe, extractEntities(safeText));
  const promoted: Finding[] = [];
  const leads: { finding: Finding; verdict: GateVerdict }[] = [];
  for (const e of extracted) {
    const finding: Finding = {
      entity: e.value,
      entity_type: e.type,
      confidence: "low",
      source_count: 1,
      infra_source_count: 0,
    };
    if (HARD_FACT_TYPES_INGEST.has(e.type.toLowerCase())) finding.claim_unverified = true; // no tool corroboration
    const verdict = promotionGate(finding);
    if (verdict.promote) promoted.push(finding);
    else leads.push({ finding, verdict });
  }

  // prd-parity-graph-faithful: proximity co-occurrence over the SAME safeText the entities came from
  // (200-char window, extractor.py:infer_relationships). Sparse, local — replaces the old all-pairs
  // co_occurs (the hairball). Offsets are transient here; only the value pairs are persisted.
  const coOccur = inferRelationships(safeText);

  const shortId = (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}`).slice(0, 8);
  const objective = `file: ${safeName} #${shortId}`; // collision-safe + readable; key == "run:" + objective
  const record = {
    objective,
    steps: [],
    promoted,
    leads,
    usage: { input: 0, output: 0 },
    stopReason: RUN_RECORD_STOP,
    coOccur, // proximity co-occurrence pairs (entity values within 200 chars)
    sourceKind: FILE_SOURCE_KIND, // D4: a non-forgeable discriminator the Inbox filters on
    // sf-briefs: report metadata for the grouped-relatedness engine — set BEFORE the deep redact below
    // so any secret in them is scrubbed; title uses safeName (already key-redacted), never raw `name`.
    title: safeName,
    ingestedAt: new Date().toISOString(),
    sourceType: FILE_SOURCE_KIND,
  };
  const safeRecord = redactProjectionDeep(vault, record); // defense-in-depth: never write any secret
  try {
    await vault.put(`run:${objective}`, safeRecord); // the ONE write path (single-writer preserved)
  } catch {
    throw new SessionError("Unlock your vault to ingest a document.");
  }
  return { count: promoted.length + leads.length, objective };
}

export interface IngestedDoc {
  objective: string;
  count: number;
  // sf-reports: the report-metadata projection (already persisted by ingestText since sf-briefs; this
  // read just stops dropping them). title = the key-redacted safeName; ingestedAt = the ISO write stamp.
  title?: string;
  ingestedAt?: string;
  sourceType?: string;
}

/** The ingested documents (run records with sourceKind === 'file_ingest') — the Inbox + the /reports
 *  table. Filters on the non-forgeable sourceKind field (D4), not the objective text; key-redacted via
 *  objectivesUnder. Newest-first by ingestedAt (sf-reports — was objective.localeCompare; the RunRecord
 *  now carries a real ingest timestamp). */
export function listIngestedDocs(vault: Vault): IngestedDoc[] {
  const out: IngestedDoc[] = [];
  for (const objective of objectivesUnder(vault, RUN_PREFIX)) {
    let rec: Partial<RunRecord> & { sourceKind?: string } = {};
    try {
      const v = vault.get(`${RUN_PREFIX}${objective}`);
      if (v && typeof v === "object") rec = v as typeof rec;
    } catch {
      continue;
    }
    if (rec.sourceKind !== FILE_SOURCE_KIND) continue;
    const count = (Array.isArray(rec.promoted) ? rec.promoted.length : 0) + (Array.isArray(rec.leads) ? rec.leads.length : 0);
    out.push({
      objective,
      count,
      // codex sf-sources review: belt title/sourceType on READ (not only the ingestText write) — a forged/
      // legacy run: record could carry the live key here; this is the single chokepoint for the Docs view,
      // the Sources gallery, AND the reports table (reportModelFor already belts these same fields).
      title: typeof rec.title === "string" ? redactProjectionText(vault, rec.title) : undefined,
      ingestedAt: typeof rec.ingestedAt === "string" ? rec.ingestedAt : undefined,
      sourceType: typeof rec.sourceType === "string" ? redactProjectionText(vault, rec.sourceType) : undefined,
    });
  }
  // newest-first by ingestedAt; docs with no stamp (legacy) sort last, tie-broken by objective.
  return out.sort((a, b) => (b.ingestedAt ?? "").localeCompare(a.ingestedAt ?? "") || a.objective.localeCompare(b.objective));
}

// ---- sf-sources: the Sources gallery (a Docs/Sources toggle on /inbox) ----
//
// The original /sources is a per-PAGE-ASSET gallery (image thumbnail + OCR-text snippet + the entities
// mentioned on that page). The browser keeps NO assets: the page image + the raw OCR blob are DISCARDED at
// ingest write (zero-retention — the sf-report-detail "read the pages" ceiling). The RETAINED projection is
// the DOCUMENT (run:file: record: title / ingestedAt / sourceType) + the gate-extracted ENTITIES. sourcesFor
// joins listIngestedDocs with runEntities per doc; the thumbnail + OCR snippet + OCR-blob search are the
// SIGNED zero-retention divergence (there is no retained image/blob to show or search).
export interface SourceDocEntity {
  label: string; // redacted entity value
  type: string;
  role: string; // the display role (for the chip pill)
  ref: EntityRef; // for the chip click → /entities
}

export interface SourceDoc {
  objective: string;
  title: string; // redacted doc title (or the objective)
  ingestedAt: string; // ISO write stamp ("" for legacy)
  ingestDate: string; // YYYY-MM-DD (the original's substr(ingested_at,1,10) facet)
  sourceType: string;
  entityCount: number;
  entities: SourceDocEntity[]; // ALL the doc's entities (the renderer caps the chip DISPLAY to 12; the
  //                              entity FILTER needs the full set so an entity beyond the 12th is filterable)
}

export function sourcesFor(vault: Vault): SourceDoc[] {
  // codex impl-review: the gallery renders eagerly. entityDbFor folds EVERY run (incl. a forged file doc with
  // a malformed finding, e.g. a numeric entity_type that crashes the admission gate's .trim()). Degrade to an
  // empty store (chips lose their role overlay) rather than crash /inbox. (Root cause = coerce entityType in
  // entity/db.ts isAdmissible — a pre-existing latent bug that also affects /entities; out of this row's
  // allowed_files, noted for a follow-up; this guard is the in-scope robustness belt.)
  let store: Record<string, EntityRecord> = {};
  try {
    store = entityDbFor(vault).entities; // already key-redacted — for the chip's display role/ref
  } catch {
    store = {};
  }
  return listIngestedDocs(vault).map((doc) => {
    // codex sf-sources review: keep ALL the doc's entities (the original filters over every mention) — the
    // CHIP DISPLAY is capped to 12 in the renderer, but the entity FILTER must see the full set so an entity
    // beyond the first 12 is still filterable. WRAP runEntities per doc (codex impl-review): the Sources
    // gallery renders EAGERLY (unlike the lazy Docs-expand), so a malformed file-ingest record (e.g. a
    // numeric entity_type) must degrade to no-chips for that doc, NOT crash the whole /inbox page.
    let raw: RunEntity[] = [];
    try {
      raw = runEntities(vault, doc.objective);
    } catch {
      raw = [];
    }
    const entities: SourceDocEntity[] = raw.map((e) => {
      const rec = store[canonKey(e.type, e.value)];
      return { label: e.value, type: e.type, role: rec?.role ?? "", ref: rec?.ref ?? { type: e.type, value: e.value } };
    });
    return {
      objective: doc.objective,
      title: doc.title ?? doc.objective, // listIngestedDocs already redacts the title
      ingestedAt: doc.ingestedAt ?? "",
      ingestDate: (doc.ingestedAt ?? "").slice(0, 10),
      sourceType: doc.sourceType ?? "",
      entityCount: doc.count,
      entities,
    };
  });
}

// sf-report-detail: the per-report detail projection (the report-detail.html analog) — the report's
// gate-faithful entities (joined to the entity DB for role/sub_role + the analysis record for the threat
// score, noise-filtered, score-sorted, capped) + the analyst overrides that touch them. READ-ONLY +
// already-redacted (runEntities + entityDbFor redact; corrections store the redacted label). NO raw-text
// view — the source text is discarded at ingest (zero-retention), so the extracted entities ARE the
// retained projection of the pages (signed divergence).
export interface ReportDetailEntity {
  value: string;
  type: string;
  role: string;
  // NOTE: the original report-detail.html renders a sub_role pill, but the client EntityRecord carries
  // no per-entity sub_role (the schema's sub_roles are not assigned per-entity) — micro-divergence, not
  // tracked client-side (impl-review A). Dropped rather than shipped as a dead/empty field.
  grade?: string;
  threatScore?: number;
  promoted: boolean;
}
export interface ReportDetail {
  entities: ReportDetailEntity[];
  overrides: CorrectionRow[];
}
const MAX_REPORT_DETAIL_ENTITIES = 200; // report-detail.html caps the entities card

export function reportDetailFor(vault: Vault, objective: string): ReportDetail {
  const store = entityDbFor(vault, null);
  const analysis = analysisFor(vault);
  const scores = analysis?.entityScores ?? {};
  const inReport = new Set<string>(); // canonKeys of this report's entities
  const entities: ReportDetailEntity[] = [];
  for (const e of runEntities(vault, objective)) {
    const key = canonKey(e.type, e.value);
    inReport.add(key);
    const rec = store.entities[key];
    const role = rec?.role ?? "";
    if (role === "noise") continue; // noise-filtered (report-detail.html)
    entities.push({
      value: e.value,
      type: e.type,
      role,
      grade: e.grade ?? rec?.grade,
      threatScore: typeof scores[key]?.threatScore === "number" ? scores[key].threatScore : undefined,
      promoted: e.promoted,
    });
  }
  // score-sorted desc (then promoted, then label) + capped, mirroring the original.
  entities.sort((a, b) => (b.threatScore ?? -1) - (a.threatScore ?? -1) || Number(b.promoted) - Number(a.promoted) || a.value.localeCompare(b.value));
  const overrides = listCorrections(vault).filter((c) => c.active && inReport.has(c.canonicalKey));
  return { entities: entities.slice(0, MAX_REPORT_DETAIL_ENTITIES), overrides };
}

// ---- sf-entity-detail: the per-entity DETAIL fold projections (entity.html analog) ----
//
// The entity-detail surfaces (the /entities row-expand + the graph node-card drawer) need the SAME depth
// as the original /entity/{id} page across SIX sections. These accessors are READ-ONLY projections over
// the already-redacted analysisFor + entityDbFor + EntityRecord.runs — EXCEPT the editable dossier
// override, which is the ONE new persisted key, mirroring setReportNotes EXACTLY (single-writer,
// redacted, capped). No raw snippet TEXT (zero-retention — signed divergence).

/** §1+2: the stored threat score + degree + report count for one entity (canonKey-keyed), or null when
 *  the Process hasn't scored the case / the entity didn't score / the vault is locked. */
export function entityScoreFor(vault: Vault, canonicalKey: string): EntityScoreRecord | null {
  const rec = analysisFor(vault);
  const s = rec?.entityScores?.[canonicalKey];
  if (!s || typeof s.threatScore !== "number") return null;
  return s;
}

/** §1+2: the INC-4a centrality metrics for one entity (canonKey-keyed), or null when graph_metrics
 *  hasn't run / the entity has no metrics / the vault is locked. */
export function entityMetricsFor(vault: Vault, canonicalKey: string): NodeMetricRecord | null {
  const rec = analysisFor(vault);
  const m = rec?.nodeMetrics?.[canonicalKey];
  if (!m || typeof m.degreeCentrality !== "number") return null;
  return m;
}

export interface EntityScoreBreakdown {
  role: string;
  roleWeight: number;
  rolePts: number; // role_weight * 10
  reportCount: number;
  reportPts: number; // report_count * 5
  degree: number;
  degreePts: number; // degree * 1
  priorPts: number; // seed_weight * 30 (30 when promoted, else 0)
  promoted: boolean;
  propPts: number; // the EXACT residual: threatScore - base - prior (so the shown total == stored)
  total: number; // == the stored threatScore
  metrics: NodeMetricRecord | null; // §1+2 centrality (degree/betweenness/eigenvector/community)
}

/**
 * §1+2: reconstruct the score breakdown so the displayed total ALWAYS equals the stored threatScore.
 * base = roleWeight*10 + reportCount*5 + degree*1 (scoring.ts); prior = 30 when promoted (seed @ 1.0,
 * compute_threat_scores seeds promoted entities at weight 1.0 → prior = 1.0*30); prop is shown as the
 * EXACT residual (threatScore − base − prior) — the per-hop seed adjacency is NOT persisted (signed
 * divergence), so showing the residual guarantees the displayed total matches the stored score with no
 * drift. roleWeight is recomputed via mergeRoleWeights over the case schema (the SAME map the score step
 * built). Returns null when the entity has no stored score (un-Processed / didn't score). Pure-ish:
 * reads analysisFor + the entity's role/promoted from the store; NO vault write.
 */
export function entityScoreBreakdownFor(
  vault: Vault,
  ref: EntityRef,
  role: string,
  promoted: boolean,
): EntityScoreBreakdown | null {
  const key = canonKey(ref.type, ref.value);
  const score = entityScoreFor(vault, key);
  if (!score) return null;
  const rec = analysisFor(vault);
  const schemaRoleWeights: Record<string, number> = {};
  for (const r of rec?.schema?.roles ?? []) schemaRoleWeights[r.name] = r.weight;
  const roleWeight = mergeRoleWeights(schemaRoleWeights)[role] ?? 0; // the SAME merged map the score step used
  const rolePts = roleWeight * 10;
  const reportPts = score.reportCount * 5;
  const degreePts = score.degree * 1;
  const priorPts = promoted ? 30 : 0; // seed @ 1.0 → 1.0 * 30 (compute_threat_scores promoted-seed default)
  const base = rolePts + reportPts + degreePts;
  const propPts = score.threatScore - base - priorPts; // EXACT residual — total always == the stored score
  return {
    role,
    roleWeight,
    rolePts,
    reportCount: score.reportCount,
    reportPts,
    degree: score.degree,
    degreePts,
    priorPts,
    promoted,
    propPts,
    total: score.threatScore,
    metrics: entityMetricsFor(vault, key),
  };
}

export interface EntityTypedRel {
  relType: string;
  confidence: string;
  evidence: string;
  otherRef: EntityRef; // the other endpoint (for the click → /entities nav)
  otherLabel: string;
  direction: "out" | "in"; // out: this → other; in: other → this
}

/**
 * §7: the persisted typed relationships touching one entity (analysisFor.relationships, the INC-4a
 * vocab-gated edges), each resolved to the other endpoint's display label via the entity DB. Only
 * relationships whose OTHER endpoint exists in the current store are returned (a forged/imported
 * relationship to a non-existent entity is dropped — the same discipline clustersFor uses). READ-ONLY;
 * the relationships were redacted on write + the labels come from the redacted store.
 */
export function typedRelationshipsFor(vault: Vault, canonicalKey: string): EntityTypedRel[] {
  const rec = analysisFor(vault);
  if (!rec?.relationships?.length) return [];
  const store = entityDbFor(vault, null);
  const out: EntityTypedRel[] = [];
  for (const r of rec.relationships) {
    let otherKey: string | null = null;
    let direction: "out" | "in" | null = null;
    if (r.srcKey === canonicalKey) {
      otherKey = r.dstKey;
      direction = "out";
    } else if (r.dstKey === canonicalKey) {
      otherKey = r.srcKey;
      direction = "in";
    }
    if (!otherKey || !direction) continue;
    const ent = store.entities[otherKey];
    if (!ent) continue; // resolve by the live store, never decode the raw key (cl-session D8 discipline)
    out.push({
      relType: r.relType,
      confidence: r.confidence,
      // codex impl-review: belt the ONE free-text field on read (redact OUT), not only on write — the
      // codebase's redact-IN+OUT discipline. relType/confidence are vocab-gated enums; otherRef/otherLabel
      // come from the already-redacted store; evidence is free text, so a legacy/forged record can't leak.
      evidence: redactProjectionText(vault, r.evidence),
      otherRef: ent.ref,
      otherLabel: ent.label,
      direction,
    });
  }
  return out;
}

/** §4: the ACTIVE analyst corrections that touch ONE entity (the exact reportDetailFor filter, by the
 *  entity's canonKey). For the per-entity corrections-audit slice + its revert affordance. */
export function entityCorrectionsFor(vault: Vault, canonicalKey: string): CorrectionRow[] {
  return listCorrections(vault).filter((c) => c.active && c.canonicalKey === canonicalKey);
}

export interface EntityAppearance {
  objective: string; // the (already-redacted) run objective the entity appeared in
  promoted: boolean;
  grade?: string;
  sourceCount: number;
  infraSourceCount: number;
  surfacedConfidence?: string; // the surfaced_in connection confidence to that run (if any)
}

/**
 * §8: the "Appears in N report(s)" projection for one entity — its EntityRecord.runs joined with the
 * gate evidentiary weight (grade / promoted / sourceCount / infraSourceCount) + the surfaced_in
 * connection confidence per run. The retained projection of mentions; the raw snippet TEXT is the
 * signed zero-retention divergence (not shown). READ-ONLY over the already-redacted entity DB.
 */
export function entityAppearancesFor(vault: Vault, ref: EntityRef): EntityAppearance[] {
  const store = entityDbFor(vault, null);
  const rec = getEntity(store, ref.type, ref.value);
  if (!rec) return [];
  // surfaced_in connections carry the per-run confidence to the objective/seed endpoint.
  const confByRun = new Map<string, string>();
  for (const c of connectionsFor(store, ref.type, ref.value)) {
    if (c.relType !== "surfaced_in") continue;
    for (const run of c.runs) if (!confByRun.has(run)) confByRun.set(run, c.confidence);
  }
  return rec.runs.map((objective) => ({
    objective,
    promoted: rec.promoted,
    grade: rec.grade,
    sourceCount: rec.sourceCount,
    infraSourceCount: rec.infraSourceCount,
    surfacedConfidence: confByRun.get(objective),
  }));
}

// §6: the EDITABLE analyst-dossier override — the ONE new persisted key. Mirrors setReportNotes EXACTLY:
// single-writer vault.put, redacted IN + OUT, capped, secret-tainted entity rejected. Kept SEPARATE from
// the AI dossier (a different key) so an "analyst-edited" badge + a Revert-to-AI are honest. Same
// local-vault, redacted, user-owned class as report:<objective>:notes — NOT a novel retention surface.
const ENTITY_PREFIX = "entity:";
const DOSSIER_OVERRIDE_SUFFIX = ":dossier_override";
const MAX_DOSSIER_OVERRIDE_CHARS = 8000; // a dossier is longer-form than a note; still bounded (capped class)

function dossierOverrideKey(canonicalKey: string): string {
  return `${ENTITY_PREFIX}${canonicalKey}${DOSSIER_OVERRIDE_SUFFIX}`;
}

/** §6: save the analyst's dossier override for ONE entity. The canonKey is built from the REDACTED
 *  type/value and REJECTED if secret-tainted (the applyCorrection discipline — you cannot annotate a
 *  secret-tainted entity); the text is redacted + line-ending normalized + capped; written through the
 *  EXISTING vault.put single-writer (NO new createWritable). */
export async function setEntityDossierOverride(vault: Vault, ref: EntityRef, text: string): Promise<void> {
  const safeType = redactProjectionText(vault, ref.type);
  const safeValue = redactProjectionText(vault, ref.value);
  if (safeType.includes("[REDACTED]") || safeValue.includes("[REDACTED]")) {
    throw new SessionError("Cannot edit the dossier of a secret-tainted entity.");
  }
  const key = canonKey(safeType, safeValue);
  const safe = redactProjectionText(vault, (text ?? "").replace(/\r\n?/g, "\n")).slice(0, MAX_DOSSIER_OVERRIDE_CHARS);
  try {
    await vault.put(dossierOverrideKey(key), { text: safe, author: getAnalyst(vault), at: new Date().toISOString() });
  } catch {
    throw new SessionError("Unlock your vault to save the dossier.");
  }
}

export interface EntityDossierOverride {
  text: string;
  author: string;
}

/** §6: the saved (redacted) dossier override for one entity, or null (locked / missing / blank / a
 *  secret-tainted canonKey). A blank text (the Revert-to-AI tombstone) reads back as null, so the AI
 *  dossier shows again. Belt: redact on read too. */
export function getEntityDossierOverride(vault: Vault, ref: EntityRef): EntityDossierOverride | null {
  // codex impl-review: redact the type/value FIRST and reject a secret-tainted entity BEFORE canonKey
  // lowercases the [REDACTED] marker — a case-sensitive check AFTER canonKey would see "[redacted]" and
  // slip (the EXACT applyCorrection D5 bug). Mirrors setEntityDossierOverride's redact-first build, so the
  // getter and the setter agree on the SAME key for a tainted entity (both reject) and a normal one (no-op).
  const safeType = redactProjectionText(vault, ref.type);
  const safeValue = redactProjectionText(vault, ref.value);
  if (safeType.includes("[REDACTED]") || safeValue.includes("[REDACTED]")) return null; // tainted → never read
  const key = canonKey(safeType, safeValue);
  let v: unknown;
  try {
    v = vault.get(dossierOverrideKey(key));
  } catch {
    return null; // locked or missing
  }
  if (!v || typeof v !== "object" || typeof (v as { text?: unknown }).text !== "string") return null;
  const text = redactProjectionText(vault, (v as { text: string }).text).trim();
  if (!text) return null; // blank → reverted-to-AI
  const author = redactProjectionText(vault, typeof (v as { author?: unknown }).author === "string" ? (v as { author: string }).author : "analyst");
  return { text, author };
}

// ---- sf-activity: the /activity feed ("who did what, when") ----
//
// The original /activity reads a server `activity` SQLite table written at each action. The browser keeps
// NO event-log table (zero-retention), so the faithful analog is a READ PROJECTION over the records that
// ALREADY carry a timestamp — corrections, dossier overrides, report notes, uploads, the analysis record,
// enrich runs, the groupbrief index. NO new write path, NO new vault key, NO new retention surface. Every
// value is key-redacted at this layer (labels via the redacted store; objectives/authors redacted; tainted
// records excluded). An action with no timestamped retained record is a SIGNED divergence (see the manifest
// note), not a silent strip.

export interface ActivityItem {
  analyst: string | null; // the actor (corrections/dossier carry author; the rest do not — shown without a chip)
  action: string; // "asserted role → channel" / "edited the dossier" / "uploaded acme.csv" / "processed the case"
  entityLabel?: string; // the entity the action touched (redacted)
  report?: string; // the report/objective the action touched (redacted)
  detail?: string; // sourceType / enrich target / "N group(s)"
  at: string; // ISO timestamp — the reverse-chron sort key
}

const MAX_ACTIVITY_ITEMS = 200; // the original activity_mod.recent(limit=200)

export function activityFor(vault: Vault): ActivityItem[] {
  let keys: string[];
  try {
    keys = vault.keys();
  } catch {
    return []; // locked
  }
  const store = entityDbFor(vault).entities; // already key-redacted; the canonKey → label map
  const labelFor = (canonicalKey: string): string =>
    redactProjectionText(vault, store[canonicalKey]?.label ?? decodeCanonKeyValue(canonicalKey));
  // codex impl-review: DROP a secret-tainted record (its canonKey/objective carries the live key) rather
  // than admit a timestamped action for it — the applyCorrection/getEntityDossierOverride drop-tainted
  // discipline. redactProjectionText is a no-op on clean input, so this only fires on a tainted key.
  const tainted = (s: string): boolean => redactProjectionText(vault, s) !== s;
  const items: ActivityItem[] = [];

  for (const k of keys) {
    // 1) corrections — read the RAW record for `at` + `deleted` (listCorrections drops both). author + value
    //    redacted (a forged record could carry a non-allowlisted value); tainted entity dropped.
    if (k.startsWith(CORRECTION_PREFIX)) {
      const parsed = parseCorrectionKey(k);
      if (!parsed || tainted(parsed.canonicalKey)) continue;
      const rec = safeGet(vault, k);
      const at = recAt(rec);
      if (!at) continue;
      const value = redactProjectionText(vault, typeof (rec as { value?: unknown }).value === "string" ? (rec as { value: string }).value : "");
      const deleted = (rec as { deleted?: unknown }).deleted === true;
      items.push({
        analyst: redactProjectionText(vault, typeof (rec as { author?: unknown }).author === "string" ? (rec as { author: string }).author : "analyst"),
        action: deleted ? `reverted ${parsed.predicate}` : `asserted ${parsed.predicate} → ${value}`,
        entityLabel: labelFor(parsed.canonicalKey),
        at,
      });
      continue;
    }
    // 2) dossier overrides — entity:<canonKey>:dossier_override. author redacted; text only gates the verb;
    //    tainted entity dropped.
    if (k.startsWith(ENTITY_PREFIX) && k.endsWith(DOSSIER_OVERRIDE_SUFFIX)) {
      const canonicalKey = k.slice(ENTITY_PREFIX.length, k.length - DOSSIER_OVERRIDE_SUFFIX.length);
      if (tainted(canonicalKey)) continue;
      const rec = safeGet(vault, k);
      const at = recAt(rec);
      if (!at) continue;
      const text = typeof (rec as { text?: unknown }).text === "string" ? redactProjectionText(vault, (rec as { text: string }).text).trim() : "";
      items.push({
        analyst: redactProjectionText(vault, typeof (rec as { author?: unknown }).author === "string" ? (rec as { author: string }).author : "analyst"),
        action: text ? "edited the dossier" : "reverted the dossier to AI",
        entityLabel: labelFor(canonicalKey),
        at,
      });
      continue;
    }
    // 3) report notes — report:<objective>:notes. No author on the record (honest: never stamped here).
    if (k.startsWith(REPORT_PREFIX) && k.endsWith(":notes")) {
      const objective = k.slice(REPORT_PREFIX.length, k.length - ":notes".length);
      if (objectiveTainted(vault, objective)) continue;
      const rec = safeGet(vault, k);
      const at = recAt(rec);
      if (!at) continue;
      items.push({ analyst: null, action: "edited notes", report: redactProjectionText(vault, objective), at });
    }
  }

  // 4) uploads — the file-ingest path stamps run.ingestedAt + title (a normal agent run has no createdAt).
  for (const objective of objectivesUnder(vault, RUN_PREFIX)) {
    const rec = safeGet(vault, `${RUN_PREFIX}${objective}`);
    // codex impl-review: an enrich run is also a run: record (with `at`, not `ingestedAt`); exclude it here
    // so a forged enrich record carrying BOTH fields can't be double-counted as an upload AND an enrich run.
    if ((rec as { sourceKind?: unknown }).sourceKind === ENRICH_SOURCE_KIND) continue;
    const at = typeof (rec as { ingestedAt?: unknown }).ingestedAt === "string" ? (rec as { ingestedAt: string }).ingestedAt : "";
    if (!at) continue;
    const title = typeof (rec as { title?: unknown }).title === "string" && (rec as { title: string }).title ? (rec as { title: string }).title : objective;
    const sourceType = typeof (rec as { sourceType?: unknown }).sourceType === "string" ? (rec as { sourceType: string }).sourceType : "";
    items.push({
      analyst: null,
      action: `uploaded ${redactProjectionText(vault, title)}`,
      detail: sourceType ? redactProjectionText(vault, sourceType) : undefined,
      at,
    });
  }

  // 5) process — the analysis record is rewritten each Process; only the latest updatedAt is retained.
  const analysis = analysisFor(vault);
  if (analysis?.updatedAt) items.push({ analyst: null, action: "processed the case", at: analysis.updatedAt });

  // 6) enrichment runs — listEnrichRuns carries `at` + provider/target. The writers redact, but belt the
  //    provider/target on read too (codex impl-review: a forged enrich run could carry a secret in either).
  for (const run of listEnrichRuns(vault)) {
    if (!run.at) continue;
    const target = redactProjectionText(vault, run.target || "");
    items.push({ analyst: null, action: `ran ${redactProjectionText(vault, run.provider)} enrichment`, detail: target || undefined, at: run.at });
  }

  // 7) group briefs — groupbrief:index is stamped on each generateGroupBriefs.
  const idx = safeGet(vault, `${GROUPBRIEF_PREFIX}${GROUPBRIEF_INDEX}`);
  const idxAt = recAt(idx);
  if (idxAt) {
    const n = Array.isArray((idx as { groups?: unknown }).groups) ? (idx as { groups: unknown[] }).groups.length : 0;
    items.push({ analyst: null, action: "grouped related reports", detail: `${n} group(s)`, at: idxAt });
  }

  // reverse-chron (at DESC — ISO strings sort lexically = chronologically), capped like the original.
  items.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  return items.slice(0, MAX_ACTIVITY_ITEMS);
}

/** Read a vault record, returning {} on lock/miss (so the activity projection never throws). */
function safeGet(vault: Vault, key: string): object {
  try {
    const v = vault.get(key);
    return v && typeof v === "object" ? (v as object) : {};
  } catch {
    return {};
  }
}

/** The ISO `at` field of a record, or "" when absent (the activity projection skips timestamp-less records). */
function recAt(rec: object): string {
  const at = (rec as { at?: unknown }).at;
  return typeof at === "string" ? at : "";
}

// ---- sf-exports: the downstream-tool export model (STIX / MISP / CSV) ----
//
// exportModelFor builds the KEY-REDACTED ExportModel the pure serializers (src/export/intel.ts) turn into
// bytes. The EXPLICIT role (correction > AI overlay, "" when none — the Python `entities.notes` analog) is
// what every export emits, NOT the type-derived display role. Noise entities are dropped; relationships
// whose endpoint isn't in the (non-noise) set are dropped; the cluster description comes from
// analysisFor().clusters (clustersFor omits it). All labels come from the already-redacted store; cluster
// names/kinds/descriptions + rel type/evidence are belted on read.
export function exportModelFor(vault: Vault, current?: GraphModel | null): ExportModel {
  const store = entityDbFor(vault, current).entities; // already key-redacted
  const rec = analysisFor(vault);
  const cmap = correctionMap(vault);
  // role decision (founder 2026-06-24): read the EFFECTIVE role off the store, which already encodes
  // correction > coerced-AI (applyCorrections(applyAnalysis(...))) — so operator-on-domain is healed to
  // infra here too (was a direct rec.roles read that bypassed the coercion). Analyst correction still wins.
  const explicitRole = (key: string): string => store[key]?.role ?? "";
  const effectiveType = (key: string, fallback: string): string => cmap[key]?.type ?? rec?.types?.[key] ?? fallback;

  // clusters (from the analysis record — it carries the description clustersFor drops) + per-entity membership.
  const clusterNamesByKey = new Map<string, string[]>();
  const clusters: ExportCluster[] = [];
  for (const c of rec?.clusters ?? []) {
    const name = redactProjectionText(vault, c.name);
    const memberNames: string[] = [];
    for (const k of c.memberKeys) {
      const ent = store[k];
      if (!ent) continue; // resolve members by the live redacted store (drop a forged/missing member)
      memberNames.push(ent.label);
      const list = clusterNamesByKey.get(k) ?? [];
      list.push(name);
      clusterNamesByKey.set(k, list);
    }
    clusters.push({ name, kind: redactProjectionText(vault, c.kind), description: redactProjectionText(vault, c.description), members: memberNames });
  }

  // entities: every NON-noise entity, sorted threat_score DESC then label (the Python ORDER BY), 1-based id.
  const ranked = Object.entries(store)
    .map(([key, ent]) => ({ key, ent, role: explicitRole(key), score: entityScoreFor(vault, key) }))
    .filter((x) => x.role !== "noise")
    .sort((a, b) => (b.score?.threatScore ?? 0) - (a.score?.threatScore ?? 0) || a.ent.label.localeCompare(b.ent.label));
  const idByKey = new Map<string, number>();
  const entities: ExportEntity[] = ranked.map((x, i) => {
    idByKey.set(x.key, i + 1);
    return {
      id: i + 1, // a stable client index — the SQLite rowid analog (signed divergence)
      name: x.ent.label,
      type: effectiveType(x.key, x.ent.ref.type),
      role: x.role,
      threatScore: x.score?.threatScore ?? 0,
      degree: x.score?.degree ?? 0,
      reportCount: x.score?.reportCount ?? 0,
      clusters: clusterNamesByKey.get(x.key) ?? [],
    };
  });

  // relationships: BOTH endpoints must be in the (non-noise) entity set (the Python id_for_entity join).
  const relationships: ExportRel[] = [];
  for (const r of rec?.relationships ?? []) {
    const srcId = idByKey.get(r.srcKey);
    const dstId = idByKey.get(r.dstKey);
    if (!srcId || !dstId) continue;
    relationships.push({
      srcId,
      dstId,
      srcName: store[r.srcKey]!.label,
      dstName: store[r.dstKey]!.label,
      relType: redactProjectionText(vault, r.relType),
      confidence: r.confidence,
      evidence: redactProjectionText(vault, r.evidence),
    });
  }

  return { investigationName: "kipi-investigations", entities, relationships, clusters };
}

/** The five export artifacts (STIX / MISP / 3 CSVs), serialized from the redacted model. */
export function exportFilesFor(vault: Vault, current?: GraphModel | null): ExportFiles {
  return buildExportFiles(exportModelFor(vault, current));
}

// ---- sf-report-builder: the branded client report model (client_report.gather port) ----
//
// reportModelFor assembles the KEY-REDACTED data the /report page renders into the branded deliverable
// (report.html). All sources are the EXISTING redacted accessors — brief:case, focusItemsFor (the
// focus._gather_top + _build_why analog), the dossier:<key> records + the analyst override, the IOC-typed
// entities + their appearances, listIngestedDocs. NO vault write, NO new key. cross_case is structurally
// empty in the single-vault client (no other cases until sf-cases) — the section renders its honest empty
// state and auto-populates once multi-case lands (signed).

export interface ReportActor {
  name: string;
  role: string;
  type: string;
  why: string; // the deterministic focus _build_why sentence
}
export interface ReportDossier {
  name: string;
  source: "analyst" | "ai";
  body: string; // markdown (rendered escape-first by the page)
}
export interface ReportIoc {
  name: string;
  type: string;
  reports: number; // distinct reports the indicator appears in (entityAppearancesFor)
}
export interface ReportCrossCase {
  name: string;
  type: string;
  alsoIn: string[];
}
export interface ReportSource {
  title: string;
  sourceType: string;
  ingestedAt: string;
}
export interface ReportModel {
  caseName: string;
  stats: { reports: number; entities: number };
  execSummary: string; // the synthesis brief markdown (frontmatter-stripped)
  topActors: ReportActor[];
  dossiers: ReportDossier[];
  iocs: ReportIoc[];
  crossCase: ReportCrossCase[];
  sources: ReportSource[];
}

const REPORT_IOC_TYPES = new Set(["ip", "domain", "email", "crypto_wallet", "phone", "url", "telegram_channel"]);
const MAX_REPORT_ACTORS = 12; // client_report._top_actors limit
const MAX_REPORT_IOCS = 100; // client_report._iocs limit

/** client_report._strip_frontmatter — drop a leading `---`…`---` YAML block (the client brief has none, but
 *  the port keeps the behavior so a frontmatter'd brief renders clean). */
function stripReportFrontmatter(md: string): string {
  if (md.startsWith("---")) {
    const parts = md.split("---");
    if (parts.length >= 3) return parts.slice(2).join("---").replace(/^\n+/, "");
  }
  return md;
}

// ---- clu-auto-report: the case report AUTO-EXISTS (no Generate button) and reflects current state ----

const REPORT_SUMMARY_KEY = "reportsummary:case"; // single-case editable exec-summary override
const MAX_REPORT_SUMMARY_CHARS = 20000;

/**
 * The deterministic, always-present working summary of the case — no LLM, no Generate. Built from the
 * SAME key-safe projections the report reads, so it auto-updates as the case grows and never leaks a
 * secret. It is the execSummary fallback when there is no LLM brief AND no analyst edit; on an empty
 * case it returns useful guidance, never an error.
 */
export function liveCaseSummary(vault: Vault): string {
  const ingest = new Set(listIngestedDocs(vault).map((d) => d.objective));
  const runs = listRuns(vault).filter((r) => !ingest.has(r.objective));
  const promoted = runs.reduce((n, r) => n + (r.promoted || 0), 0);
  const leads = runs.reduce((n, r) => n + (r.leads || 0), 0);
  const entities = Object.values(entityDbFor(vault, null).entities) as EntityRecord[]; // key-redacted
  const reports = ingest.size;

  if (reports === 0 && runs.length === 0 && entities.length === 0) {
    return [
      "## Working summary",
      "",
      "No evidence yet. Attach files or images, or paste a report in the Workspace — then `investigate <entity>` to build findings.",
      "This report updates live as the case grows; there is nothing to generate.",
    ].join("\n");
  }

  const top = entities
    .map((e) => ({ label: e.label, type: e.ref.type, n: entityAppearancesFor(vault, e.ref).length }))
    .sort((a, b) => b.n - a.n || a.label.localeCompare(b.label))
    .slice(0, 8);
  const done = new Set(tradecraftState(vault).filter((s) => s.done).map((s) => s.step));
  const mark = (k: TradecraftStep): string => (done.has(k) ? "✓" : "—");
  const scope = getTradecraft(vault, "scope")?.content?.trim();

  const lines: string[] = ["## Working summary", ""];
  if (scope) lines.push(`**Scope.** ${scope}`, "");
  lines.push(`**Evidence.** ${reports} report${reports === 1 ? "" : "s"} ingested · ${runs.length} investigation run${runs.length === 1 ? "" : "s"}.`);
  lines.push(`**Findings.** ${promoted} promoted, ${leads} lead${leads === 1 ? "" : "s"}.`);
  if (top.length) {
    lines.push("", "**Key entities.**");
    for (const t of top) lines.push(`- ${t.label} (${t.type}) — in ${t.n} report${t.n === 1 ? "" : "s"}`);
  }
  lines.push("", `**Tradecraft.** Challenge ${mark("challenge")} · Premortem ${mark("premortem")} · Reality-check ${mark("reality_check")}`);
  lines.push("", "_Live working summary, auto-derived from the current case state. Run Challenge before delivering; use Regenerate brief for a written narrative._");
  return redactProjectionText(vault, lines.join("\n")); // belt: each line is already from a redacted projection
}

/** The analyst's persisted edit of the report exec-summary (the top authority), or null if none/blank.
 *  Redact-on-read so a secret that somehow landed in the record never reaches the report. */
export function getReportSummaryEdit(vault: Vault): string | null {
  let v: unknown;
  try {
    v = vault.get(REPORT_SUMMARY_KEY);
  } catch {
    return null;
  }
  if (!v || typeof v !== "object" || typeof (v as { text?: unknown }).text !== "string") return null;
  const text = redactProjectionText(vault, (v as { text: string }).text).trim();
  return text || null; // blank → reverted-to-derived
}

/** Persist the analyst's report exec-summary edit (redacted + length-capped) through the single writer. */
export async function saveReportSummaryEdit(vault: Vault, text: string): Promise<void> {
  const safe = redactProjectionText(vault, (text ?? "").replace(/\r\n?/g, "\n")).slice(0, MAX_REPORT_SUMMARY_CHARS);
  try {
    await vault.put(REPORT_SUMMARY_KEY, { text: safe, author: getAnalyst(vault), at: new Date().toISOString() });
  } catch {
    throw new SessionError("Unlock your vault to save the report.");
  }
}

/** Re-render: drop the analyst edit so the report reverts to the current-state summary (brief or live). */
export async function clearReportSummaryEdit(vault: Vault): Promise<void> {
  try {
    await vault.put(REPORT_SUMMARY_KEY, { text: "", author: getAnalyst(vault), at: new Date().toISOString() });
  } catch {
    throw new SessionError("Unlock your vault to re-render the report.");
  }
}

export function reportModelFor(vault: Vault, current?: GraphModel | null): ReportModel {
  const store = entityDbFor(vault, current).entities; // already key-redacted
  const rec = analysisFor(vault);
  const cmap = correctionMap(vault);
  // role decision (founder 2026-06-24): read the EFFECTIVE role off the store, which already encodes
  // correction > coerced-AI (applyCorrections(applyAnalysis(...))) — so operator-on-domain is healed to
  // infra here too (was a direct rec.roles read that bypassed the coercion). Analyst correction still wins.
  const explicitRole = (key: string): string => store[key]?.role ?? "";
  const effectiveType = (key: string, fallback: string): string => cmap[key]?.type ?? rec?.types?.[key] ?? fallback;

  // clu-auto-report: the exec summary ALWAYS resolves (no Generate button). Precedence: analyst edit >
  // the LLM brief > the deterministic live summary (which is itself non-empty/guidance on an empty case).
  const edit = getReportSummaryEdit(vault);
  const brief = stripReportFrontmatter(getBrief(vault, CASE_BRIEF_KEY) ?? "");
  const execSummary = edit ?? (brief || liveCaseSummary(vault));

  // top actors (focus._gather_top + _build_why) — already redacted + score-ranked.
  const actors = focusItemsFor(vault).slice(0, MAX_REPORT_ACTORS);
  const topActors: ReportActor[] = actors.map((a) => ({ name: a.name, role: a.role, type: a.type, why: a.why }));

  // dossiers: the analyst override (top authority) else the AI dossier:<key>; included only when a body exists.
  const dossiers: ReportDossier[] = [];
  for (const a of actors) {
    const override = getEntityDossierOverride(vault, a.ref);
    if (override?.text) {
      dossiers.push({ name: a.name, source: "analyst", body: override.text }); // already redacted on read
      continue;
    }
    const raw = safeGet(vault, `${DOSSIER_PREFIX}${canonKey(a.ref.type, a.ref.value)}`);
    const body = typeof (raw as { dossier?: unknown }).dossier === "string" ? redactProjectionText(vault, (raw as { dossier: string }).dossier) : "";
    if (body) dossiers.push({ name: a.name, source: "ai", body });
  }

  // IOCs: IOC-typed, non-noise entities + their distinct-report count (entityAppearancesFor).
  const iocs: ReportIoc[] = [];
  for (const [key, e] of Object.entries(store) as [string, EntityRecord][]) {
    const type = effectiveType(key, e.ref.type);
    if (!REPORT_IOC_TYPES.has(type) || explicitRole(key) === "noise") continue;
    iocs.push({ name: e.label, type, reports: entityAppearancesFor(vault, e.ref).length });
  }
  iocs.sort((a, b) => a.type.localeCompare(b.type) || b.reports - a.reports);

  // sources + stats (the ingested docs + the entity count). codex impl-review: belt the title/sourceType on
  // read — listIngestedDocs returns rec.title/sourceType raw, so a forged/legacy file-ingest record with the
  // key in title would otherwise reach the Methodology table (the objective fallback is already redacted).
  const docs = listIngestedDocs(vault);
  const sources: ReportSource[] = docs.map((d) => ({
    title: redactProjectionText(vault, d.title ?? d.objective),
    sourceType: redactProjectionText(vault, d.sourceType ?? ""),
    ingestedAt: d.ingestedAt ?? "",
  }));

  return {
    caseName: ANALYSIS_SLUG, // the analysis-record slug (not a case dimension)
    stats: { reports: docs.length, entities: Object.keys(store).length },
    execSummary,
    topActors,
    dossiers,
    iocs: iocs.slice(0, MAX_REPORT_IOCS),
    crossCase: [], // structurally empty in the single-vault client — populates after sf-cases (signed)
    sources,
  };
}

// ---- rb-session: alerts (priority projection) + per-report notes ----

export interface Alert {
  id: string; // stable + deterministic: `${alertType}|${canonKey}` (the ack key; NOT random)
  label: string;
  type: string;
  role: string;
  grade: string;
  runs: number;
  reason: string;
  severity: "high" | "medium"; // high = watchlist (grade-A) ; medium = cross-run (the cross_case analog)
  alertType: "watchlist" | "cross_run"; // the original alerts.py alert_type taxonomy (cross_case → sf-cases)
  acknowledged: boolean; // read from alert:<id>:ack
}
export const MAX_ALERTS = 100;

// sf-alerts: the analyst-acknowledgement write-path. Mirrors setEntityDossierOverride EXACTLY (single-writer
// vault.put, redacted IN, secret-tainted id rejected). alert:<id>:ack = {at, author}. The original alerts.py
// has acknowledge / acknowledge_all + open_count; the client reproduces them over the computed alerts.
const ALERT_PREFIX = "alert:";
const ALERT_ACK_SUFFIX = ":ack";
function alertAckKey(id: string): string {
  return `${ALERT_PREFIX}${id}${ALERT_ACK_SUFFIX}`;
}

// codex impl-review: the marker test is CASE-INSENSITIVE. canonKey lowercases the [REDACTED] marker to
// [redacted] when it builds the id (the applyCorrection D5 trap), so an uppercase-only check is dead. This
// catches both forms, and alertsFor ALSO skips a tainted entity up front (defense in depth + no id collision).
function isRedactedId(s: string): boolean {
  return /\[redacted\]/i.test(s);
}

/** Is this alert acknowledged? Reads alert:<id>:ack; a secret-tainted id is never read (returns false). */
export function getAlertAck(vault: Vault, id: string): boolean {
  const safe = redactProjectionText(vault, id);
  if (isRedactedId(safe)) return false;
  let v: unknown;
  try {
    v = vault.get(alertAckKey(safe));
  } catch {
    return false; // locked or missing
  }
  return !!v && typeof v === "object";
}

/** Acknowledge ONE alert (the original alerts.py acknowledge). Single-writer; secret-tainted id rejected. */
export async function ackAlert(vault: Vault, id: string): Promise<void> {
  const safe = redactProjectionText(vault, id);
  if (isRedactedId(safe)) throw new SessionError("Cannot acknowledge a secret-tainted alert.");
  try {
    await vault.put(alertAckKey(safe), { at: new Date().toISOString(), author: getAnalyst(vault) });
  } catch {
    throw new SessionError("Unlock your vault to acknowledge alerts.");
  }
}

/** Acknowledge MANY alerts (the original acknowledge_all). Returns the count actually written. */
export async function ackAllAlerts(vault: Vault, ids: string[]): Promise<number> {
  let n = 0;
  for (const id of ids) {
    const safe = redactProjectionText(vault, id);
    if (isRedactedId(safe)) continue; // never write a tainted id
    try {
      await vault.put(alertAckKey(safe), { at: new Date().toISOString(), author: getAnalyst(vault) });
      n++;
    } catch {
      break; // locked → stop
    }
  }
  return n;
}

/** The "act first" priority list: grade-A entities (HIGH / watchlist) + PROMOTED cross-run entities (MEDIUM
 *  / cross_run — codex D3: a non-promoted cross-run lead is NOT an alert). Each alert carries its severity,
 *  alertType, a stable id, and its ack state. Read-only over the already-redacted entity DB; ranked
 *  deterministically (severity then runs then label) + capped. The original alerts.py cross_case (MEDIUM)
 *  type is single-vault-impossible until sf-cases — the cross-RUN tier is its within-vault analog. */
export function alertsFor(vault: Vault): Alert[] {
  const out: Alert[] = [];
  for (const e of allEntities(entityDbFor(vault, null))) {
    const gradeA = (e.grade ?? "") === "A";
    const crossRun = e.promoted && e.runs.length >= 2;
    if (!gradeA && !crossRun) continue;
    // codex impl-review: a secret-tainted entity (its value redacted to the marker by entityDbFor) is NOT an
    // actionable alert — drop it so no ack is written for it AND two tainted entities can't collide on one id.
    if (isRedactedId(e.ref.value) || isRedactedId(e.label)) continue;
    const alertType: "watchlist" | "cross_run" = gradeA ? "watchlist" : "cross_run";
    const severity: "high" | "medium" = gradeA ? "high" : "medium";
    const id = `${alertType}|${canonKey(e.ref.type, e.ref.value)}`; // deterministic; the entity is already redacted
    out.push({
      id,
      label: e.label,
      type: e.type,
      role: e.role,
      grade: e.grade ?? "",
      runs: e.runs.length,
      reason: gradeA ? "grade A — strongest corroboration (watchlist)" : "appears across multiple runs (cross-run)",
      severity,
      alertType,
      acknowledged: getAlertAck(vault, id),
    });
  }
  out.sort(
    (a, b) =>
      (a.severity === "high" ? 0 : 1) - (b.severity === "high" ? 0 : 1) ||
      b.runs - a.runs ||
      a.label.localeCompare(b.label),
  );
  return out.slice(0, MAX_ALERTS);
}

const REPORT_PREFIX = "report:";
const MAX_NOTE_CHARS = 4000;

/** Save the analyst's notes for ONE ingested report (overwrite — codex D7). The objective is REJECTED if
 *  secret-tainted (codex D2 — the key embeds the objective); the text is redacted (D4) + line-ending
 *  normalized + capped; written through the EXISTING vault.put single-writer (NO new createWritable). */
export async function setReportNotes(vault: Vault, objective: string, text: string): Promise<void> {
  if (objectiveTainted(vault, objective)) throw new SessionError("Cannot attach notes to a secret-tainted report.");
  const safe = redactProjectionText(vault, (text ?? "").replace(/\r\n?/g, "\n")).slice(0, MAX_NOTE_CHARS);
  try {
    await vault.put(`${REPORT_PREFIX}${objective}:notes`, { text: safe, at: new Date().toISOString() });
  } catch {
    throw new SessionError("Unlock your vault to save notes.");
  }
}

/** The saved (redacted) notes for a report, or '' (locked / missing / a secret-tainted objective). */
export function getReportNotes(vault: Vault, objective: string): string {
  if (objectiveTainted(vault, objective)) return "";
  try {
    const v = vault.get(`${REPORT_PREFIX}${objective}:notes`);
    if (v && typeof v === "object" && typeof (v as { text?: unknown }).text === "string") {
      return redactProjectionText(vault, (v as { text: string }).text); // belt: redact on read too
    }
  } catch {
    /* locked or missing */
  }
  return "";
}

// ---- td-session: cross-domain — entities bridging >= 2 detected investigation types ----

export interface CrossDomainEntity {
  ref: EntityRef;
  label: string;
  types: string[]; // the distinct SPECIFIC types it bridges, ordered by TAXONOMY_ORDER
  runs: string[]; // the (redacted) objectives, lexicographic
}

function taxIndex(t: string): number {
  const i = (TAXONOMY_ORDER as readonly string[]).indexOf(t);
  return i < 0 ? TAXONOMY_ORDER.length : i;
}

/**
 * Entities that appear in runs spanning >= 2 distinct SPECIFIC investigation types (codex D1 —
 * 'general' is excluded; a general↔specific overlap is cross-CASE, not cross-domain). Each run's type
 * is detected deterministically (NO LLM) over its KEY-REDACTED objective + gated entities; the
 * run→type map is keyed by the REDACTED objective (codex D7 — matching EntityRecord.runs), so a raw
 * objective never reaches the output. READ-ONLY: NO vault write. All inputs are already key-redacted.
 */
export function crossDomainEntities(vault: Vault): CrossDomainEntity[] {
  // {safeObjective -> type}; detection uses the redacted objective + the run's key-redacted entities.
  const typeBySafe = new Map<string, string>();
  for (const rawObjective of objectivesUnder(vault, RUN_PREFIX)) {
    const safeObjective = redactProjectionText(vault, rawObjective);
    const ents = runEntities(vault, rawObjective).map((e) => ({ value: e.value, type: e.type }));
    typeBySafe.set(safeObjective, detectRunType(safeObjective, ents).type);
  }

  const store = entityDbFor(vault, null); // already key-redacted; runs are the safe objectives
  const out: (CrossDomainEntity & { specificCount: number })[] = [];
  for (const rec of Object.values(store.entities) as EntityRecord[]) {
    const types = [...new Set(rec.runs.map((r) => typeBySafe.get(r)).filter((t): t is string => !!t))];
    const specific = types.filter(isSpecificType);
    if (specific.length < 2) continue; // >= 2 distinct SPECIFIC types (D1)
    const sortedTypes = [...specific].sort((a, b) => taxIndex(a) - taxIndex(b));
    out.push({ ref: rec.ref, label: rec.label, types: sortedTypes, runs: [...rec.runs].sort(), specificCount: specific.length });
  }

  // TOTAL sort (codex D6): specific-type-count desc, run-count desc, canon type asc, value asc.
  out.sort((a, b) =>
    b.specificCount - a.specificCount ||
    b.runs.length - a.runs.length ||
    a.ref.type.localeCompare(b.ref.type) ||
    a.ref.value.localeCompare(b.ref.value),
  );
  return out.map(({ specificCount, ...rest }) => rest); // drop the internal sort key
}

// ---- cl-session: clusters — a pure, deterministic, read-only projection (no LLM, no fetch) ----

/**
 * The case's clusters for the /clusters page — the REAL analyze-pass clusters persisted in the
 * analysis record (ca-analyze INC-3), NOT the buildClusters co-occurrence approximation the founder
 * rejected (build-it-right-no-stopgaps). Empty until Process runs the analyze step — faithful to the
 * server (which has no clusters before analyze). Read-only: entityDbFor is key-redacted, the record
 * is validated on read, and each member's role is a real count from the store. Returns Cluster[] (the
 * /clusters page's shape) built from the record. `current` is unused now (the record is the source).
 */
export function clustersFor(vault: Vault, current?: GraphModel | null): Cluster[] {
  void current;
  const rec = analysisFor(vault);
  if (!rec?.clusters?.length) return [];
  const store = entityDbFor(vault, null);
  const out: Cluster[] = [];
  for (let i = 0; i < rec.clusters.length; i++) {
    const c = rec.clusters[i];
    const members: EntityRef[] = [];
    const roleCounts: Record<string, number> = {};
    for (const key of c.memberKeys) {
      // codex (INC-3 impl review): build the member from the STORE entity (key-redacted by
      // entityDbFor), NOT by decoding the raw memberKey — so a forged/imported record whose
      // canonical memberKey embeds a secret can never surface it, and only members that exist in
      // the CURRENT entity DB render. A memberKey absent from the store is skipped.
      const ent = store.entities[key]; // store is keyed by entityKey === canonKey
      if (!ent) continue;
      members.push(ent.ref);
      roleCounts[ent.role] = (roleCounts[ent.role] ?? 0) + 1;
    }
    if (!members.length) continue;
    // Defense-in-depth (cl-session D8): putAnalysis redacts on WRITE, but re-redact the LLM-authored
    // cluster name on READ too, so a forged/imported record can never surface a raw key in /clusters.
    out.push({ id: `c${i}`, label: redactProjectionText(vault, c.name), kind: c.kind || "cluster", members, size: members.length, roleCounts });
  }
  return out;
}

// ---- sf-bridges: cross-cluster bridge entities — a pure, deterministic, read-only projection ----

export interface BridgeCluster {
  id: string; // the clustersFor id (cN), so a chip can address the same cluster the /clusters page uses
  name: string; // the (already-redacted) analyze-cluster NAME
}

export interface Bridge {
  ref: EntityRef;
  label: string;
  type: string;
  role: string;
  promoted: boolean; // the SEED analog (the original badges seed_weight > 0)
  threatScore: number; // entityScoreFor (0 when the case isn't scored / the entity didn't score)
  clusters: BridgeCluster[]; // the distinct clusters it bridges, in clustersFor order
  clusterCount: number; // clusters.length (the original's HAVING cluster_count >= min_clusters)
  crossRelCount: number; // its typed relationships whose other endpoint sits in a DIFFERENT cluster
}

export const MAX_BRIDGES = 100; // == the original /api/bridges default limit

/**
 * The case's cross-cluster bridge entities for the /bridges page — the network-structure connectors.
 *
 * Faithful to the original /api/bridges (app.py:5345): a bridge is an entity that spans >= 2 distinct
 * analyze-clusters. The original counts an entity's DISTINCT cluster_members rows; clustersFor assigns
 * each entity to its membership clusters (a memberKey can appear in >1 analyze cluster), AND the
 * original's companion cross_edges section pairs entities across clusters via typed_relationships. This
 * projection unions BOTH paths per the build directive: an entity bridges a cluster if it is a MEMBER of
 * it OR has a typed relationship to an entity that is a member of it. Keeping >= 2 distinct clusters ==
 * the original's `HAVING cluster_count >= min_clusters` (the page's min-clusters control filters 2..5).
 *
 * Pure + read-only: clustersFor / typedRelationshipsFor / entityScoreFor all read the KEY-REDACTED
 * entity DB + the validated analysis record; no LLM, no fetch, no vault write. Sorted clusterCount desc
 * (the original's primary ORDER BY) then threatScore desc then label, and capped at MAX_BRIDGES.
 */
export function bridgesFor(vault: Vault, current?: GraphModel | null): Bridge[] {
  const clusters = clustersFor(vault, current);
  if (clusters.length < 2) return []; // no cross-cluster structure possible (honest empty, pre-Process)

  // canonKey -> the set of cluster ids the entity is a MEMBER of (an entity may be in >1 cluster).
  const memberClusters = new Map<string, Set<string>>();
  // cluster id -> its display name, for building the chip list in clustersFor order.
  const nameById = new Map<string, string>();
  for (const c of clusters) {
    nameById.set(c.id, c.label);
    for (const m of c.members) {
      const k = canonKey(m.type, m.value);
      let set = memberClusters.get(k);
      if (!set) memberClusters.set(k, (set = new Set<string>()));
      set.add(c.id);
    }
  }

  const store = entityDbFor(vault, current); // already key-redacted (label/ref/role/type/grade)
  const out: Bridge[] = [];
  for (const rec of Object.values(store.entities) as EntityRecord[]) {
    const key = canonKey(rec.ref.type, rec.ref.value);
    const spanned = new Set<string>(memberClusters.get(key) ?? []); // its own membership clusters

    // the typed-relationship path: each edge's OTHER endpoint contributes the cluster(s) it is a member
    // of, so an entity tied across clusters bridges them even if it sits in only one (or zero) itself.
    let crossRelCount = 0;
    for (const rel of typedRelationshipsFor(vault, key)) {
      const otherKey = canonKey(rel.otherRef.type, rel.otherRef.value);
      const otherClusters = memberClusters.get(otherKey);
      if (!otherClusters || otherClusters.size === 0) continue;
      // a CROSS-cluster relationship: the endpoint lands in a cluster this entity is NOT a member of.
      const ownMembership = memberClusters.get(key);
      const isCross = [...otherClusters].some((cid) => !ownMembership?.has(cid));
      if (isCross) crossRelCount++;
      for (const cid of otherClusters) spanned.add(cid);
    }

    if (spanned.size < 2) continue; // not a bridge — spans < 2 distinct clusters
    const bridgedClusters: BridgeCluster[] = clusters
      .filter((c) => spanned.has(c.id))
      .map((c) => ({ id: c.id, name: nameById.get(c.id) ?? c.label }));
    const score = entityScoreFor(vault, key);
    out.push({
      ref: rec.ref,
      label: rec.label,
      type: rec.type,
      role: rec.role,
      promoted: rec.promoted,
      threatScore: typeof score?.threatScore === "number" ? score.threatScore : 0,
      clusters: bridgedClusters,
      clusterCount: bridgedClusters.length,
      crossRelCount,
    });
  }

  // the original ORDER BY: cluster_count DESC, threat_score DESC (then a TOTAL order: label, value).
  out.sort(
    (a, b) =>
      b.clusterCount - a.clusterCount ||
      b.threatScore - a.threatScore ||
      a.label.localeCompare(b.label) ||
      a.ref.value.localeCompare(b.ref.value),
  );
  return out.slice(0, MAX_BRIDGES);
}

// ---- sf-focus: "where to look first" — a pure, deterministic, read-only projection (no LLM, no fetch) ----
//
// Faithful port of investigations/focus.py (_gather_top + compute_gaps), the iterative-loop output: the
// TOP-N entities ranked by threat score (each with role / cluster chips / the deterministic _build_why
// sentence / its top typed relationships) + the deterministic "what's missing / what to look for next"
// gap list. Pure + read-only: focusFor / focusGapsFor read the KEY-REDACTED entity DB + the validated
// analysis record (entityScoreFor / clustersFor / typedRelationshipsFor) — NO LLM, NO fetch, NO vault
// write. Honest empty (no items / no gaps) until Process scores the case — faithful to the server (which
// has no scored entities before analyze). The score-run-history DELTA strip (elevated/cooling/status) is
// the signed client-N/A divergence (the client keeps no focus-run-history snapshot store — it matches the
// server's case-scoped status="" branch app.py:886). The optional LLM Analyst summary (focus.py
// _summary_via_llm) is omitted; the deterministic gap list is the retained analog (signed).

const FOCUS_TOP_N = 12; // == focus.py TOP_N
const FOCUS_GAP_TOP_N = 15; // == focus.py GAP_TOP_N (gaps are reported against the actors that matter)
const FOCUS_MAX_RELS = 3; // == _gather_top's "max 3" top typed relationships

/** A cluster a focus item belongs to (the clustersFor id + redacted name), for the cluster chips. */
export interface FocusCluster {
  id: string; // the clustersFor id (cN)
  name: string; // the already-redacted analyze-cluster NAME
}

/** A top typed relationship for a focus item (other endpoint resolved + redacted), for the rel chips. */
export interface FocusRel {
  relType: string;
  otherRef: EntityRef;
  otherLabel: string;
  direction: "out" | "in";
}

/** One ranked focus item — a top-N entity by threat score with its role / clusters / why / top rels. */
export interface FocusItem {
  rank: number;
  ref: EntityRef;
  name: string;
  type: string;
  role: string;
  score: number; // the stored threatScore (0 only if it somehow scored to 0; un-scored never appear)
  degree: number;
  reportCount: number;
  promoted: boolean; // the SEED analog (focus.py seed_weight > 0)
  clusters: FocusCluster[];
  topRelationships: FocusRel[];
  why: string; // the deterministic _build_why sentence
}

/** A deterministic gap (port of compute_gaps' rows): what's missing / what to look for next. */
export interface FocusGap {
  kind: "uninvestigated" | "uncorroborated" | "unconsolidated";
  severity: "high" | "medium" | "low";
  title: string;
  action: string;
  count: number;
  entities: { ref: EntityRef; name: string }[]; // a display-capped named sample (focus.py [:6])
}

/** The whole focus brief: the top-ranked items + the deterministic gaps. */
export interface Focus {
  items: FocusItem[];
  gaps: FocusGap[];
}

const FOCUS_GAP_SAMPLE = 6; // == compute_gaps' `[:6]` named-sample cap

/** True if an entity is "real" for ranking/gaps — NOT noise, NOT an unresolved person_candidate (the
 *  focus.py `real` predicate: notes NOT LIKE 'role:noise%' AND entity_type != 'person_candidate'). */
function isFocusReal(rec: EntityRecord): boolean {
  return rec.role !== "noise" && rec.type !== "person_candidate";
}

/** The score-sorted real entities that scored — the shared ranking the items + gaps both draw from. The
 *  server orders by threat_score DESC; ties broken by a TOTAL order (promoted, then value) so the result
 *  is deterministic. Un-scored / noise / person_candidate entities are excluded (the focus.py WHERE). */
function rankedFocusEntities(vault: Vault): { rec: EntityRecord; score: EntityScoreRecord }[] {
  const store = entityDbFor(vault, null); // already key-redacted
  const scored: { rec: EntityRecord; score: EntityScoreRecord }[] = [];
  for (const rec of allEntities(store)) {
    if (!isFocusReal(rec)) continue;
    const score = entityScoreFor(vault, canonKey(rec.ref.type, rec.ref.value));
    if (!score) continue; // un-scored entities never enter Focus (parity with the JOIN entity_scores)
    scored.push({ rec, score });
  }
  scored.sort(
    (a, b) =>
      b.score.threatScore - a.score.threatScore ||
      Number(b.rec.promoted) - Number(a.rec.promoted) ||
      a.rec.ref.value.localeCompare(b.rec.ref.value),
  );
  return scored;
}

/** Build the deterministic "why this entity is a priority" sentence — a faithful port of focus.py
 *  _build_why over the client's retained signals (seed/clusters/top-rels/footprint). The server's
 *  sub_role/sub_role_reason + cross-case `investigations` are not per-entity-retained on the client
 *  (the EntityRecord has no sub_role; runs are objectives, not cases) — a signed micro-divergence,
 *  same as sf-report-detail's no-sub_role-pill. Pure; all inputs are already key-redacted. */
function buildFocusWhy(
  promoted: boolean,
  clusters: FocusCluster[],
  rels: FocusRel[],
  reportCount: number,
  degree: number,
): string {
  const parts: string[] = [];
  // 1. Seed prior is the strongest signal (focus.py surfaces seed_note first; the client analog is the
  //    promoted/known-bad flag — no free-text seed note is retained per entity).
  if (promoted) parts.push("flagged as known-bad (promoted prior)");
  // 3. Clusters give crew/cohort context (focus.py step 3; steps 1/2 sub_role have no client analog).
  if (clusters.length) {
    let clusterText = clusters.slice(0, 2).map((c) => c.name).join(", ");
    if (clusters.length > 2) clusterText += ` (+${clusters.length - 2} more)`;
    parts.push(`in ${clusterText}`);
  }
  // 4. Top typed relationships — what they're doing in the graph (focus.py step 4, max 2 shown).
  if (rels.length) {
    parts.push(rels.slice(0, 2).map((r) => `${r.relType} ${r.direction === "out" ? "→" : "←"} ${r.otherLabel}`).join("; "));
  }
  // 5. Report/degree footprint — only if other signals are thin (focus.py step 5: `len(parts) < 2`).
  if (parts.length < 2) {
    const footprint: string[] = [];
    if (reportCount > 1) footprint.push(`${reportCount} reports`);
    if (degree > 3) footprint.push(`degree ${degree}`);
    if (footprint.length) parts.push(footprint.join(", "));
  }
  if (!parts.length) return "high score, no narrative signal yet — run profile or check mentions.";
  return parts.join(". ").replace(/\.$/, "") + ".";
}

/**
 * The case's focus brief — the top-N entities ranked by threat score, each with role / cluster chips /
 * the deterministic why-sentence / its top typed relationships, PLUS the deterministic gaps.
 *
 * Faithful to focus.py _gather_top: ORDER BY threat_score DESC LIMIT 12; clusters = the analyze-clusters
 * the entity is a member of (clustersFor); top_relationships = max 3 typed rels, confidence-sorted
 * (high>medium>low); seed = promoted. Pure + read-only (no LLM, no fetch, no vault write); honest empty
 * pre-Process. `current` is unused (the analysis record is the source, like clustersFor).
 */
export function focusFor(vault: Vault, current?: GraphModel | null): Focus {
  void current;
  return { items: focusItemsFor(vault), gaps: focusGapsFor(vault) };
}

/** The top-N ranked focus items (focus.py _gather_top). Split out so a caller can take just the list. */
export function focusItemsFor(vault: Vault): FocusItem[] {
  const ranked = rankedFocusEntities(vault);
  if (!ranked.length) return [];

  // canonKey -> the clusters it is a MEMBER of, in clustersFor order (for the cluster chips).
  const clusters = clustersFor(vault, null);
  const clustersByKey = new Map<string, FocusCluster[]>();
  for (const c of clusters) {
    for (const m of c.members) {
      const k = canonKey(m.type, m.value);
      const list = clustersByKey.get(k) ?? [];
      list.push({ id: c.id, name: c.label });
      clustersByKey.set(k, list);
    }
  }

  const confRank: Record<string, number> = { high: 1, medium: 2, low: 3 };
  const items: FocusItem[] = [];
  for (let i = 0; i < ranked.length && i < FOCUS_TOP_N; i++) {
    const { rec, score } = ranked[i];
    const key = canonKey(rec.ref.type, rec.ref.value);
    // top typed relationships: confidence-sorted (high>medium>low — focus.py's CASE ORDER BY), then a
    // TOTAL order (relType, other label) for determinism, capped at 3. Sort on the FULL rel (which still
    // carries confidence), THEN project to the chip shape so the confidence ranking is real.
    const rels: FocusRel[] = typedRelationshipsFor(vault, key)
      .slice()
      .sort(
        (a, b) =>
          (confRank[a.confidence] ?? 4) - (confRank[b.confidence] ?? 4) ||
          a.relType.localeCompare(b.relType) ||
          a.otherLabel.localeCompare(b.otherLabel),
      )
      .slice(0, FOCUS_MAX_RELS)
      .map((r) => ({ relType: r.relType, otherRef: r.otherRef, otherLabel: r.otherLabel, direction: r.direction }));
    const cls = clustersByKey.get(key) ?? [];
    items.push({
      rank: i + 1,
      ref: rec.ref,
      name: rec.label,
      type: rec.type,
      role: rec.role,
      score: score.threatScore,
      degree: score.degree,
      reportCount: score.reportCount,
      promoted: rec.promoted,
      clusters: cls,
      topRelationships: rels,
      why: buildFocusWhy(rec.promoted, cls, rels, score.reportCount, score.degree),
    });
  }
  return items;
}

/**
 * The deterministic gaps — a faithful port of focus.py compute_gaps over the TOP-ranked actors (so the
 * list stays short, named, and actionable). The three server rules, EXACTLY:
 *   1. uninvestigated (merged) — a top actor with degree 0 OR never enriched (the SAME next action:
 *      investigate it; the detective enriches AND builds its typed links in one pass).
 *   2. uncorroborated — a top actor seen in <= 1 report (find a corroborating source before relying on it).
 *   3. unconsolidated — the count of unresolved person_candidate entities (extraction noise; re-Process merges).
 * Pure + read-only; all inputs are key-redacted. Recomputes live, sharpening as intel is added.
 */
export function focusGapsFor(vault: Vault): FocusGap[] {
  const top = rankedFocusEntities(vault).slice(0, FOCUS_GAP_TOP_N);
  const gaps: FocusGap[] = [];

  // enrichment: a target VALUE that has at least one enrich run is "enriched". hasEnr mirrors the
  // server's `_table_exists(conn, 'enrichment_runs')` — true once any enrich run has landed.
  const enriched = new Set<string>();
  const enrichRuns = listEnrichRuns(vault);
  for (const run of enrichRuns) if (run.target) enriched.add(run.target.trim().toLowerCase());
  const hasEnr = enrichRuns.length > 0;

  const actors = (n: number) => (n === 1 ? "actor" : "actors");
  const sample = (recs: EntityRecord[]) => recs.slice(0, FOCUS_GAP_SAMPLE).map((r) => ({ ref: r.ref, name: r.label }));

  // 1. uninvestigated — degree 0 OR (enrichment exists AND this actor was never enriched).
  const uninvestigated = top
    .filter(({ score, rec }) => score.degree === 0 || (hasEnr && !enriched.has(rec.ref.value.trim().toLowerCase())))
    .map((t) => t.rec);
  if (uninvestigated.length) {
    const n = uninvestigated.length;
    gaps.push({
      kind: "uninvestigated",
      severity: "medium",
      count: n,
      entities: sample(uninvestigated),
      title: `${n} top ${actors(n)} not investigated yet`,
      action:
        "Investigate them — open one on the graph and hit Investigate (or run a whole-case swarm). " +
        "The detective enriches them AND builds their typed connections in one pass.",
    });
  }

  // 2. uncorroborated — seen in <= 1 report.
  const uncorroborated = top.filter(({ score }) => score.reportCount <= 1).map((t) => t.rec);
  if (uncorroborated.length) {
    const n = uncorroborated.length;
    gaps.push({
      kind: "uncorroborated",
      severity: "medium",
      count: n,
      entities: sample(uncorroborated),
      title: `${n} top ${actors(n)} seen in only one report`,
      action: "Find corroborating sources before relying on them",
    });
  }

  // 3. unconsolidated — the count of unresolved person_candidate entities (extraction noise).
  const store = entityDbFor(vault, null);
  const nPc = allEntities(store).filter((e) => e.type === "person_candidate").length;
  if (nPc) {
    gaps.push({
      kind: "unconsolidated",
      severity: "low",
      count: nPc,
      entities: [],
      title: `${nPc} unresolved person candidate${nPc === 1 ? "" : "s"}`,
      action:
        "Mostly extraction noise. Re-running Process merges the resolvable ones; the rest are " +
        "low-signal name fragments.",
    });
  }

  return gaps;
}

// ---- adr-session: the AI dossier + semantic typed relations (no-tools LLM passes) ----

export interface AiPassOpts {
  fetchImpl?: FetchLike;
  current?: GraphModel | null;
  maxTokens?: number;
  signal?: AbortSignal;
}

/**
 * The model-written AI dossier for one entity, grounded ONLY on the entity's gated store data
 * (the entity DB is already key-redacted; `entityDbFor` redacts every input). NO tools. Key
 * hygiene mirrors generateBrief: the live key is redacted from the prompt INPUT and the model
 * OUTPUT. An objective/unknown entity OR one with zero connections returns null WITHOUT a model
 * call (no key needed, no spend). READ-ONLY: it issues NO vault write.
 */
export async function aiDossierFor(vault: Vault, type: string, value: string, opts?: AiPassOpts): Promise<string | null> {
  const store = entityDbFor(vault, opts?.current ?? null); // already key-redacted
  const rec = getEntity(store, type, value);
  if (!rec) return null; // objective/unknown entity — no entity record, no call
  const conns = connectionsFor(store, type, value);
  if (!conns.length) return null; // nothing to ground a dossier on — no model call

  const key = getApiKey(vault); // throws SessionError if locked
  if (!key) throw new SessionError("Add your Anthropic API key to generate an AI dossier.");

  const prompt = redactProjectionText(vault, buildDossierPrompt(rec, conns)); // redact IN (defense in depth)
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { text } = await client.complete({
    system: AI_DOSSIER_PERSONA,
    messages: [{ role: "user", content: prompt }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? 1400,
    signal: opts?.signal,
  });
  return parseDossier(redactProjectionText(vault, text)); // redact OUT + strip any fabricated source
}

/**
 * Semantic typed relations for one entity: the model RE-LABELS the entity's already-gated
 * connections (it cannot invent an edge). The store is key-redacted; the prompt is redacted IN
 * and the output redacted OUT before `parseSemanticRelations` validates each proposal against
 * the real connection set + runs the strong-attribution confidence gate. An entity with no
 * relatable (entity↔entity) connection returns [] WITHOUT a model call. READ-ONLY.
 */
export async function semanticRelationsFor(vault: Vault, type: string, value: string, opts?: AiPassOpts): Promise<SemanticRelation[]> {
  const store = entityDbFor(vault, opts?.current ?? null);
  const rec = getEntity(store, type, value);
  if (!rec) return [];
  const conns = connectionsFor(store, type, value);
  if (!relatableConnections(conns).length) return []; // nothing to type — no model call

  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to type relations.");

  const prompt = redactProjectionText(vault, buildRelationsPrompt(rec.ref, rec.label, conns));
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { text } = await client.complete({
    system: "You output strict JSON only. No prose, no markdown fence.",
    messages: [{ role: "user", content: prompt }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? 1200,
    signal: opts?.signal,
  });
  return parseSemanticRelations(rec.ref, redactProjectionText(vault, text), conns); // redact OUT + re-validate + gate
}

// ---- ct-session: consolidate (LLM dedup + role) + typing (LLM surface re-type) — read projections ----

// Map the entity DB to the model's view: an OPAQUE id (e0..eN) + the real ref/metadata kept LOCALLY
// (codex D1 — the model never gets a key it could fabricate to reach an unshown entity).
// kweb-analyze-uncap-entities (sp-bc070b51): analyze is CROSS-ENTITY — its clusters + typed_relationships
// span the WHOLE set, so unlike consolidate/typing (which batch the DB in MAX_CONSOLIDATE_ENTITIES chunks)
// analyze must see EVERY entity in ONE call, or it silently drops every cluster/edge touching an entity past
// the cap. (The old presentedFor 80-slice did exactly that and was removed — analyze was its only caller.)
// Parity with analyze.py _gather_context, which feeds an UNCAPPED entity_list and caps only the heavy dossier
// text (dossiers[:80], analyze.py:113). So: all entities in the compact list here; the heavy per-entity
// evidence is gated separately in analyzeCase.
function analyzePresentedFor(store: EntityStore): Presented[] {
  return allEntities(store).map((r, i) => ({
    id: `e${i}`, ref: r.ref, label: r.label, type: r.type, role: r.role, promoted: r.promoted,
  }));
}

// kweb-classify-batch (founder 2026-06-24, "remove caps"): the per-entity classification passes
// (consolidate + typing) must see EVERY entity, not silently drop everything past the first
// MAX_CONSOLIDATE_ENTITIES — a dense case (28 FIFA domains → 100+ entities via DNS/RDAP) left the
// overflow as unclassified infra "squares" with no error. Chunk the WHOLE entity DB into bounded batches,
// each re-indexed e0..ek so the opaque-id contract stays per-batch (identical to one call). Cross-batch
// alias merges are missed (same accepted limitation as the server's BATCH_SIZE batching — see CLAUDE.md),
// but every entity is now classified; before, the overflow was simply gone.
function presentedBatchesFor(store: EntityStore): Presented[][] {
  const all = allEntities(store);
  const batches: Presented[][] = [];
  for (let i = 0; i < all.length; i += MAX_CONSOLIDATE_ENTITIES) {
    batches.push(
      all.slice(i, i + MAX_CONSOLIDATE_ENTITIES).map((r, j) => ({
        id: `e${j}`, ref: r.ref, label: r.label, type: r.type, role: r.role, promoted: r.promoted,
      })),
    );
  }
  return batches;
}

// Per-batch output ceiling for the classify passes. An ≤80-entity classification JSON is ~10KB (well
// under MAX_PARSE_BYTES=32768), so a batch never truncates at this cap; the stopReason guard in each pass
// turns any residual truncation into an honest error rather than a silent null parse. Replaces the old
// 4096 (consolidate) / 1500 (typing) per-call caps that truncated an 80-entity batch → parse fail → no
// roles → squares (the bug the comment at the old call site already documented).
const CLASSIFY_BATCH_MAX_TOKENS = 8192;

const CONSOLIDATE_SYSTEM = "You output strict JSON only. No prose, no markdown fence.";

/**
 * Consolidate (server consolidate.py): a bounded, gate-faithful Haiku pass that proposes MERGE
 * equivalence groups + a role over the entity DB. A READ PROJECTION — it returns SUGGESTIONS; it writes
 * NO vault record, picks NO canonical, and invents NO entity (every returned id is validated against the
 * presented set). The prompt is redacted IN and the structured suggestions redacted OUT (codex D8). A
 * case with < 2 entities returns [] WITHOUT a model call. Parity with the AI hooks: opts.current folds
 * the live graph model (codex D10).
 */
export async function consolidateEntities(vault: Vault, opts?: AiPassOpts): Promise<ConsolidateSuggestion[]> {
  // kweb-classify-batch: classify EVERY entity by batching the whole DB — never silently drop the overflow
  // past one batch. consolidate is CLASSIFICATION (role per entity), so it runs with even ONE entity (a
  // single spoof domain still needs its operator role, else it stays an infra square). Empty case → [].
  const batches = presentedBatchesFor(entityDbFor(vault, opts?.current ?? null));
  if (batches.length === 0) return [];
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to consolidate entities.");
  // A1: feed the auto-modeled per-case schema (Process persisted it at step 1) into the prompt so the
  // model classifies by the case's own roles — an attacker-operated spoof domain → operator, not the
  // infra default (the "squares not circles" keystone). Null when no schema yet (the default role descs).
  const schema = analysisFor(vault)?.schema ?? null;
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const out: ConsolidateSuggestion[] = [];
  for (const batch of batches) {
    const prompt = redactProjectionText(vault, buildConsolidatePrompt(batch, schema));
    const { text, stopReason } = await client.complete({
      system: CONSOLIDATE_SYSTEM,
      messages: [{ role: "user", content: prompt }],
      kind: "classify",
      maxTokens: opts?.maxTokens ?? CLASSIFY_BATCH_MAX_TOKENS,
      signal: opts?.signal,
    });
    // No silent loss: a truncated batch would null-parse and drop every role in it — fail honestly instead.
    if (stopReason === "max_tokens") {
      throw new SessionError("Consolidation response was truncated — no roles were silently dropped; retry or lower the batch size.");
    }
    out.push(...redactProjectionDeep(vault, parseConsolidate(redactProjectionText(vault, text), batch)));
  }
  return out;
}

/**
 * Typing (server typing.py retype): a bounded, gate-faithful Haiku pass that proposes a refined SURFACE
 * type (from a fixed allowlist) per entity. Same read-projection + redaction discipline as consolidate.
 * An empty case returns [] WITHOUT a model call.
 */
export async function typeEntities(vault: Vault, opts?: AiPassOpts): Promise<TypingSuggestion[]> {
  // kweb-classify-batch: type EVERY entity by batching the whole DB — never silently drop the overflow.
  const batches = presentedBatchesFor(entityDbFor(vault, opts?.current ?? null));
  if (batches.length === 0) return []; // empty — no spend
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to refine entity types.");
  // PRD-B typing-case-type: feed the auto-modeled per-case schema so the pass re-buckets each entity into
  // the case's own case_type vocabulary (port of typing.py retype — was dropped on port). Null pre-schema.
  const schema = analysisFor(vault)?.schema ?? null;
  // pass the schema's case_type vocabulary so a non-schema value is coerced to 'other' (typing.py parity).
  const allowedCaseTypes = (schema?.entityTypes ?? []).map((t) => t.name).filter(Boolean);
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const out: TypingSuggestion[] = [];
  for (const batch of batches) {
    const prompt = redactProjectionText(vault, buildTypingPrompt(batch, schema));
    const { text, stopReason } = await client.complete({
      system: CONSOLIDATE_SYSTEM,
      messages: [{ role: "user", content: prompt }],
      kind: "classify",
      maxTokens: opts?.maxTokens ?? CLASSIFY_BATCH_MAX_TOKENS,
      signal: opts?.signal,
    });
    if (stopReason === "max_tokens") {
      throw new SessionError("Typing response was truncated — no types were silently dropped; retry or lower the batch size.");
    }
    out.push(...redactProjectionDeep(vault, parseTyping(redactProjectionText(vault, text), batch, allowedCaseTypes)));
  }
  return out;
}

// analyze-evidence-feed (PRD-B, RCA rca-discipline-evaporation-kipi-web-2026-06-23): build per-entity
// RETAINED evidence text for the analyze prompt. The original analyze.py feeds profile dossiers (@2500
// chars); the zero-retention client discards report text and generates the AI dossier only at Process
// step 10 (AFTER analyze, step 6), so the richest evidence retained AT analyze time is the agent's own
// per-finding CLAIM (model-authored) across every run. Keyed by canonKey, deduped, capped per entity.
// Redaction is at the egress seam: the whole analyze prompt (this text included) is wrapped in
// redactProjectionText in analyzeCase, so a claim that echoed a secret is scrubbed before the model call.
const ANALYZE_EVIDENCE_CHARS = 600; // per-entity cap (claims are short; bounds prompt growth)
// kweb-analyze-uncap-entities (sp-bc070b51): == analyze.py dossiers[:80] (analyze.py:113). Bounds the
// EXPENSIVE per-entity evidence prose, NOT the entity count — entities past this index still appear in the
// compact analyze list (id/label/type/role) so clustering can place them; they just carry no dossier text.
const ANALYZE_DOSSIER_CAP = 80;

function analyzeEvidenceFor(vault: Vault): Map<string, string> {
  const byKey = new Map<string, string[]>();
  for (const objective of objectivesUnder(vault, RUN_PREFIX)) {
    let rec: Partial<RunRecord> = {};
    try {
      const v = vault.get(`${RUN_PREFIX}${objective}`);
      if (v && typeof v === "object") rec = v as Partial<RunRecord>;
    } catch {
      continue; // unreadable record — skip
    }
    const findings: (Finding | undefined)[] = [
      ...(Array.isArray(rec.promoted) ? rec.promoted : []),
      ...(Array.isArray(rec.leads) ? rec.leads.map((l) => l?.finding) : []),
    ];
    for (const f of findings) {
      if (!f || typeof f.entity !== "string") continue;
      const claim = typeof (f as { claim?: unknown }).claim === "string" ? (f as { claim?: string }).claim!.trim() : "";
      if (!claim) continue;
      const ck = canonKey(f.entity_type ?? "", f.entity);
      const arr = byKey.get(ck) ?? [];
      if (!arr.includes(claim)) arr.push(claim);
      byKey.set(ck, arr);
    }
  }
  const out = new Map<string, string>();
  for (const [ck, claims] of byKey) out.set(ck, claims.join(" | ").slice(0, ANALYZE_EVIDENCE_CHARS));
  return out;
}

/**
 * Analyze (server analyze.py extract_typed_relationships): a bounded, no-tools LLM pass that groups the
 * case's entities into LLM-named CLUSTERS + emits typed relationships. The SAME read-projection +
 * redaction discipline as consolidate: the prompt presents OPAQUE e0..eN ids (the model never sees a
 * canonKey it could fabricate), the prompt is redacted IN, the response redacted + salvage-parsed OUT
 * (a truncated big-case response still yields the clusters that survived), and mapAnalyzeToCanonKeys
 * resolves the ids back to canonKeys LOCALLY (dropping any id outside the presented set) + gate_attribution
 * drops/demotes evidence-free strong-attribution edges. A case with < 2 entities returns empty (no spend).
 */
export async function analyzeCase(
  vault: Vault,
  opts?: AiPassOpts,
): Promise<{ clusters: AnalysisCluster[]; relationships: AnalysisRelationship[] }> {
  // kweb-analyze-uncap-entities (sp-bc070b51): EVERY entity (no 80-slice) — analyze clusters across the whole
  // set, so a sliced input silently drops every cluster/edge touching an entity past the cap.
  const presented = analyzePresentedFor(entityDbFor(vault, opts?.current ?? null));
  if (presented.length < 2) return { clusters: [], relationships: [] }; // nothing to cluster — no spend
  const key = getApiKey(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to analyze the case.");
  const schema = analysisFor(vault)?.schema ?? null;
  // canonKey(p.ref.type, p.ref.value) === the store's entityKey for this entity === the key
  // applyClustersToModel matches on (canonKey(node.entityType, node.label)) — so a cluster lands on the graph.
  const evidence = analyzeEvidenceFor(vault); // analyze-evidence-feed: retained per-entity claim text
  // The heavy dossier prose is attached to only the first ANALYZE_DOSSIER_CAP entities (== analyze.py
  // dossiers[:80]); the rest still appear in the compact list so clustering can place them.
  const entities: PresentedEntity[] = presented.map((p, i) => {
    const ck = canonKey(p.ref.type, p.ref.value);
    const dossier = i < ANALYZE_DOSSIER_CAP ? evidence.get(ck) : undefined;
    return { id: p.id, canonKey: ck, label: p.label, type: p.type, role: p.role, dossier };
  });
  const prompt = redactProjectionText(vault, buildAnalyzePrompt(entities, schema));
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { text } = await client.complete({
    system: buildAnalyzeSystem(schema),
    messages: [{ role: "user", content: prompt }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? ANALYZE_MAX_TOKENS,
    signal: opts?.signal,
  });
  const raw = salvageAnalyzeJson(redactProjectionText(vault, text));
  // analyze-max-rels (PRD-B, RCA discipline-evaporation): the original analyze.py bounds typed_relationships
  // ONLY via the prompt ("Emit AT MOST N"); kipi-web ADDS a deterministic apply-side cap. DEFENSIVE bound:
  // only trim a runaway response (4x the cap) before gating — capping raw to exactly N here would let junk
  // (self-loops / unknown ids / evidence-free strong attribution dropped by gateAttribution) in the first N
  // crowd out VALID edges later in the response (codex issue-1 major). The real semantic cap is applied to
  // the GATED relationships below, so the agent keeps up to N *valid* network edges.
  if (Array.isArray(raw.typed_relationships) && raw.typed_relationships.length > ANALYZE_MAX_RELATIONSHIPS * 4) {
    raw.typed_relationships = raw.typed_relationships.slice(0, ANALYZE_MAX_RELATIONSHIPS * 4);
  }
  // INC-4a: a schema-APPROVED run keeps a clean per-case rel label (allowNovel); a generic run uses the
  // closed vocab (unknown → linked_to). normalizeRel runs inside mapAnalyzeToCanonKeys.
  const allowNovel = !!(schema && schema.domain);
  const analyzed = mapAnalyzeToCanonKeys(raw, entities, allowNovel);
  analyzed.relationships = analyzed.relationships.slice(0, ANALYZE_MAX_RELATIONSHIPS); // the real cap, post-gate
  return redactProjectionDeep(vault, analyzed);
}

// ---- cd-grounding: grounded Q&A (no-tools), key-redacted in context + question + output ----

export interface AnswerOpts {
  fetchImpl?: FetchLike;
  maxTokens?: number;
  signal?: AbortSignal;
  // Node-reference (founder 2026-06-24): the entity the analyst has SELECTED on the graph. The graph is a
  // visual Claude can't see; the selection is how the analyst points at what "this" means. Folded into the
  // Q&A prompt by focusedQuestionFor so "what is this?" resolves to the clicked node.
  selectedNode?: string | null;
  // Statelessness fix (founder 2026-07-03): the recent chat turns, so a follow-up ("more succinctly",
  // "why?", "drill into X") has the prior answer to work from instead of resetting to "I don't know".
  // Redacted + capped here (QA_HISTORY_TURNS / QA_HISTORY_TURN_CHARS) before reaching the wire.
  history?: QaTurn[];
}

const QA_HISTORY_TURNS = 6; // the last N real chat turns fed back into Q&A
const QA_HISTORY_TURN_CHARS = 1200; // bound ONE turn (a long prior answer still compresses fine from its head)

/** Cap + key-redact the caller's chat history into the turns fed to the Q&A prompt. */
function safeHistoryFor(vault: Vault, history: QaTurn[] | undefined): QaTurn[] {
  return (history ?? [])
    .filter((t) => t && (t.role === "you" || t.role === "agent") && typeof t.text === "string" && t.text.trim())
    .slice(-QA_HISTORY_TURNS)
    .map((t) => ({ role: t.role, text: redactProjectionText(vault, t.text.trim().slice(0, QA_HISTORY_TURN_CHARS)) }));
}

// N4a (video-review 2026-06-25): a DEICTIC question points at the selected node ("what is this?", "who's
// behind it?", "dig here"). Only THESE should be resolved onto the selection. The old prompt added
// "…or is otherwise about the selection" — which made the model answer EVERY question about the clicked
// node, so "what should I investigate next in this case?" (a case-wide question) came back scoped to one
// IP. We now gate on an explicit deictic in the question text; a non-deictic / case-wide question ignores
// the selection entirely.
// A bare "this"/"it"/"here" points at the clicked node — EXCEPT "this case / investigation / graph / …",
// which refer to the whole case, not the selection (the false positive that made "what should I investigate
// next in this case?" scope to one node). The negative lookahead after "this" excludes those case-level nouns.
const DEICTIC_RE = /\b(?:it|its|it['’]s|here|that\s+(?:node|one|entity)|selected\s+node|this(?!\s+(?:case|investigation|graph|roster|list|run|sweep|report|brief)))\b/i;

/** Node-reference: fold the analyst's SELECTED graph entity into the Q&A question ONLY when the question is
 *  deictic (refers to "this"/"it"/"here"/"that node"). A no-op when nothing is selected OR the question is
 *  case-wide (N4a). Pure — redaction happens on the composed result in answerQuestion. */
export function focusedQuestionFor(question: string, selectedNode: string | null | undefined): string {
  const focus = (selectedNode ?? "").trim();
  if (!focus) return question;
  if (!DEICTIC_RE.test(question)) return question; // case-wide / non-deictic question — the selection is irrelevant
  return (
    `The analyst has the entity "${focus}" selected on the graph and the question likely refers to it. ` +
    `Resolve "this" / "it" / "that node" / "here" to "${focus}". If the question is actually about the whole ` +
    `case, answer case-wide instead. Question: ${question}`
  );
}
export interface QaAnswer {
  answer: string;
  sources: GroundingSource[];
  // A5 (ask.py): coverage report (full vs partial/sweep) + deterministic citation faithfulness — the
  // analyst is told when grounding was partial AND which answer sentences cite a fact the run doesn't hold.
  coverage: GroundingCoverage;
  unsupportedCitations: UnsupportedCitation[];
}

const QA_SWEEP_BATCH_CAP = 8; // A5: bound the map-reduce sweep to the FIRST N batches (vault iteration
// order; the web has no relevance ranking to prefer a prefix) — when it bites, coverage reports partial
// (used < total) so the cap is never silent. No runaway spend (codex: comment now matches the behavior).

/**
 * Answer a question about the current case from the vault's run findings/leads ONLY (D2/D9).
 * Key hygiene is the SAME as runInvestigation/generateBrief: the live key is redacted from the
 * built EVIDENCE context, the question, the cited sources, AND the model output. A case with no
 * evidence returns the deterministic "I don't know from this case" answer WITHOUT a model call
 * (no key required, no spend). Only `run:` records feed grounding — briefs, pivots, and the
 * reserved secret: namespace are never read into the context (buildGroundingContext drops them).
 */
export async function answerQuestion(vault: Vault, question: string, opts?: AnswerOpts): Promise<QaAnswer> {
  let allKeys: string[];
  try {
    allKeys = vault.keys();
  } catch {
    throw new SessionError("Unlock your vault to ask questions about the case.");
  }
  const entries: VaultEntry[] = [];
  for (const k of allKeys) {
    if (!k.startsWith(RUN_PREFIX)) continue; // only run: records are evidence
    try {
      entries.push({ key: k, value: vault.get(k) });
    } catch {
      /* unreadable record: skip */
    }
  }

  const context = buildGroundingContext(entries);
  if (!context.hasEvidence) {
    return { answer: NO_EVIDENCE_ANSWER, sources: [], coverage: context.coverage, unsupportedCitations: [] };
  }

  const key = currentKeyOrNull(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to ask grounded questions.");

  const client = new AnthropicClient(key, opts?.fetchImpl);
  const safeQuestion = redactProjectionText(vault, focusedQuestionFor(question, opts?.selectedNode));
  // Statelessness fix (founder 2026-07-03): the recent turns ride into the prompt so follow-ups resolve.
  const safeHistory = safeHistoryFor(vault, opts?.history);
  // Conclusions routing (deterministic regex, unit-tested in answer.test.ts): "what are the conclusions /
  // summarize / where do we stand" gets the SYNTHESIS voice — the connected picture, not a per-fact answer.
  const persona = isConclusionsQuestion(question) ? SYNTHESIS_PERSONA : GROUNDING_PERSONA;
  // scope-injection (founder 2026-07-07): the saved case scope frames every answer, the same way it frames
  // the whole-case ▶ run (buildCaseTask). Absent before, so a question ignored the analyst's objective.
  // Stored already-redacted (recordScope); redact again defensively before it reaches the wire.
  const safeScope = redactProjectionText(vault, getTradecraft(vault, "scope")?.content?.trim() ?? "");

  // A5: a case bigger than the single-shot cap is SWEPT (map-reduce over the whole case), never silently
  // truncated to the first 80 (ask.py:_single_shot vs _sweep). Small/medium cases stay single-shot.
  const { answer, sources, coverage } =
    context.coverage.mode === "partial"
      ? await sweepAnswer(vault, client, entries, safeQuestion, persona, safeHistory, opts, safeScope)
      : await singleShotAnswer(vault, client, context.text, context.sources, context.coverage, safeQuestion, persona, safeHistory, opts, safeScope);

  // deterministic citation faithfulness over the (redacted) answer + the sources it could cite.
  const unsupportedCitations = verifyCitations(answer, sources);
  return { answer: answer.trim() || NO_EVIDENCE_ANSWER, sources, unsupportedCitations, coverage };
}

/** Single-shot Q&A: the whole case fit the window — one grounded call (ask.py:_single_shot). */
async function singleShotAnswer(
  vault: Vault, client: AnthropicClient, contextText: string, sources: GroundingSource[],
  coverage: GroundingCoverage, safeQuestion: string, persona: string, safeHistory: QaTurn[], opts?: AnswerOpts,
  safeScope = "",
): Promise<{ answer: string; sources: GroundingSource[]; coverage: GroundingCoverage }> {
  const safeContext = redactProjectionText(vault, contextText);
  const { text } = await client.complete({
    system: persona,
    messages: [{ role: "user", content: buildQaPrompt(safeContext, safeQuestion, safeHistory, safeScope) }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? 1024,
    signal: opts?.signal,
  });
  return {
    answer: redactProjectionText(vault, text),
    sources: redactProjectionDeep(vault, sources),
    coverage,
  };
}

/**
 * Map-reduce sweep (ask.py:_sweep): too big for one window, so MAP each batch (a cheap extract of the
 * question-relevant facts, citations kept) → REDUCE (compose the answer from the extracts). Reads the
 * WHOLE case up to QA_SWEEP_BATCH_CAP batches; coverage reports how much was swept + whether capped.
 */
async function sweepAnswer(
  vault: Vault, client: AnthropicClient, entries: VaultEntry[], safeQuestion: string, persona: string,
  safeHistory: QaTurn[], opts?: AnswerOpts, safeScope = "",
): Promise<{ answer: string; sources: GroundingSource[]; coverage: GroundingCoverage }> {
  const batches = buildGroundingBatches(entries);
  const run = batches.slice(0, QA_SWEEP_BATCH_CAP);
  const total = batches.reduce((n, b) => n + b.sources.length, 0);
  const sweptSources = run.flatMap((b) => b.sources);

  const extracts: string[] = [];
  for (const batch of run) {
    const safeText = redactProjectionText(vault, batch.text);
    const { text } = await client.complete({
      system: GROUNDING_MAP_PERSONA,
      messages: [{ role: "user", content: buildMapPrompt(safeText, safeQuestion) }],
      kind: "classify", // the cheap extract pass
      maxTokens: 600,
      signal: opts?.signal,
    });
    const extract = redactProjectionText(vault, text).trim();
    if (extract && extract.toUpperCase() !== "NONE") extracts.push(extract);
  }

  // REDUCE: the extracted, still-cited facts ARE the evidence for the final grounded answer.
  const reduceEvidence = extracts.join("\n\n") || "(no relevant facts found while sweeping the case)";
  // history rides only in the REDUCE call — the MAP passes are question-scoped fact extraction.
  const { text } = await client.complete({
    system: persona,
    messages: [{ role: "user", content: buildQaPrompt(redactProjectionText(vault, reduceEvidence), safeQuestion, safeHistory, safeScope) }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? 1024,
    signal: opts?.signal,
  });
  return {
    answer: redactProjectionText(vault, text),
    sources: redactProjectionDeep(vault, sweptSources),
    // swept the whole case unless the batch cap bit (then it's partial — and SAID so, never silent).
    coverage: { mode: batches.length > run.length ? "partial" : "full", total, used: sweptSources.length },
  };
}

// ---- cd-tradecraft (chat-graph-parity-fixes): Scope/Challenge/Premortem gates over the case ----
// Ported from investigations/tradecraft.py. State is a per-case `tradecraft:<step>` vault DATA key
// (auto case-scoped by the scoped-vault chokepoint). Scope captures analyst INPUT (no model call);
// Challenge/Premortem run a bounded no-tools model pass over the case findings + store the result.
// SAME key hygiene as answerQuestion: the live key is redacted from the EVIDENCE, the prompt, and the
// model OUTPUT. A gate is "done" when its artifact exists (the soft brief nudge reads this).

const TRADECRAFT_PREFIX = "tradecraft:";

/** One stored tradecraft artifact (the gate output or the scope framing) + when it last ran. */
export interface TradecraftRecord {
  step: TradecraftStep;
  content: string;
  when: number; // epoch ms
}

/** Read one tradecraft artifact, or null. Key-redacted defensively on the way out. */
export function getTradecraft(vault: Vault, step: TradecraftStep): TradecraftRecord | null {
  let rec: unknown;
  try {
    rec = vault.get(`${TRADECRAFT_PREFIX}${step}`);
  } catch {
    return null;
  }
  if (!rec || typeof rec !== "object") return null;
  const r = rec as { content?: unknown; when?: unknown };
  if (typeof r.content !== "string") return null;
  return { step, content: redactProjectionText(vault, r.content), when: typeof r.when === "number" ? r.when : 0 };
}

/** The per-case checklist: every step + a done flag + when it last ran (mirrors tradecraft.state). */
export function tradecraftState(vault: Vault): { step: TradecraftStep; kind: TradecraftKind; done: boolean; when: number }[] {
  return TRADECRAFT_STEPS.map((s) => {
    const rec = getTradecraft(vault, s.key);
    return { step: s.key, kind: s.kind, done: !!rec, when: rec?.when ?? 0 };
  });
}

/** Gate steps not yet run — drives the soft brief nudge (mirrors tradecraft.unmet_gates). */
export function unmetTradecraftGates(vault: Vault): TradecraftStep[] {
  return TRADECRAFT_GATE_KEYS.filter((k) => !getTradecraft(vault, k));
}

// hydra ISSUE-2 (durability, founder 2026-07-07): AWAIT + return the put. This was fire-and-forget
// (`: void`, un-awaited vault.put) so scope + gate results updated the in-memory doc but raced the durable
// write — a reload read `null`. Reproduced in tests/chat/scope-persist.repro.test.ts. Callers now await.
async function putTradecraft(vault: Vault, step: TradecraftStep, content: string): Promise<void> {
  return vault.put(`${TRADECRAFT_PREFIX}${step}`, { content, when: Date.now() });
}

/** Capture (or refresh) the case Scope framing — analyst input, NO model call. Stored case-scoped. */
export async function recordScope(vault: Vault, scope: { question: string; hypotheses?: string; proof?: string }): Promise<TradecraftRecord> {
  const question = (scope.question || "").trim();
  if (!question) throw new SessionError("Scope needs a question to frame the case.");
  const parts = [
    `Question: ${question}`,
    scope.hypotheses?.trim() ? `Hypotheses: ${scope.hypotheses.trim()}` : null,
    scope.proof?.trim() ? `What counts as proof: ${scope.proof.trim()}` : null,
  ].filter(Boolean);
  const content = redactProjectionText(vault, parts.join("\n")); // redact defensively (analyst could paste a key)
  await putTradecraft(vault, "scope", content); // await: the durable write must land before saveScope proceeds
  return { step: "scope", content, when: Date.now() };
}

/** The saved Scope parsed back into the 3 form fields, or null when no scope is set. Lets the chat's Scope
 *  form RE-HYDRATE on open — before this it always opened blank, so a saved scope read as "didn't persist"
 *  (founder 2026-07-07). Parses the labeled lines recordScope wrote (form inputs are single-line, so a
 *  prefix split is exact). Pure read; redact-on-read for defense-in-depth. */
export function getScopeFields(vault: Vault): { question: string; hypotheses: string; proof: string } | null {
  const content = getTradecraft(vault, "scope")?.content?.trim();
  if (!content) return null;
  const safe = redactProjectionText(vault, content);
  const out = { question: "", hypotheses: "", proof: "" };
  for (const line of safe.split("\n")) {
    const t = line.trim();
    if (t.startsWith("Question:")) out.question = t.slice("Question:".length).trim();
    else if (t.startsWith("Hypotheses:")) out.hypotheses = t.slice("Hypotheses:".length).trim();
    else if (t.startsWith("What counts as proof:")) out.proof = t.slice("What counts as proof:".length).trim();
  }
  return out.question ? out : null;
}

/**
 * Run the Challenge or Premortem gate over the case's current findings (mirrors tradecraft.run_analysis).
 * A bounded no-tools model pass; the evidence pack is the SAME grounding the Q&A uses. Returns the stored
 * record, or throws SessionError (locked / no key / no evidence). Key-redacted IN (evidence + prompt) and
 * OUT (model output). READ-of-runs + single WRITE of `tradecraft:<step>`.
 */
export async function runTradecraftGate(
  vault: Vault,
  step: "challenge" | "premortem",
  opts?: AnswerOpts,
): Promise<TradecraftRecord> {
  let allKeys: string[];
  try {
    allKeys = vault.keys();
  } catch {
    throw new SessionError("Unlock your vault to run a tradecraft gate.");
  }
  const entries: VaultEntry[] = [];
  for (const k of allKeys) {
    if (!k.startsWith(RUN_PREFIX)) continue;
    try {
      entries.push({ key: k, value: vault.get(k) });
    } catch {
      /* unreadable record: skip */
    }
  }
  const context = buildGroundingContext(entries);
  if (!context.hasEvidence) {
    throw new SessionError("No findings yet — investigate something first, then run the gate over what landed.");
  }
  // ch-gate-floor (controls-honesty / sp-2a98dc39): hasEvidence is true for ANY finding OR lead — including
  // a single stray thin lead with no finished investigator run. Running challenge/premortem over that
  // produced weak generic boilerplate ("evidence contains no dates…") the founder read as the gate lying.
  // The honest floor: a gate only runs once the case is substantively investigated (>=1 finished agent run
  // OR >=1 promoted finding). A thin-leads-only case gets a plain "not investigated yet" message and NO
  // model call. The HARD tradecraft floor (promotion gate / evidence tiers) is unchanged — this gates the
  // gate's INPUT, not its logic.
  if (!isInvestigated(entries)) {
    throw new SessionError(
      `This case hasn't been investigated yet — nothing substantive to ${step} yet. ` +
        "Run `investigate <target>` first (an uploaded report counts once Process turns it into findings), " +
        "then re-run the gate.",
    );
  }
  const key = currentKeyOrNull(vault);
  if (!key) throw new SessionError("Add your Anthropic API key to run a tradecraft gate.");

  const safeEvidence = redactProjectionText(vault, context.text);
  const system = step === "challenge" ? CHALLENGE_SYSTEM : PREMORTEM_SYSTEM;
  // scope-injection (founder 2026-07-07): the Challenge / Premortem gates pressure-tested the findings but
  // never saw the analyst's scope, so they judged against a frame they couldn't read. Name it first so the
  // gate tests the case AGAINST the question it was scoped to answer.
  const safeScope = redactProjectionText(vault, getTradecraft(vault, "scope")?.content?.trim() ?? "");
  const scopeFrame = safeScope ? `Analyst scope / objective:\n${safeScope}\n\n` : "";
  const prompt = `${scopeFrame}Current findings + graph:\n${safeEvidence}\n\nNow produce the ${step} analysis.`;
  const client = new AnthropicClient(key, opts?.fetchImpl);
  const { text } = await client.complete({
    system,
    messages: [{ role: "user", content: prompt }],
    kind: "judgment",
    maxTokens: opts?.maxTokens ?? 1200,
  });
  const content = redactProjectionText(vault, text).trim();
  if (!content) throw new SessionError("The gate returned an empty analysis — try again.");
  await putTradecraft(vault, step, content); // await: the gate ✓ done-state must survive a reload (hydra ISSUE-2)
  return { step, content, when: Date.now() };
}

export interface ExpandOpts {
  fetchImpl?: FetchLike;
  toolOpts?: OsintOpts;
  signal?: AbortSignal;
  onStep?: (step: Step) => void;
  maxTurns?: number;
  maxOutputTokens?: number;
}

/**
 * Expand `fromNodeId` by one hop: run the agent on `fromEntity` and merge the result into
 * `baseModel`. Two safety properties (codex-1, codex-2-adjacent):
 *  - NO-PERSIST: the expansion does not write a run:<entity> vault record, so a key echoed
 *    in the entity/steps can never be read back via __kipi.getCase.
 *  - KEY-REDACTED: the live key is stripped from the result BEFORE the merge, so neither the
 *    merged model nor __kipi.graphModel() ever sees it.
 */
export async function expandFromNode(
  vault: Vault,
  fromEntity: string,
  baseModel: GraphModel,
  fromNodeId: string,
  opts?: ExpandOpts,
): Promise<GraphModel> {
  const result = await runInvestigation({
    vault,
    objective: fromEntity,
    persist: false, // codex-1: no run:<entity> record
    fetchImpl: opts?.fetchImpl,
    toolOpts: opts?.toolOpts,
    signal: opts?.signal,
    onStep: opts?.onStep,
    maxTurns: opts?.maxTurns,
    maxOutputTokens: opts?.maxOutputTokens ?? getCaseBudget(vault), // D3 finding-6: same up-front per-case ceiling
  });
  const safeResult = redactProjectionDeep(vault, result);
  return finalizeModel(vault, mergeGraphModel(baseModel, fromNodeId, safeResult)); // D10 + pf-process D4 + ca-analyze clusters
}

// ---- en-session: BYO-key enrichment — run a keyed provider DIRECT, gate, land as a run: record ----

/** A per-provider hard cap on entities folded into one enrich run (codex D7): the adapters already
 *  slice their result lists, this bounds the total even across a multi-field response. */
const MAX_ENRICH_ENTITIES = 200;
export const ENRICH_SOURCE_KIND = "enrich";

export interface ProviderStatusRow {
  id: string;
  label: string;
  blurb: string;
  category: string;
  docsUrl: string;
  keyHint: string;
  targets: string[];
  configured: boolean;
  /** Where the key lives — the client only ever has the vault, so "db" (saved locally) or "none". The
   *  server's "env" source has no client analog (keys never live in env on the client). */
  keySource: "db" | "none";
  /** Key-acquisition guidance (KEY_GUIDANCE) surfaced on the card: whether the key is required or only
   *  lifts the rate limit, the token-creation page, and one-line steps. Founder 2026-07-09. */
  keyRequired: boolean;
  keyUrl: string;
  keySteps: string;
}
export interface BlockedProviderRow {
  id: string;
  label: string;
}
export interface ProvidersView {
  providers: ProviderStatusRow[];
  blocked: BlockedProviderRow[];
}

/** The per-provider status for the Keys & providers UI: the six CORS-open providers with their
 *  configured flag + the blocked holdouts (label only). Read-only; carries NO secret value. */
export function providerStatus(vault: Vault): ProvidersView {
  return {
    providers: ENRICH_PROVIDERS.map((p) => {
      const configured = hasProviderKey(vault, p.id);
      return {
        id: p.id,
        label: p.label,
        blurb: p.blurb,
        category: p.category,
        docsUrl: p.docsUrl,
        keyHint: p.keyHint,
        targets: [...p.targets],
        configured,
        keySource: configured ? ("db" as const) : ("none" as const),
        keyRequired: KEY_GUIDANCE[p.id].required,
        keyUrl: KEY_GUIDANCE[p.id].url,
        keySteps: KEY_GUIDANCE[p.id].steps,
      };
    }),
    blocked: BLOCKED_PROVIDERS.map((b) => ({ id: b.id, label: b.label })),
  };
}

export interface EnrichOpts {
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
  retries?: number;
}
export interface EnrichResult {
  count: number;
  objective: string;
  provider: string;
  tier: string;
}

/**
 * Enrich `target` with provider `id`: read the provider key from the vault, fetch the provider DIRECT
 * (the user's key in the provider's auth slot), and land the result as a SANITIZED `run:` record
 * through the EXISTING vault.put chokepoint (NO new write path — createWritable stays solely in
 * src/vault/store.ts). Gate fidelity (codex D1): the provider result is treated as ONE infra
 * observation and the grade-bearing counts are DERIVED via the existing `attributeFindings` machinery
 * (NOT hardcoded), then `promotionGate` runs — so a single provider corroboration is grade B
 * (single infra source), exactly like a single DNS lookup in the agent loop, and an entity the
 * provider did not return attributes to 0. Key hygiene (codex D2/D3): every configured secret (and
 * its encoded / base64 / id:secret-half forms) is redacted out of the TARGET before the objective —
 * and therefore the vault key — is formed, and out of the whole record before the write.
 */
export async function enrichTarget(vault: Vault, id: string, target: string, opts?: EnrichOpts): Promise<EnrichResult> {
  const provider = enrichProvider(id);
  if (!provider) throw new SessionError(`Unknown provider "${id}".`);
  const key = getProviderKey(vault, id); // throws SessionError if the vault is locked
  if (!key) throw new SessionError(`Add your ${provider.label} key to enrich.`);

  const cleanTarget = target.trim();
  if (!cleanTarget) throw new SessionError("Enter a target to enrich.");

  const result = await provider.run(cleanTarget, key, {
    fetchImpl: opts?.fetchImpl,
    signal: opts?.signal,
    retries: opts?.retries,
  });

  // D1: re-gate via the SAME path the agent loop uses — admission, then attribution over the real
  // provider observation, then the promotion gate. No hardcoded count.
  const admitted = result.entities.filter((e) => isAdmissible(e.type, e.value)[0]).slice(0, MAX_ENRICH_ENTITIES);
  const observed: Observed[] = [
    { provider: result.provider, infra: true, entities: admitted.map((e) => ({ type: e.type, value: e.value })) },
  ];
  const rawFindings: Finding[] = admitted.map((e) => ({ entity: e.value, entity_type: e.type, confidence: "medium" }));
  const findings = attributeFindings(rawFindings, observed);

  const promoted: Finding[] = [];
  const leads: { finding: Finding; verdict: GateVerdict }[] = [];
  for (const f of findings) {
    const verdict = promotionGate(f);
    if (verdict.promote) promoted.push(f);
    else leads.push({ finding: f, verdict });
  }

  // D2: redact every configured secret out of the target BEFORE it becomes part of the vault key.
  const forms = configuredSecretForms(vault);
  const safeTarget = redactForms(cleanTarget, forms) || "target";
  const objective = `enrich: ${provider.id} ${safeTarget}`;
  const record = {
    objective,
    steps: [],
    promoted,
    leads,
    usage: { input: 0, output: 0 },
    stopReason: ENRICH_SOURCE_KIND,
    sourceKind: ENRICH_SOURCE_KIND, // a non-forgeable discriminator (parity with FILE_SOURCE_KIND)
    provider: provider.id,
    tier: result.tier,
    target: safeTarget, // the redacted target — drives the Recent-runs table "target" column
    at: new Date().toISOString(), // when the run landed — the Recent-runs "When" column
  };
  const safeRecord = redactFormsDeep(record, forms); // D2/D3: no secret form is ever persisted
  try {
    await vault.put(`run:${objective}`, safeRecord); // the ONE write path (single-writer preserved)
  } catch {
    throw new SessionError("Unlock your vault to save enrichment.");
  }
  return { count: promoted.length + leads.length, objective, provider: provider.id, tier: result.tier };
}

// ---- pb-proxy: the user-owned Cloudflare-Worker tier for the CORS-blocked providers ----

const WORKER_URL_KEY = "setting:worker_url";

/** Save the user's Cloudflare Worker URL (validated to https://<sub>.workers.dev — codex D1). It is the
 *  ONLY value the client stores for the proxy tier; the provider keys live in the worker (codex D3). */
export async function setWorkerUrl(vault: Vault, url: string): Promise<void> {
  const clean = (url ?? "").trim();
  if (!isValidWorkerUrl(clean)) throw new SessionError("Enter a valid https://<name>.workers.dev URL.");
  try {
    await vault.put(WORKER_URL_KEY, { url: clean });
  } catch {
    throw new SessionError("Unlock your vault to save the worker URL.");
  }
}
export function getWorkerUrl(vault: Vault): string | null {
  try {
    const v = vault.get(WORKER_URL_KEY);
    if (v && typeof v === "object" && typeof (v as { url?: unknown }).url === "string") return (v as { url: string }).url;
  } catch {
    /* locked or unset */
  }
  return null;
}

// ob-tour: the first-run onboarding flag — a key-safe session chokepoint over `setting:onboarded`
// (same shape as the worker URL). isProtectedKey denies `setting:` via the debug bridge, so the
// flag is not forgeable; the UI reads/writes ONLY through these two functions.
const ONBOARDED_KEY = "setting:onboarded";

/** Mark the first-run tour as seen (per-vault). Single-writer through the existing vault.put. */
export async function setOnboarded(vault: Vault): Promise<void> {
  try {
    await vault.put(ONBOARDED_KEY, { seen: true });
  } catch {
    throw new SessionError("Unlock your vault to dismiss onboarding.");
  }
}

/** True once the user has dismissed the first-run tour. False on a fresh OR locked vault (never throws). */
export function getOnboarded(vault: Vault): boolean {
  try {
    const v = vault.get(ONBOARDED_KEY);
    return !!(v && typeof v === "object" && (v as { seen?: unknown }).seen === true);
  } catch {
    return false; // locked or unset
  }
}

/**
 * Enrich a target through the user's worker (a CORS-blocked provider, tier T2). Requires a configured
 * worker. The proxied response is gated by the SAME admission + attributeFindings + promotionGate path as
 * enrichTarget (codex D4 — a hostile worker's forged counts are stripped) and persisted as a sanitized
 * run: record through the EXISTING vault.put (NO new createWritable).
 */
export async function enrichViaProxy(vault: Vault, id: string, target: string, opts?: EnrichOpts): Promise<EnrichResult> {
  const workerUrl = getWorkerUrl(vault);
  if (!workerUrl) throw new SessionError("Configure your Cloudflare Worker URL (Enrich) to use the proxy tier.");
  const provider = proxiedProvider(id);
  if (!provider) throw new SessionError(`Unknown proxied provider "${id}".`);
  const cleanTarget = target.trim();
  if (!cleanTarget) throw new SessionError("Enter a target to enrich.");

  const result = await runProxiedProvider(id, cleanTarget, workerUrl, {
    fetchImpl: opts?.fetchImpl,
    signal: opts?.signal,
    retries: opts?.retries,
  });

  // D4: re-gate exactly like enrichTarget — admission, attribution over the real observation, the gate.
  const admitted = result.entities.filter((e) => isAdmissible(e.type, e.value)[0]).slice(0, MAX_ENRICH_ENTITIES);
  const observed: Observed[] = [{ provider: result.provider, infra: true, entities: admitted.map((e) => ({ type: e.type, value: e.value })) }];
  const rawFindings: Finding[] = admitted.map((e) => ({ entity: e.value, entity_type: e.type, confidence: "medium" }));
  const findings = attributeFindings(rawFindings, observed);
  const promoted: Finding[] = [];
  const leads: { finding: Finding; verdict: GateVerdict }[] = [];
  for (const f of findings) {
    const verdict = promotionGate(f);
    if (verdict.promote) promoted.push(f);
    else leads.push({ finding: f, verdict });
  }

  const forms = configuredSecretForms(vault);
  const safeTarget = redactForms(cleanTarget, forms) || "target";
  const objective = `enrich: ${id} ${safeTarget}`;
  const record = {
    objective,
    steps: [],
    promoted,
    leads,
    usage: { input: 0, output: 0 },
    stopReason: ENRICH_SOURCE_KIND,
    sourceKind: ENRICH_SOURCE_KIND,
    provider: id,
    tier: result.tier,
    target: safeTarget, // parity with enrichTarget — the Recent-runs "target" column / modal
    at: new Date().toISOString(), // the Recent-runs "When" column
  };
  const safeRecord = redactFormsDeep(record, forms);
  try {
    await vault.put(`run:${objective}`, safeRecord); // the ONE write path (single-writer preserved)
  } catch {
    throw new SessionError("Unlock your vault to save enrichment.");
  }
  return { count: promoted.length + leads.length, objective, provider: id, tier: result.tier };
}

// ---- nd-transform: per-node deterministic OSINT transforms (no LLM, no persist, grow the graph) ----

/** Per-transform cap on adapter output before gate/merge/grow (codex D13). */
export const MAX_TRANSFORM_ENTITIES = 60;

interface FreeTransform {
  tool: string; // the OSINT_TOOLS name
  param: string; // the tool's input field
  label: string;
  type: string; // the node surface type it applies to
}
const FREE_TRANSFORMS: Record<string, FreeTransform> = {
  dns: { tool: "dns_lookup", param: "domain", label: "DNS records", type: "domain" },
  rdap: { tool: "rdap_domain", param: "domain", label: "RDAP / whois", type: "domain" },
  crtsh: { tool: "crtsh_subdomains", param: "domain", label: "crt.sh subdomains", type: "domain" },
  btc: { tool: "btc_address", param: "address", label: "BTC on-chain", type: "wallet" },
};
/** The keyless transforms offered per node surface type. */
export const TRANSFORMS_BY_TYPE: Record<string, string[]> = {
  domain: ["dns", "rdap", "crtsh"],
  wallet: ["btc"],
};
// A BTC address (base58 1.../3... or bech32 bc1...) — the btc transform's value validator (D2), since
// validateTarget's "wallet" kind is the ETH 0x-40-hex form (Etherscan), not BTC.
const BTC_RE = /^(bc1[a-z0-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/;

const normVal = (s: string): string => s.trim().toLowerCase();

function freeTransformValid(transformId: string, value: string): boolean {
  if (transformId === "btc") return BTC_RE.test(value.trim());
  return validateTarget("domain", value); // dns / rdap / crtsh
}

export interface TransformOption {
  id: string;
  label: string;
  keyed: boolean;
}

/**
 * The OSINT transforms applicable to a node of (type, value) (codex D2 — value-aware): the keyless
 * transforms for the type whose value validates, plus every keyed enrich provider whose key is
 * configured AND whose target kind matches the node type AND validates the value. An honest empty list
 * is the correct answer for, e.g., a keyless ip node.
 */
export function availableTransforms(vault: Vault, type: string, value: string): TransformOption[] {
  const out: TransformOption[] = [];
  for (const id of TRANSFORMS_BY_TYPE[type] ?? []) {
    if (freeTransformValid(id, value)) out.push({ id, label: FREE_TRANSFORMS[id].label, keyed: false });
  }
  for (const p of ENRICH_PROVIDERS) {
    if (!hasProviderKey(vault, p.id)) continue;
    if (!p.targets.some((k) => k === type && validateTarget(k, value))) continue;
    out.push({ id: `enrich:${p.id}`, label: p.label, keyed: true });
  }
  return out;
}

/**
 * Run ONE deterministic transform on a node and return a GATED, REDACTED InvestigateResult — WITHOUT
 * persisting (like the agent one-hop expand). The queried node (self — derived from the original value
 * AND outcome.queryEcho, codex D3) is excluded from the findings, so a transform never re-adds its own
 * source. Entities are admitted + capped (D13), attributed via the SAME attributeFindings machinery
 * (D5 — counts are derived, not forged), and gated by promotionGate. Key hygiene (codex D8): an error
 * surfaces ONLY as a sanitized SessionError (never outcome.content or a query-auth URL), and the result
 * is redactProjectionDeep'd before it leaves the session.
 */
export async function transformNode(
  vault: Vault,
  type: string,
  value: string,
  transformId: string,
  opts?: EnrichOpts,
): Promise<InvestigateResult> {
  const cleanValue = value.trim();
  if (!cleanValue) throw new SessionError("No value to transform.");
  const osintOpts: OsintOpts = { fetchImpl: opts?.fetchImpl, signal: opts?.signal, retries: opts?.retries };

  let outcome: ToolOutcome;
  if (transformId.startsWith("enrich:")) {
    const id = transformId.slice("enrich:".length);
    const provider = enrichProvider(id);
    if (!provider) throw new SessionError("Unknown transform.");
    if (!hasProviderKey(vault, id)) throw new SessionError(`Add your ${provider.label} key to run this transform.`);
    if (!provider.targets.some((k) => validateTarget(k, cleanValue))) {
      throw new SessionError(`This value is not a valid ${provider.label} target.`);
    }
    outcome = await runEnrichTool(`enrich_${id}`, { target: cleanValue }, (i) => getProviderKey(vault, i), osintOpts);
  } else {
    const free = FREE_TRANSFORMS[transformId];
    if (!free || free.type !== type) throw new SessionError("Unknown transform for this node.");
    if (!freeTransformValid(transformId, cleanValue)) throw new SessionError(`This value is not a valid ${free.label} target.`);
    outcome = await defaultRunTool(free.tool, { [free.param]: cleanValue }, osintOpts);
  }

  if (outcome.is_error) throw new SessionError("The transform returned no usable result."); // D8: never echo outcome.content

  // self = the queried node value (D3: free tools have no queryEcho) AND outcome.queryEcho.
  const self = new Set<string>([normVal(cleanValue)]);
  if (outcome.queryEcho) self.add(normVal(outcome.queryEcho));

  const admitted = outcome.entities
    .filter((e) => isAdmissible(e.type, e.value)[0] && !self.has(normVal(e.value)))
    .slice(0, MAX_TRANSFORM_ENTITIES);
  const observed: Observed[] = [
    { provider: outcome.provider ?? transformId, infra: outcome.infra ?? true, entities: admitted.map((e) => ({ type: e.type, value: e.value })) },
  ];
  const rawFindings: Finding[] = admitted.map((e) => ({ entity: e.value, entity_type: e.type, confidence: "medium" }));
  const findings = attributeFindings(rawFindings, observed);
  const promoted: Finding[] = [];
  const leads: { finding: Finding; verdict: GateVerdict }[] = [];
  for (const f of findings) {
    const verdict = promotionGate(f);
    if (verdict.promote) promoted.push(f);
    else leads.push({ finding: f, verdict });
  }
  // worked:true — a transform reaching here ran its tool successfully (an error throws at D8 above), so
  // even a zero-entity transform is a genuine clean result, never a degraded no-work (sp-2c870c26).
  const result: InvestigateResult = { steps: [], promoted, leads, relationships: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", worked: true };
  return redactProjectionDeep(vault, result); // D8: no secret form leaves the session
}

export interface EnrichRunRow {
  objective: string;
  provider: string;
  count: number;
  /** The redacted target the run was for (Recent-runs "target" column). Falls back to the objective tail. */
  target: string;
  /** Only successfully-landed runs are persisted as records, so the client status is always "success"
   *  (a transient provider error shows in the per-provider lastResult, it is never persisted). */
  status: "success";
  /** ISO timestamp of when the run landed, or "" for legacy records written before the field existed. */
  at: string;
  /** The promoted-or-held entity labels surfaced by the run (the "entity" column / modal seed). */
  entities: string[];
}

type EnrichRecord = Partial<RunRecord> & { sourceKind?: string; provider?: string; target?: string; at?: string };

function readEnrichRecord(vault: Vault, objective: string): EnrichRecord | null {
  let rec: EnrichRecord = {};
  try {
    const v = vault.get(`${RUN_PREFIX}${objective}`);
    if (v && typeof v === "object") rec = v as EnrichRecord;
  } catch {
    return null;
  }
  if (rec.sourceKind !== ENRICH_SOURCE_KIND) return null;
  return rec;
}

function enrichEntityLabels(rec: EnrichRecord): string[] {
  const promoted = Array.isArray(rec.promoted) ? rec.promoted : [];
  const leads = Array.isArray(rec.leads) ? rec.leads : [];
  // guard every shape: a malformed/legacy record may have a finding-less lead (codex robustness MINOR).
  return [...promoted.map((f) => f?.entity), ...leads.map((l) => l?.finding?.entity)].filter((e): e is string => typeof e === "string");
}

/** The enrichment run records (sourceKind === 'enrich'), key-redacted via objectivesUnder. Newest first
 *  (by `at`, then objective) so the Recent-runs table reads top-down like the original. */
export function listEnrichRuns(vault: Vault): EnrichRunRow[] {
  const out: EnrichRunRow[] = [];
  for (const objective of objectivesUnder(vault, RUN_PREFIX)) {
    const rec = readEnrichRecord(vault, objective);
    if (!rec) continue;
    const entities = enrichEntityLabels(rec);
    // legacy records have no `target` field — derive it from `enrich: <provider> <target>`.
    const tail = objective.replace(/^enrich:\s*\S+\s*/, "");
    out.push({
      objective,
      provider: typeof rec.provider === "string" ? rec.provider : "?",
      count: entities.length,
      target: typeof rec.target === "string" && rec.target ? rec.target : tail || objective,
      status: "success",
      at: typeof rec.at === "string" ? rec.at : "",
      entities,
    });
  }
  return out.sort((a, b) => (b.at || "").localeCompare(a.at || "") || a.objective.localeCompare(b.objective));
}

export interface EnrichStats {
  runCount: number;
  distinctEntities: number;
}

/** Stats-header summary: how many enrich runs landed + how many distinct entities they surfaced. No $
 *  (founder 2026-06-18: the BYO-key client never meters cost — the provider bills the user directly). */
export function enrichStats(vault: Vault): EnrichStats {
  const runs = listEnrichRuns(vault);
  const distinct = new Set<string>();
  for (const r of runs) for (const e of r.entities) distinct.add(e.toLowerCase());
  return { runCount: runs.length, distinctEntities: distinct.size };
}

export interface EnrichRunFinding {
  entity: string;
  entityType: string;
  grade: string;
  status: "promoted" | "lead";
}
export interface EnrichRunDetail {
  objective: string;
  provider: string;
  target: string;
  findings: EnrichRunFinding[];
}

/** The full detail for one enrich run (the Run-detail modal): its extracted findings (promoted + held). */
export function getEnrichRunDetail(vault: Vault, objective: string): EnrichRunDetail | null {
  const rec = readEnrichRecord(vault, objective);
  if (!rec) return null;
  const promoted = (Array.isArray(rec.promoted) ? rec.promoted : []).filter((f) => f && typeof f.entity === "string");
  const leads = (Array.isArray(rec.leads) ? rec.leads : []).filter((l) => l?.finding && typeof l.finding.entity === "string");
  const findings: EnrichRunFinding[] = [
    ...promoted.map((f) => ({ entity: f.entity, entityType: f.entity_type, grade: f.grade ?? "?", status: "promoted" as const })),
    ...leads.map((l) => ({ entity: l.finding.entity, entityType: l.finding.entity_type, grade: l.finding.grade ?? "?", status: "lead" as const })),
  ];
  const tail = objective.replace(/^enrich:\s*\S+\s*/, "");
  return {
    objective,
    provider: typeof rec.provider === "string" ? rec.provider : "?",
    target: typeof rec.target === "string" && rec.target ? rec.target : tail || objective,
    findings,
  };
}
