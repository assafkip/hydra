// PRD-2: the manual agentic loop. Drives the Messages API tool-use cycle in the
// browser (tool_use -> run tools -> tool_result -> repeat until end_turn), builds an
// ordered step trail, and runs every emitted finding through attribution + the gate
// before returning it. Cancellable via AbortSignal; bounded by maxTurns + an output-
// token budget so it can never run unbounded spend on the user's key.

import type { AnthropicClient, ContentBlock, Message, ToolDef } from "../llm/client.js";
import type { OsintOpts } from "../osint/types.js";
import { OSINT_TOOLS, runTool as defaultRunTool, type ToolOutcome } from "./tools.js";
import { attributeFindings, promotionGate, type Finding, type GateVerdict, type Observed } from "./gate.js";
import { PERSONA } from "./persona.js";

export interface Step {
  kind: "reasoning" | "tool";
  text?: string;
  tool?: string;
  input?: unknown;
  result?: string;
  isError?: boolean;
}

/** kweb-live-graph: a successful tool's observed entities, surfaced LIVE so the graph can grow as the
 *  agent digs. The target + entity VALUES are already secret-redacted (the same egress cut as the trail). */
export interface ObservedEvent {
  tool: string;
  target: string; // the queried value this tool worked (domain/ip/handle/…)
  entities: { type: string; value: string; self?: boolean }[];
}

export type StopReason = "end_turn" | "budget" | "aborted" | "incomplete";

// PRD-B (RCA rca-discipline-evaporation item 3): LIVE relationship emission. The agent emits the
// entity↔entity links a TOOL established AS IT DIGS (a domain that resolves to an IP, a wallet a page
// pays out to), so the network is built from what was dug up — NOT reconstructed blind by all-pairs
// co-occurrence after the fact (the original investigator emits typed edges; the port lost it).
export interface AgentRelationship {
  src: string; // an entity VALUE that also appears in `findings`
  dst: string; // the other endpoint's value
  relType: string; // a short snake_case label (resolves_to, hosted_on, drains_to, registered_by, …)
  confidence: string; // low | medium | high
}

export interface InvestigateResult {
  steps: Step[];
  promoted: Finding[];
  leads: { finding: Finding; verdict: GateVerdict }[];
  // the agent's live-emitted entity↔entity relationships (built as it digs, provenance = this run).
  relationships: AgentRelationship[];
  usage: { input: number; output: number };
  stopReason: StopReason;
  // sp-2c870c26: the honest-degraded signal (port of investigator.py _run_agent worked:false). false ⇒
  // the pass did NO real work: no tool returned data AND nothing surfaced — a degraded/keys-missing run,
  // NOT a genuine "nothing to find". The conductor surfaces degradedReason so it never reads as clean-empty.
  worked: boolean;
  degradedReason?: string;
}

export interface InvestigateOpts {
  objective: string;
  client: AnthropicClient;
  signal?: AbortSignal;
  runTool?: (name: string, input: Record<string, unknown>, opts: OsintOpts) => Promise<ToolOutcome>;
  toolOpts?: OsintOpts;
  tools?: ToolDef[];
  maxTurns?: number;
  maxOutputTokens?: number;
  /** Live trail: fired AFTER each step is appended. A throwing callback is isolated
   *  (it can neither abort the loop nor change the returned result). */
  onStep?: (step: Step) => void;
  /** kweb-live-graph: fired after each SUCCESSFUL tool result with its observed entities (secret-redacted),
   *  so the session can grow the REAL graph as the dig happens instead of only at the end. Isolated like
   *  onStep — a throwing callback can neither abort the loop nor change the result. */
  onObserved?: (ev: ObservedEvent) => void;
  /** Live Claude text deltas from the Messages stream. Fired before the complete reasoning step exists. */
  onTextDelta?: (text: string) => void;
  /** Opt into Anthropic Messages SSE streaming for live Claude runs. */
  stream?: boolean;
  /** Redact every configured secret form from a tool result's content + input BEFORE it is shown in the
   *  trail (emit) OR sent back to the model (tool_result) — codex D9. Injected by the session
   *  (allSecretForms); default identity. The free tools never carry a secret, so this is a no-op until
   *  an enrich tool runs; it is the in-flight cut that complements the at-rest/projection redaction. */
  redactContent?: (s: string) => string;
}

const DEFAULT_MAX_TURNS = 12;
// kweb-salvage-01 (NO TURN LEASH, founder 2026-06-03 + canonical decisions.md): a turn count must NOT
// bound a whole-case run. The OLD value (28) was killing the agent mid-dig — a 27-seed FIFA run did ~60
// tool calls, hit the cap, truncated its final turn, and returned 0 because findings extract only on a
// clean end_turn. The COST BUDGET (maxOutputTokens → maxOut, enforced at the top of the loop) is the
// real gate; this constant is now only a runaway-loop backstop set far above any real run (mirrors the
// Python timeout-only model — investigator.py runs --max-turns-less, bounded by the timeout). Removing
// the turn leash is what lets a whole-case run FINISH naturally and return a FULL result. If a run is
// still genuinely cut off (budget exhausted / backstop) before a clean end_turn, finish() saves nothing
// and reports an honest cut-off error — a half-run is not reliable (founder 2026-06-24).
// The per-objective default stays 12 (the cheap one-hop); only investigateCase opts into DEEP.
export const DEEP_MAX_TURNS = 200;

// kweb-findings-cutoff (founder 2026-06-24): the per-call OUTPUT cap for a run turn. The shared client
// default is 4096, which TRUNCATES the final findings JSON on any rich case — a 28-seed FIFA run emits a
// findings array far larger than 4096 tokens, the truncated turn returns stop_reason max_tokens, the loop
// discards it as a cutoff, and a FULLY-WORKED case returns ZERO promoted / ZERO leads. The "no turn leash"
// fix raised turns but never touched this cap, which is the actual blade. Opus 4.8 emits a normal case's
// findings well within this ceiling; MAX_FINDINGS_CONTINUATIONS is the belt for a case whose JSON still
// exceeds one call. A ceiling, not a target — it only costs what is actually generated.
const RUN_MAX_OUTPUT_TOKENS = 16384;
// The belt: how many times a truncated FINAL answer (no tool_use) may be continued so its findings JSON
// finishes across calls. Bounded here AND by the output-token budget checked at the top of the loop.
const MAX_FINDINGS_CONTINUATIONS = 4;

// PRD-B agent-completeness-stop (RCA discipline-evaporation, port of investigator.py _coverage_met): the
// port stopped on the turn cap / a premature end_turn only, so the agent could quit with un-worked leads on
// the table. These drive a COVERAGE stop: keep digging while the agent has surfaced pivotable entities it
// has not worked, bounded by a nudge budget + a plateau guard (no new observations) so it can never loop.
const MAX_COVERAGE_NUDGES = 3;
const PIVOTABLE_TYPES = new Set(["domain", "subdomain", "ip", "ip_address", "nameserver", "mailserver", "wallet", "handle", "url"]);
// the tool-input field names that carry a TARGET the agent worked (mirrors session.ts TOUCH_FIELDS).
const TARGET_FIELDS = new Set(["domain", "ip", "address", "url", "name", "target", "query", "value", "host", "hostname", "handle", "wallet"]);

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === "AbortError";
}

export async function investigate(opts: InvestigateOpts): Promise<InvestigateResult> {
  const tools = opts.tools ?? OSINT_TOOLS;
  const runTool = opts.runTool ?? defaultRunTool;
  const maxTurns = opts.maxTurns ?? DEFAULT_MAX_TURNS;
  const maxOut = opts.maxOutputTokens ?? Infinity;
  const redactStr = opts.redactContent ?? ((s: string) => s); // codex D9: identity until the session injects allSecretForms

  const messages: Message[] = [{ role: "user", content: opts.objective }];
  const steps: Step[] = [];
  const observed: Observed[] = [];
  // agent-completeness-stop: the targets the agent has actually worked (tool inputs) + the nudge budget.
  const workedTargets = new Set<string>();
  let coverageNudges = 0;
  let observedAtLastNudge = -1;
  // the pivotable entities the agent surfaced but has NOT worked yet (a queried-target echo doesn't count).
  const uncoveredTargets = (): string[] => {
    const out: string[] = [];
    for (const o of observed) {
      for (const e of o.entities) {
        if (e.self || !PIVOTABLE_TYPES.has(e.type.toLowerCase())) continue;
        const v = e.value.trim().toLowerCase();
        if (v && !workedTargets.has(v) && !out.includes(v)) out.push(v);
      }
    }
    return out;
  };
  // coverage is met when every surfaced-but-un-worked target was at least REPORTED as a finding (the agent
  // accounted for it) — only a target it discovered yet neither pivoted on NOR reported is a dropped lead.
  const coverageMet = (reported: Set<string>): boolean => uncoveredTargets().every((v) => reported.has(v));

  // Append the step, THEN notify the live trail. A throwing onStep is swallowed so a
  // bad UI renderer cannot abort or corrupt the agent run (codex finding-2).
  const emit = (step: Step): void => {
    steps.push(step);
    if (opts.onStep) {
      try {
        opts.onStep(step);
      } catch {
        /* a broken renderer must not break the loop */
      }
    }
  };
  let finalText = "";
  // the RICHEST end_turn text seen (most extractable findings) — so a coverage nudge can never DOWNGRADE the
  // result by replacing a good end_turn with a thinner one the agent emits after the nudge (codex issue-5 C2).
  let bestFinalText = "";
  let bestFindingCount = -1;
  // kweb-findings-cutoff: text the agent emitted across max_tokens CONTINUATIONS of its FINAL answer,
  // re-joined ahead of the eventual end_turn so a findings JSON that spanned calls parses as one block.
  let continuationBuffer = "";
  let findingsContinuations = 0;
  let stopReason: StopReason = "budget"; // if the turn cap is hit without end_turn

  for (let turn = 0; turn < maxTurns; turn++) {
    if (opts.signal?.aborted) return finish("aborted");
    if (opts.client.tokensUsed.output >= maxOut) return finish("budget");

    let res;
    try {
      res = await opts.client.run({
        messages,
        tools,
        system: PERSONA,
        cache: true,
        kind: "judgment",
        maxTokens: RUN_MAX_OUTPUT_TOKENS, // kweb-findings-cutoff: don't let the 4096 default truncate findings
        signal: opts.signal,
        stream: opts.stream,
        onTextDelta: opts.onTextDelta ? (text) => opts.onTextDelta?.(redactStr(text)) : undefined,
      });
    } catch (e) {
      if (isAbort(e)) return finish("aborted");
      throw e;
    }

    for (const b of res.content) {
      if (b.type === "text" && typeof b.text === "string") emit({ kind: "reasoning", text: b.text });
    }

    if (res.stopReason === "end_turn") {
      // agent-completeness-stop (port of investigator.py _coverage_met): if the agent quit while pivotable
      // entities it surfaced are still un-worked, nudge it to keep digging — UNLESS it has plateaued (no new
      // observations since the last nudge) or the nudge budget is spent. This keeps the network being mapped
      // instead of stopping at the first end_turn, without ever looping (bounded by budget + plateau).
      // kweb-findings-cutoff: prepend any buffered continuation text so a findings JSON that was emitted
      // across max_tokens continuations parses as one block. A clean finish consumes the buffer.
      const turnText = continuationBuffer + textOf(res.content);
      continuationBuffer = "";
      const turnFindings = extractFindings(turnText);
      if (turnFindings.length > bestFindingCount) {
        bestFindingCount = turnFindings.length;
        bestFinalText = turnText; // remember the richest answer (codex issue-5 C2)
      }
      const reported = new Set(turnFindings.map((f) => f.entity.trim().toLowerCase()));
      const uncovered = uncoveredTargets().filter((v) => !reported.has(v)); // discovered but neither worked NOR reported
      const plateaued = observed.length === observedAtLastNudge;
      if (!coverageMet(reported) && coverageNudges < MAX_COVERAGE_NUDGES && !plateaued) {
        coverageNudges++;
        observedAtLastNudge = observed.length;
        messages.push({ role: "assistant", content: res.content });
        messages.push({
          role: "user",
          content:
            `You surfaced entities you have NOT worked yet: ${uncovered.slice(0, 12).join(", ")}. ` +
            "Pivot on each that fits the objective (resolve it, read its registry/chain, enumerate it) before you finish. " +
            "When the inventory is genuinely worked, end your turn with the findings JSON.",
        });
        continue;
      }
      finalText = bestFinalText || turnText; // the richest end_turn, never a nudge-downgraded one (C2)
      return finish("end_turn");
    }
    // kweb-findings-cutoff (founder 2026-06-24, "prevent the cutoff"): a max_tokens stop while the agent is
    // writing its FINAL answer (no tool_use in this turn) is the #1 cause of a rich case returning 0 — the
    // findings JSON exceeded one call's output cap. Buffer the partial text and ask it to finish, so the JSON
    // completes ACROSS calls and parses on the eventual end_turn — instead of being discarded as a cutoff.
    // Bounded by MAX_FINDINGS_CONTINUATIONS + the output-token budget (checked at the top of the loop). A
    // truncated TOOL_USE turn is NOT continuable (a half-emitted tool call is unusable), so it still finishes
    // as an honest cutoff; so does a run that exhausts the continuation budget. A refusal is never continued.
    if (res.stopReason === "max_tokens") {
      const hasToolUse = res.content.some((b) => b.type === "tool_use");
      if (!hasToolUse && findingsContinuations < MAX_FINDINGS_CONTINUATIONS) {
        findingsContinuations++;
        continuationBuffer += textOf(res.content);
        messages.push({ role: "assistant", content: res.content });
        messages.push({
          role: "user",
          content:
            "Your previous message was cut off before it finished. Continue from exactly where you stopped — " +
            "output ONLY the remaining characters that complete the findings JSON. Do not repeat earlier text, " +
            "do not restart the JSON, no preamble.",
        });
        continue;
      }
      return finish("incomplete");
    }
    if (res.stopReason === "refusal") return finish("incomplete");

    if (res.stopReason === "pause_turn") {
      // Server paused a long turn: resend the assistant content to continue.
      messages.push({ role: "assistant", content: res.content });
      continue;
    }

    if (res.stopReason === "tool_use") {
      // Append the assistant turn with its tool_use blocks UNCHANGED (required ordering).
      messages.push({ role: "assistant", content: res.content });
      const toolUses = res.content.filter((b) => b.type === "tool_use");
      const toolResults: ContentBlock[] = [];
      for (const tu of toolUses) {
        const name = String((tu as { name?: unknown }).name ?? "");
        const id = String((tu as { id?: unknown }).id ?? "");
        const input = ((tu as { input?: unknown }).input ?? {}) as Record<string, unknown>;
        // agent-completeness-stop: record every TARGET value this tool worked, so the coverage stop knows
        // which surfaced entities still need a pivot. liveTarget = the first such value (kweb-live-graph:
        // the node a live observation hangs off — domain resolves_to ip, etc.).
        let liveTarget = "";
        for (const [k, v] of Object.entries(input)) {
          if (TARGET_FIELDS.has(k) && typeof v === "string" && v.trim()) {
            workedTargets.add(v.trim().toLowerCase());
            if (!liveTarget) liveTarget = v.trim();
          }
        }
        let outcome: ToolOutcome;
        try {
          outcome = await runTool(name, input, { ...opts.toolOpts, signal: opts.signal });
        } catch (e) {
          if (isAbort(e)) return finish("aborted");
          throw e;
        }
        // codex D9: redact every secret form from the result + input BEFORE the trail OR the model sees
        // it — a provider key echoed in an entity/note never reaches the DOM or the Anthropic messages.
        const safeContent = redactStr(outcome.content);
        let safeInput: unknown = input;
        try {
          safeInput = JSON.parse(redactStr(JSON.stringify(input ?? {})));
        } catch {
          /* a non-serializable input keeps its raw shape; the persist layer redacts it at rest */
        }
        emit({ kind: "tool", tool: name, input: safeInput, result: safeContent, isError: outcome.is_error });
        // sp-918b0d0d: record EVERY non-error result (even zero-entity ones) so its redacted text is
        // available for CLAIM-prose hard-token corroboration in attributeFinding — a whois result whose
        // only date lives in free text (not an extracted entity) must still be able to back a claim. A
        // zero-entity entry never matches the entity-corroboration loop, so source_count is unchanged.
        if (!outcome.is_error) {
          const echo = outcome.queryEcho ? outcome.queryEcho.trim().toLowerCase() : null;
          observed.push({
            provider: outcome.provider ?? name,
            infra: outcome.infra ?? true, // per the tool's own classification (free tools are all T1 infra)
            text: safeContent, // the redacted raw tool result — claim-token corroboration reads this
            entities: outcome.entities.map((e) => ({
              type: e.type,
              value: e.value,
              // codex D4: the queried-target echo doesn't corroborate a finding about that same target
              self: echo !== null && e.value.trim().toLowerCase() === echo,
            })),
          });
          // kweb-live-graph: surface this tool's entities LIVE (secret-redacted) so the graph grows as the
          // dig happens. Isolated like onStep — a throwing renderer can never break the run.
          if (opts.onObserved) {
            try {
              opts.onObserved({
                tool: name,
                target: redactStr(liveTarget),
                entities: outcome.entities.map((e) => ({
                  type: e.type,
                  value: redactStr(e.value),
                  self: echo !== null && e.value.trim().toLowerCase() === echo,
                })),
              });
            } catch {
              /* a broken live-graph renderer must not break the loop */
            }
          }
        }
        const block: ContentBlock = { type: "tool_result", tool_use_id: id, content: safeContent };
        if (outcome.is_error) block.is_error = true;
        toolResults.push(block);
      }
      // A single user turn carries ALL tool_result blocks for this assistant turn.
      messages.push({ role: "user", content: toolResults });
      continue;
    }

    // Any other stop_reason: stop cleanly rather than loop blindly.
    return finish("incomplete");
  }

  return finish(stopReason);

  function finish(reason: StopReason): InvestigateResult {
    // A clean end_turn is the ONLY result that yields findings (codex finding-7 — never parse truncated
    // output as if it were real). A CUTOFF (budget / incomplete / backstop) saves NOTHING: a half-run's
    // partial findings are untrustworthy, so finish() reports an honest cut-off error instead of
    // salvaging (founder 2026-06-24: "if the run was cut off, we don't save … half a run doesn't help").
    // An ABORTED run is the analyst's explicit Stop — no findings, but not an error.
    const isCutoff = reason !== "end_turn" && reason !== "aborted";
    const raw = reason === "end_turn" ? extractFindings(finalText) : [];
    const relationships = reason === "end_turn" ? extractRelationships(finalText) : [];
    const attributed = attributeFindings(raw, observed);
    const promoted: Finding[] = [];
    const leads: { finding: Finding; verdict: GateVerdict }[] = [];
    for (const f of attributed) {
      const verdict = promotionGate(f);
      if (verdict.promote) promoted.push(f);
      else leads.push({ finding: f, verdict });
    }
    // A CUTOFF is an ERROR, not a clean-empty: the run did not finish, so whatever it touched is a
    // half-run and nothing is saved. worked:false + a cut-off degradedReason so the conductor surfaces it
    // as "re-run with more budget", never as a clean "nothing to find" (founder 2026-06-24). This takes
    // precedence over the tool-success check below — a cutoff that ran tools is still an error.
    //
    // worked:false is otherwise the UNAMBIGUOUS degraded signal: the pass produced NOTHING (no promoted,
    // no leads) AND no tool ever returned data. A "successful tool" = a non-error step: in kipi-web EVERY
    // tool failure (exception / bad input / timeout / 4xx-5xx / bad key) returns errorOutcome with
    // is_error:true (tools.ts), so a non-error step is by construction a real observation — an
    // empty-but-successful lookup (e.g. DNS no-records) is a genuine clean-empty, worked:true. An ABORTED
    // run is the analyst's choice, not a degradation, so it is worked:true with no degradedReason (codex
    // C1: don't overload worked:false to mean analyst-stopped; bottomLine surfaces the abort via stopReason).
    const hadSuccessfulTool = steps.some((s) => s.kind === "tool" && !s.isError);
    const producedSomething = promoted.length > 0 || leads.length > 0;
    const worked = !isCutoff && (hadSuccessfulTool || producedSomething || reason === "aborted");
    let degradedReason: string | undefined;
    if (isCutoff) {
      degradedReason =
        "the run was cut off before it finished — nothing was saved (a partial run is not reliable). " +
        "Raise the per-case budget and re-run.";
    } else if (!worked) {
      const triedATool = steps.some((s) => s.kind === "tool");
      degradedReason = triedATool
        ? "every OSINT tool call failed — check your keys / connectivity (this is a tooling problem, not an empty case)"
        : "the agent ran no OSINT tools and found nothing — check tool availability or rephrase the objective";
    }
    return { steps, promoted, leads, relationships, usage: opts.client.tokensUsed, stopReason: reason, worked, degradedReason };
  }
}

function textOf(content: ContentBlock[]): string {
  return content
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text as string)
    .join("\n");
}

// ---- strict findings extraction (last trailing JSON; zero on any parse failure) ----

export function extractFindings(text: string): Finding[] {
  const block = lastJsonBlock(text);
  if (!block) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(block);
  } catch {
    return []; // malformed/partial output is never gated as if it were real
  }
  if (!parsed || typeof parsed !== "object") return [];
  const arr = (parsed as { findings?: unknown }).findings;
  if (!Array.isArray(arr)) return [];
  return arr.filter(
    (f): f is Finding =>
      !!f && typeof f === "object" && typeof f.entity === "string" && typeof f.entity_type === "string",
  );
}

/** Extract the agent's live-emitted relationships from the SAME trailing JSON block as the findings
 *  ({findings:[...], relationships:[...]}). Drops a malformed entry, a self-loop, or one missing an
 *  endpoint; normalizes the confidence + a default rel_type. Zero on any parse failure (never gated as
 *  real from truncated output — the caller only calls this on a clean end_turn). PRD-B RCA item 3. */
export function extractRelationships(text: string): AgentRelationship[] {
  const block = lastJsonBlock(text);
  if (!block) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(block);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];
  const arr = (parsed as { relationships?: unknown }).relationships;
  if (!Array.isArray(arr)) return [];
  const out: AgentRelationship[] = [];
  for (const r of arr) {
    if (!r || typeof r !== "object") continue;
    const rr = r as Record<string, unknown>;
    const src = (typeof rr.src === "string" ? rr.src : "").trim();
    const dst = (typeof rr.dst === "string" ? rr.dst : "").trim();
    if (!src || !dst || src.toLowerCase() === dst.toLowerCase()) continue; // need two distinct endpoints
    const relRaw = (typeof rr.rel_type === "string" ? rr.rel_type : typeof rr.relType === "string" ? rr.relType : "").trim();
    const relType = relRaw ? relRaw.toLowerCase().replace(/\s+/g, "_").slice(0, 40) : "linked";
    const c = (typeof rr.confidence === "string" ? rr.confidence : "").trim().toLowerCase();
    const confidence = c === "high" || c === "low" ? c : "medium";
    out.push({ src, dst, relType, confidence });
  }
  return out;
}

function lastJsonBlock(text: string): string | null {
  const fences = [...text.matchAll(/```json\s*([\s\S]*?)```/gi)];
  if (fences.length > 0) return fences[fences.length - 1][1].trim();
  // Prefer the LAST {"findings" object: on a max_tokens CONTINUATION the agent may (despite the
  // instruction) restart the JSON, so a later COMPLETE block must win over an earlier truncated one
  // (kweb-findings-cutoff). For a normal single-block answer this is identical to the first match.
  const matches = [...text.matchAll(/\{\s*"findings"/g)];
  const last = matches[matches.length - 1];
  if (last && last.index !== undefined) return balancedObject(text, last.index);
  return null;
}

/** Return the balanced {...} starting at `start`, respecting strings/escapes. */
function balancedObject(text: string, start: number): string | null {
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === "{") depth++;
    else if (ch === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
  }
  return null;
}
