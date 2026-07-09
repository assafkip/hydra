// Persistent investigation lifecycle rail — the "you are here" across the case.
//
// Port of investigations/webapp/app.py::_lifecycle_state. The Understand stage was removed
// 2026-06-10 (the schema auto-models during Process), so the stages are
// Intake → Investigate → Deliver → Portfolio. Each stage carries a per-case `done` flag + a
// short detail, computed from the SAME key-safe session projections the pages read — never the
// raw vault. kipi-web always has exactly one active (scoped) case, so unlike the Python webapp
// there is no all/multi-case branch that returns null; the rail always shows for a loaded vault.

import type { Vault } from "./vault/vault.js";
import {
  listIngestedDocs,
  listRuns,
  listBriefs,
  entityDbFor,
  tradecraftState,
} from "./agent/session.js";
import { crossRunEntities } from "./entity/db.js";

export interface LifecycleStage {
  key: "intake" | "investigate" | "deliver" | "portfolio";
  num: number;
  label: string;
  route: string;
  done: boolean;
  detail: string;
  // ccc-lifecycle-strip: the chat-driven strip prefills this prompt into the chat input when a stage is
  // clicked (instead of navigating to `route`). Safe analyst-intent prompts — prefilled for the analyst
  // to send, never auto-fired, so a click can't kick off a spendy run by surprise.
  prompt: string;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** The 4 lifecycle stages for the active (scoped) vault, each with a done flag + short detail.
 *  Done signals are the kipi-web analogs of _lifecycle_state's SQL counts. */
export function lifecycleStages(vault: Vault): LifecycleStage[] {
  // The run: namespace holds BOTH file-ingest reports (sourceKind=file, surfaced by listIngestedDocs)
  // AND agent investigation runs. Intake counts the ingested reports; Investigate counts the agent
  // runs (every run: record MINUS the ingest ones) — faithful to the Python split (reports table vs
  // enrichment_runs WHERE provider_slug='agent'). liveReportCount/listRuns alone conflate the two.
  const ingestObjectives = new Set(listIngestedDocs(vault).map((d) => d.objective));
  const reports = ingestObjectives.size;
  const agentRuns = listRuns(vault).filter((r) => !ingestObjectives.has(r.objective));
  const findings = agentRuns.reduce((n, r) => n + (r.promoted || 0), 0);
  const briefs = listBriefs(vault).length;
  // portfolio = cross-case overlap, faithful to what /cross-case actually renders (crossRunEntities:
  // entities appearing in >= 2 runs — the kipi-web single-vault analog of the Python cross-investigation count).
  const crossCase = crossRunEntities(entityDbFor(vault, null)).length;
  return [
    {
      key: "intake", num: 1, label: "Intake", route: "/reports",
      done: reports > 0, detail: plural(reports, "report"),
      prompt: "What evidence and entities are in this case so far?",
    },
    {
      // Investigate + Findings are ONE stage (same data: agent runs + what they found).
      key: "investigate", num: 2, label: "Investigate", route: "/runs",
      done: agentRuns.length > 0,
      detail: plural(agentRuns.length, "run") + (findings ? ` · ${plural(findings, "finding")}` : ""),
      prompt: "What should I investigate next in this case?",
    },
    {
      key: "deliver", num: 3, label: "Deliver", route: "/deliverables",
      done: briefs > 0, detail: briefs > 0 ? "brief ready" : "no brief",
      prompt: "Summarize the findings and generate the brief for this case.",
    },
    {
      key: "portfolio", num: 4, label: "Portfolio", route: "/cross-case",
      // sp-e253d09c: Portfolio is the LAST stage — a ✓ here while Investigate/Deliver are still blank read
      // as broken and undercut trust in the only orientation aid. Gate its done-check on the prior stages
      // so the rail is monotonic; the shared-entity count still shows as the detail regardless (it is a
      // count chip, not a milestone that can complete on its own).
      done: reports > 0 && agentRuns.length > 0 && briefs > 0 && crossCase > 0,
      detail: `${crossCase} shared entit${crossCase === 1 ? "y" : "ies"}`,
      prompt: "What entities does this case share with my other cases?",
    },
  ];
}

// Which lifecycle stage owns a given route, for "you are here" highlighting. Mirrors the sidebar
// grouping (the secondary Analysis surfaces are all part of Investigate; Deliver/Portfolio map to
// their sections). Routes with no stage (/, /cases, /account, /activity, /corrections) return null.
const ROUTE_STAGE: Record<string, LifecycleStage["key"]> = {
  "/reports": "intake",
  "/inbox": "intake",
  "/runs": "investigate",
  "/enrich": "investigate",
  "/entities": "investigate",
  "/clusters": "investigate",
  "/bridges": "investigate",
  "/focus": "investigate",
  "/alerts": "investigate",
  "/deliverables": "deliver",
  "/briefs": "deliver",
  "/exports": "deliver",
  "/report": "deliver",
  "/cross-case": "portfolio",
  "/cross-domain": "portfolio",
};

export function stageForRoute(route: string): LifecycleStage["key"] | null {
  return ROUTE_STAGE[route] ?? null;
}

// ---- clu-conductor: the chat conductor state machine ----
// The chat is the conductor. It SUGGESTS the next step; the analyst drives. Challenge/Premortem/Reality-check
// are SUGGESTIONS in the cycle order, NOT hard gates — the brief is never blocked (founder: the brief is
// auto-created, no blocking; the tradecraft steps are soft nudges, same as the chat tradecraft layer). These
// functions are PURE; app.ts derives the state from the vault projections + the tradecraft checklist.

export interface ConductorState {
  scopeSet: boolean; // the Scope gate has an artifact
  hasIntake: boolean; // at least one report ingested
  hasRuns: boolean; // at least one agent run
  hasFindings: boolean; // at least one promoted finding to write up
  challengeRan: boolean; // the Challenge step ran (a soft conductor suggestion now — no longer a gate)
  premortemRan: boolean;
  realityCheckRan: boolean;
  hasBrief: boolean; // a deliverable exists
}

export type ConductorStep =
  | "scope"
  | "intake"
  | "investigate"
  | "challenge"
  | "premortem"
  | "reality_check"
  | "deliver"
  | "done";

export interface ConductorSuggestion {
  step: ConductorStep;
  title: string; // the one-line suggestion shown in the chat
  detail: string; // why this is next
  /** True for any step that spends (an agent run) OR writes a deliverable: the analyst must greenlight
   *  it. Always true except "done" — a suggestion NEVER auto-runs (suggest-not-auto invariant). */
  requiresGreenlight: boolean;
}

function suggestion(step: ConductorStep, title: string, detail: string): ConductorSuggestion {
  return { step, title, detail, requiresGreenlight: step !== "done" };
}

/**
 * The next step the conductor SUGGESTS for the current case state. Pure: it never runs anything — the
 * analyst acts on the suggestion. First match wins; the order encodes the intelligence cycle and puts
 * Challenge BEFORE the deliverable (a SUGGESTION, not a gate — the brief is never blocked) once findings exist.
 */
export function suggestNextStep(state: ConductorState): ConductorSuggestion {
  if (!state.scopeSet) {
    // scope is a SOFT nudge, not a prerequisite — offer it AND the act-now path so it never reads as a wall.
    return suggestion("scope", "Set the scope (optional)", "Frame the question + what counts as proof with `scope` — or just start: type `investigate <target>` (or a direction like `focus on the cluster`).");
  }
  if (!state.hasIntake && !state.hasRuns) {
    return suggestion("intake", "Add evidence or investigate", "Attach files/paste a report — or type `investigate <target>` (or a direction) to start a run.");
  }
  if (!state.hasFindings) {
    return suggestion("investigate", "Investigate a lead", "Type `investigate <target>` — or direct it in plain language (`focus on the wallet cluster`, `trace the funds`); the graph grows live.");
  }
  if (!state.challengeRan) {
    return suggestion("challenge", "Run Challenge (required before findings)", "Pressure-test the findings for name-match traps, weak sources, and circular reasoning — type `challenge`.");
  }
  if (!state.premortemRan) {
    return suggestion("premortem", "Run Premortem", "Assume the brief is wrong six months from now — what made it wrong? Type `premortem`.");
  }
  if (!state.realityCheckRan) {
    return suggestion("reality_check", "Reality-check", "Sanity-check the picture for overreach — type `reality check`.");
  }
  if (!state.hasBrief) {
    return suggestion("deliver", "Write the brief", "The gates are clear — generate the deliverable from the current findings.");
  }
  return suggestion("done", "You're up to date", "Scope, findings, the gates, and the brief are all in place.");
}

/** Derive the conductor state for the active (scoped) vault from the SAME key-safe projections the rail
 *  reads + the tradecraft checklist. The single place the conductor reads the vault. */
export function conductorStateFor(vault: Vault): ConductorState {
  const ingestObjectives = new Set(listIngestedDocs(vault).map((d) => d.objective));
  const agentRuns = listRuns(vault).filter((r) => !ingestObjectives.has(r.objective));
  const findings = agentRuns.reduce((n, r) => n + (r.promoted || 0), 0);
  const done = new Set(tradecraftState(vault).filter((s) => s.done).map((s) => s.step));
  return {
    scopeSet: done.has("scope"),
    hasIntake: ingestObjectives.size > 0,
    hasRuns: agentRuns.length > 0,
    hasFindings: findings > 0,
    challengeRan: done.has("challenge"),
    premortemRan: done.has("premortem"),
    realityCheckRan: done.has("reality_check"),
    hasBrief: listBriefs(vault).length > 0,
  };
}
