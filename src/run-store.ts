// run-store.ts — the investigator run's durable state, decoupled from the view DOM.
//
// rsn-run-store (prd-run-survives-navigation-2026-06-25): the run trail used to live ONLY inside the
// dock's #trail DOM (dock.ts), so unmountChatDock() on nav destroyed it and the streaming run was
// silently orphaned — the founder hit this clicking OSINT mid-run (rca-nav-during-run-orphans-run-and-
// graph-2026-06-25). This module gives the run a home OUTSIDE any view: the run writes here on every
// step/finding, and the dock's #trail/#findings render is a PROJECTION of it. A later view rebuild
// (renderSplitView / mountChatDock) can replay this store, so navigation can no longer lose the trail.
//
// Pure + DOM-free on purpose: app.ts holds the single instance and is the ONLY writer (one run at a
// time — run-supersede stays; concurrent runs are a non-goal). This module never touches the document,
// the vault, or the key, which is also why it is unit-testable by direct import (the codebase has no
// jsdom; app.ts itself is not import-safe under node, so the store's logic lives here to be tested).

import type { Step } from "./agent/loop.js";
import type { Finding, GateVerdict } from "./agent/gate.js";

export type RunStatus = "idle" | "running" | "done" | "aborted";

/** A gated-but-not-promoted finding (the run's leads), shaped exactly like InvestigateResult.leads. */
export interface RunLead {
  finding: Finding;
  verdict: GateVerdict;
}

/** The full run-lifecycle state. `steps` is the ordered live trail; `findings`/`leads` land at finalize. */
export interface RunStoreState {
  status: RunStatus;
  objective: string;
  steps: Step[];
  findings: Finding[];
  leads: RunLead[];
}

function emptyState(): RunStoreState {
  return { status: "idle", objective: "", steps: [], findings: [], leads: [] };
}

// The single module-level instance. app.ts mutates it through the helpers below; the dock projects it.
let state: RunStoreState = emptyState();

/** The live store. The dock renders from this; callers must treat it as read-only (never mutate in place). */
export function getRunStore(): RunStoreState {
  return state;
}

/** True while a run is streaming — the off-Workspace chip + the render() preserve guard read this. */
export function isRunActive(): boolean {
  return state.status === "running";
}

/** Begin a new run: clear the prior trail/findings and mark it running. Called at run START
 *  (startInvestigation / startCaseInvestigation), the single point a run is born. A new run that
 *  supersedes an older one calls this, which resets the store for the new run (run-supersede). */
export function beginRun(objective: string): void {
  state = { status: "running", objective, steps: [], findings: [], leads: [] };
}

/** Append one streamed step. The run writes here on EVERY step, independent of whether the dock DOM is
 *  mounted — the whole point: a nav-away must not lose the trail. */
export function recordRunStep(step: Step): void {
  state.steps.push(step);
}

/** Record the run's promoted findings + leads at finalize (the dock #findings/#leads project these). */
export function recordRunFindings(findings: Finding[], leads: RunLead[]): void {
  state.findings = findings;
  state.leads = leads;
}

/** Set the terminal status: a finished run is "done"; an aborted / superseded / failed one is "aborted". */
export function setRunStatus(status: RunStatus): void {
  state.status = status;
}

// G1 (video-review 2026-06-25): the run-progress ENVELOPE strings. The founder could not tell "did it
// start? where is it? is it about to end?" — the run-chip showed a static "Investigator running…" and
// vanished silently at the end. These pure formatters drive a LIVE chip label (objective · step N ·
// elapsed) + a terminal flash ("✓ Done" / "■ Stopped"). Pure + DOM-free so they unit-test by direct
// import; app.ts owns the wall-clock (Date.now is not import-safe to assert here).

/** mm:ss from an elapsed millisecond count (clamped at 0). */
function clock(elapsedMs: number): string {
  const secs = Math.max(0, Math.floor(elapsedMs / 1000));
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
}

/** The LIVE chip label while a run streams: "Investigating <objective> · N steps · m:ss". Before the
 *  first step lands it reads "starting…" so the analyst sees the run was accepted (answers "did it start?"). */
export function formatRunProgress(objective: string, stepCount: number, elapsedMs: number): string {
  const obj = (objective || "").trim() || "the case";
  if (stepCount <= 0) return `Investigating ${obj} · starting…`;
  return `Investigating ${obj} · ${stepCount} step${stepCount === 1 ? "" : "s"} · ${clock(elapsedMs)}`;
}

/** The TERMINAL flash label (answers "did it end?"): a clean "✓ Done — N promoted, M leads (reason)" for a
 *  finished run, or "■ Run stopped" for an abort. A plain end_turn finish drops the redundant reason tail. */
export function formatRunDone(status: RunStatus, promoted: number, leads: number, stopReason: string): string {
  if (status === "aborted") return "■ Run stopped";
  const tail = stopReason && stopReason !== "end_turn" ? ` (${stopReason})` : "";
  return `✓ Done — ${promoted} promoted, ${leads} lead${leads === 1 ? "" : "s"}${tail}`;
}

/** Hard reset to idle/empty. The NEXT issue (rsn-case-switch-wipe) wires this into clearCaseDerivedState
 *  so a case switch / lock / reset can never replay case A's run into case B (a confidentiality invariant
 *  in a zero-retention app). Not yet called in this issue — it is the foundation that wiring depends on. */
export function resetRunStore(): void {
  state = emptyState();
}
