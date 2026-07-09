// cd-ui (PRD chat-dock): the cloned _chat.html unified investigator, mounted into the
// Investigator dock and wired to the BROWSER agent loop (not a server). ONE input box, three
// modes (D3): a typed graph command drives CyGraph via the __kipiGraph bridge; an objective runs
// the browser loop streaming into the live trail (#trail) + growing the graph; a question is a
// no-tools grounded Q&A over the vault's runs. A few card actions are not yet built client-side (honest
// port-pending, D11). Built imperatively (matching app.ts) with createElement + textContent — a hostile entity
// value is never markup; model output goes through the escape-first renderMarkdown (D10).
//
// app.ts owns the vault + the graph + the run path; the dock receives everything it needs as
// `deps` (so the dock stays decoupled + the key never reaches it). The run-output ids the existing
// proofs depend on (#trail/#brief/#stopBtn/#briefBtn/#dlBriefBtn) live HERE, each
// exactly once, and app.ts's startInvestigation/startBrief render into them (D7).

import { classifyInput, parseGraphCommand, objectiveFrom, type GraphCommand } from "./commands.js";
import { classifyChatAction, type ChatActionPolicy } from "./action-policy.js";
import { type ProposedActionCard } from "./action-card.js";
import { commitChatAction, type ChatCommitResult } from "./action-commit.js";
import {
  parseTradecraftCommand,
  helperPromptFor,
  TRADECRAFT_STEPS,
  TOOL_GUIDE,
  type TradecraftStep,
} from "./tradecraft.js";
import { renderMarkdown } from "./markdown.js";
import { intakeCompleteness, renderCompleteness } from "./completeness.js";
import { mapRunError, type MappedError } from "./errors.js";
import { isRunActive } from "../run-store.js"; // stream-observer discriminates a LIVE run from a reload replay
import type { ConductorSuggestion } from "../lifecycle.js";
import type { ExtractedEntity } from "../ingest/extract.js";
import type { OcrProgress, OcrProgressCb } from "../ingest/ocr.js";
import type { CyNodeData } from "../graph/cy-adapter.js";
import type { Connection, Dossier, EdgeEvidence } from "../entity/db.js";
import type { EntityScoreBreakdown, EntityTypedRel, EntityAppearance, ChatMessage } from "../agent/session.js";

/** The graph bridge the chat drives (an adapter over CyGraph's real methods — D6). */
export interface KipiGraph {
  searchGraph(query: string): void;
  highlightByName(name: string): void;
  applyFilter(filter: { etype?: string; minScore?: number }): void;
  showAll(): void;
  fit(): void;
  reLayout(): void;
  setLayout(name: string): void;
  focusDirection(dir: "in" | "out" | "all"): void;
  selectedName(): string | null;
  digNode(nodeId: string): void;
  removeNode(target: string): void; // node-removal: target = an entity value, or "" for the selected node
  startInvestigation(objective: string): void;
  hasGraph(): boolean;
  // G2a (video-review 2026-06-25): test seam — toggle the "Focus threats" spine dim + read how many nodes
  // are currently receded, so a smoke can prove the dim applies to non-promoted nodes AND clears on toggle-off.
  setSpineFocus(on: boolean): void;
  offSpineCount(): number;
}

/** The chat bridge the graph drives (graph → chat). Payloads are already key-redacted (D4). */
export interface KipiChatBridge {
  // remove-cards (founder 2026-07-03): a graph node/edge click no longer injects a CARD into the chat — the
  // cards cluttered the conversation. Selection/highlight is graph-side; NODE DETAIL is now pulled by the
  // right-click menu, which routes a question through askInChat and the answer arrives as a normal chat turn.
  // showNode/showEdge are kept as no-op stubs so any residual caller is harmless (removed from the hot paths).
  showNode(data: CyNodeData): void;
  showEdge(data: EdgeCardData): void;
  // askInChat: the right-click menu (app.ts renderMenu) feeds a question/command into the SAME router the
  // analyst types into (dispatch), so "What is this?" / "Show connections" / "Investigate fully" answer in
  // the chat. Focuses the composer + echoes the question as a You bubble via the normal dispatch path.
  askInChat(text: string): void;
  // showNodeDetails: "Show full details" — render the DETERMINISTIC entity panel (score / typed rels /
  // appears-in / dossier — NO LLM) as a normal chat message (founder 2026-07-03: keep the computed detail
  // reachable in-chat, just as text, not a card). Retains the sf-entity-detail chat fold (parity).
  showNodeDetails(data: CyNodeData): void;
  pushAgent(text: string): void;
  pushAside(text: string): void;
  // Live streaming: the run loop publishes redacted model tokens; streamDelta appends them into ONE
  // live assistant bubble so the reply TYPES OUT (chat-feels-like-a-product). streamEnd seals/clears it
  // — the curated final briefing then arrives via pushAgent. Tokens are already key-redacted upstream.
  streamDelta(text: string): void;
  streamEnd(): void;
  // Holistic-fix P1 (chronological ordering): move the live run block (trail/findings/leads) to the
  // current bottom of the message stream at run start, so a post-run question renders BELOW the logs.
  relocateRunBlockToBottom(): void;
}

export interface EdgeCardData {
  src_id?: string; // cytoscape source node id (ed-wire D1: keyable endpoint)
  dst_id?: string; // cytoscape target node id
  src_name: string;
  dst_name: string;
  rel_type?: string;
}

/** The client entity DB view for a node — already key-redacted by the session layer (ed-wire). */
export interface EntityView {
  found: boolean;
  dossier: Dossier | null;
  connections: Connection[];
  coOccurrences: Connection[];
  // sf-entity-detail: the drawer mirrors the /entities-fold depth (§1+2 score+breakdown, §7 typed rels,
  // §8 appears-in) so BOTH folds reach the same depth (the built-not-wired scar). All key-redacted at
  // the session layer; null/[] when the node is the objective seed or the case is un-Processed.
  score: EntityScoreBreakdown | null; // §1+2
  typedRels: EntityTypedRel[]; // §7
  appearances: EntityAppearance[]; // §8
}

/** The client entity DB evidence for an edge — already key-redacted (ed-wire D1). */
export interface EdgeView {
  found: boolean;
  evidence: EdgeEvidence | null;
}

export interface QaSource {
  run: string;
  entity: string;
  entity_type: string;
  status: string;
}

/** Everything the dock needs from app.ts. The dock never touches the vault or the key. */
export interface ChatDeps {
  /** Run an objective on the browser loop. app.ts streams steps into #trail + renders
   *  #findings/#leads + the graph. Returns a summary, or null on error/abort. */
  runObjective(objective: string): Promise<{ stopReason: string; promoted: number; leads: number; worked?: boolean; degradedReason?: string; briefing?: string } | null>;
  /** A3: run the WHOLE-CASE pass (investigateCase) over every seed; returns the summary + the
   *  still-uninvestigated entities the analyst should direct next, or null on error/abort. `briefing` is the
   *  co-investigator reply (video-review 2026-06-25); empty/absent ⇒ fall back to the count line. */
  runCase(): Promise<{ stopReason: string; promoted: number; leads: number; rosterSize: number; pivots: { name: string }[]; worked?: boolean; degradedReason?: string; briefing?: string } | null>;
  /** Abort the in-flight run (the in-trail Stop). */
  stop(): void;
  /** Generate the brief for the last objective; app.ts renders it into #brief. */
  generateBrief(objective: string): Promise<void>;
  /** Download #brief as .md (app.ts owns the cap + redaction). */
  downloadBrief(): void;
  /** Commit an explicitly approved proposed action. app.ts is the single durable writer. */
  commitProposedAction(action: ProposedActionCard): Promise<ChatCommitResult>;
  /** Grounded Q&A (no tools) over the vault's runs, key-redacted by the session layer. */
  // history: the recent finished chat turns (statelessness fix, founder 2026-07-03) so follow-ups like
  // "more succinctly" / "why?" compress or deepen the PRIOR answer instead of resetting to "I don't know".
  answer(
    question: string,
    selectedName?: string | null,
    history?: { role: "you" | "agent"; text: string }[],
  ): Promise<{ answer: string; sources: QaSource[] }>;
  /** Node-reference: the analyst's currently-SELECTED graph node label (or null) — folded into a Q&A so
   *  "what is this?" resolves to it. The dock reads it at question time; null when nothing is selected. */
  selectedName(): string | null;
  /** The vault's runs for the findings/runs card. */
  listRuns(): { objective: string; promoted: number; leads: number; stopReason: string }[];
  /** The graph bridge, or null when no graph is mounted. */
  graph(): KipiGraph | null;
  /** The entity DB view for a node (real typed connections + dossier + co-occurrence), key-redacted. */
  entityView(node: CyNodeData): EntityView;
  /** The entity DB evidence for an edge (real edge evidence), key-redacted. */
  edgeView(edge: EdgeCardData): EdgeView;
  // ccc-workspace-shell: the node drawer is gone — its FULL content (facts, OSINT pivots, Dig-one-hop,
  // the OSINT transform menu, neighbors, dossier/typed/co-occurrence, cluster, AI dossier + Type
  // relations) now renders INTO the chat node card. app.ts owns that rich body (it touches the vault/
  // entity DB/cyGraph + spends the key on the AI passes — all barred from the dock), so the dock hands
  // it the card host and lets app.ts fill it. When unset (e.g. a test dock with no app), renderNodeCard
  // falls back to its own built-in body so the dock stays self-contained.
  renderNodeBody?(host: HTMLElement, node: CyNodeData): void;
  // cd-tradecraft: the analytical gates ported from tradecraft.py. The dock NEVER touches the vault/key —
  // app.ts wires these to the session functions (key-redacted there).
  /** Capture the case Scope framing (analyst input, no model call). Throws on a missing question. */
  recordScope(scope: { question: string; hypotheses: string; proof: string }): Promise<void>;
  /** The saved Scope parsed into the form fields, or null when none set — re-hydrates the form on open so
   *  a saved scope stops reading as "didn't persist" (founder 2026-07-07). */
  readScope(): { question: string; hypotheses: string; proof: string } | null;
  /** Run the Challenge or Premortem gate over the case findings. Returns the analysis, or null on error. */
  runGate(step: "challenge" | "premortem"): Promise<{ content: string } | null>;
  /** The per-case tradecraft checklist (which gates/helpers have run) for the bar's done marks. */
  tradecraftState(): { step: TradecraftStep; done: boolean }[];
  // clu-chat-intake: intake from the chat. app.ts decodes (fileToText, threading onProgress for OCR) +
  // persists through the ingestText gate; returns the extracted entities for the completeness check. The
  // dock never touches the vault/key. Throws on a locked/failed vault (caller shows a neutral line; E owns wording).
  /** Ingest one attached/dropped/pasted file (any type). Returns a key-REDACTED `safeName` for display —
   *  the dock must NEVER render the raw File.name (a key embedded in a filename would reach the chat DOM
   *  before redaction; codex). */
  ingestFile(file: File, onProgress?: OcrProgressCb): Promise<{ kind: string; entities: ExtractedEntity[]; warnings?: string[]; safeName: string }>;
  /** Ingest pasted plain text as a document. */
  ingestPastedText(text: string): Promise<{ entities: ExtractedEntity[] }>;
  /** Optional: app.ts refreshes the case graph + lifecycle after intake lands new entities. */
  onIngested?(): void;
  // clu-conductor: the conductor SUGGESTS the next step; the dock posts it and the analyst greenlights.
  /** The next step the conductor suggests for the current case (null when no vault is unlocked). */
  conductorSuggestion(): ConductorSuggestion | null;
  // clu-error-output: the honest cause of the last run that returned null (null = aborted/none). The dock
  // shows this instead of guessing — runObjective swallows the throw to render its own trail.
  lastRunError(): MappedError | null;
  // clu-chat-persist: the conversation must survive refresh / nav / tab-switch (it lived only in this
  // closure before). app.ts persists + rehydrates through the scoped vault (key-redacted + capped there);
  // the dock never touches the vault/key.
  /** The persisted conversation for the active case (key-redacted), or [] when none. Read once on mount. */
  loadChat(): ChatMessage[];
  /** Persist the full conversation. app.ts caps to the last 100 + redacts + seals before disk. */
  saveChat(messages: ChatMessage[]): void;
}

declare global {
  interface Window {
    __kipiChat?: KipiChatBridge | null;
    __kipiGraph?: KipiGraph | null;
  }
}

const EMPTY_PROMPT =
  'Ask anything, or give a command. New here? Type "help" for a walkthrough. "who runs this domain?" ' +
  'answers from the case with sources. "investigate trumpfundus.com" runs the agent. Tradecraft: "scope", ' +
  '"challenge", "premortem". Drive the graph: "only domains", "min score 50", "show all", "fit". See the ' +
  'work: "findings" or "runs".';

let teardown: (() => void) | null = null;

/** Mount the chat dock into `container`. Returns nothing; call unmountChatDock() to clear. */
export function mountChatDock(container: HTMLElement, deps: ChatDeps): void {
  unmountChatDock(); // never stack two chats / two __kipiChat registrations
  container.replaceChildren();

  let busy = false;
  let lastObjective: string | null = null;
  // clu-chat-persist: the in-memory conversation, mirrored to the vault so it survives refresh/nav/tab-switch.
  // `record` is the SINGLE point that appends + persists (called only from pushYou/pushAgent — the real
  // turn bubbles; transient asides like OCR-progress are NOT persisted). `replaying` suppresses re-persist
  // while we rehydrate prior messages on mount.
  const history: ChatMessage[] = [];
  let replaying = false;
  function record(msg: ChatMessage): void {
    if (replaying) return;
    history.push(msg);
    deps.saveChat(history); // app.ts caps + redacts + seals (fire-and-forget; never blocks the UI)
  }

  // ---- DOM (cloned _chat.html docked layout) ----
  const root = elem(`<div class="chatdock"></div>`);
  const scroll = elem(`<div id="chat-scroll" class="chat-scroll"></div>`);
  const empty = elem(`<div id="chat-empty" class="chat-empty-prompt"></div>`);
  empty.textContent = EMPTY_PROMPT;
  const messages = elem(`<div id="chat-messages"></div>`);
  const trail = elem(`<div id="trail" class="livetrail"></div>`); // app.ts streams steps here (#trail)
  // hydra ISSUE-3 (founder 2026-07-07): the run log had no dismiss and held ~40vh open for the whole run,
  // burying the chat. Wrap #trail with a collapse toggle (sibling of #trail so app.ts's `trail.innerHTML=""`
  // on each run reset never wipes it). #trail keeps its id + streaming untouched. Persisted like kipiDockOpen.
  const trailWrap = elem(`<div class="livetrail-wrap"></div>`);
  const trailToggle = elem(`<button type="button" class="livetrail-toggle" aria-expanded="false" title="Show or hide the run log"><span class="tc-caret">▸</span><span class="tc-label">Run log</span><span class="tc-hint">Show</span></button>`) as HTMLButtonElement;
  // hydra ISSUE-6 (founder 2026-07-08): default COLLAPSED. ISSUE-3 made the log collapsible but left it
  // expanded-by-default, so it still overtook the chat; then hiding the empty wrap made a finished run read
  // as "gone" ("now I don't see the log at all"). Fix: the log starts collapsed to a pill (the always-visible
  // affordance), a LIVE run auto-expands to stream (setRunExpanded), and it collapses back when the run ends.
  // NEW key `kipiTrailPref`, written ONLY on an explicit click — never on mount. The ISSUE-3 code wrote
  // `kipiTrailCollapsed` on every mount, so "expanded" got auto-persisted for everyone and would have
  // overridden this collapsed default (caught live 2026-07-08: a stale "0" kept the log expanded). A fresh
  // key with click-only writes means: no explicit choice ⇒ always collapsed; only a real click sticks.
  const wantsExpanded = typeof sessionStorage !== "undefined" && sessionStorage.getItem("kipiTrailPref") === "open";
  const setTrailCaret = (collapsed: boolean): void => {
    trailToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    const caret = trailToggle.querySelector(".tc-caret");
    if (caret) caret.textContent = collapsed ? "▸" : "▾";
    const hint = trailToggle.querySelector(".tc-hint");
    if (hint) hint.textContent = collapsed ? "Show" : "Hide"; // hydra ISSUE-7: spell out the action, not just a caret
  };
  const setTrailVisual = (collapsed: boolean): void => {
    trail.classList.toggle("collapsed", collapsed);
    setTrailCaret(collapsed);
  };
  // Explicit user toggle — the ONLY writer of the preference key.
  const applyTrailCollapsed = (collapsed: boolean): void => {
    setTrailVisual(collapsed);
    if (typeof sessionStorage !== "undefined") sessionStorage.setItem("kipiTrailPref", collapsed ? "closed" : "open");
  };
  // Transient run-lifecycle expand: a streaming run opens the log WITHOUT persisting (so the collapsed
  // default survives the run); when the run ends it falls back to the analyst's saved preference.
  const setRunExpanded = (expanded: boolean): void => {
    if (expanded) { setTrailVisual(false); return; }
    const wantOpen = typeof sessionStorage !== "undefined" && sessionStorage.getItem("kipiTrailPref") === "open";
    setTrailVisual(!wantOpen);
  };
  setTrailVisual(!wantsExpanded); // mount: visual only, no persist — default collapsed unless a click stuck
  trailToggle.addEventListener("click", () => applyTrailCollapsed(!trail.classList.contains("collapsed")));
  // hydra ISSUE-6b (founder 2026-07-08: "I still don't see any of the logs when the llm runs"): auto-expand
  // the log the instant a step streams in. app.ts's runEvents subscriber appends step rows to #trail for
  // EVERY run regardless of entry point; wiring only the two dock run-functions missed paths and left the
  // log collapsed (invisible) mid-run. Observing #trail's children catches 100% of runs — an ADDED node is
  // a live step ⇒ expand. (A run's `trail.innerHTML=""` removes nodes only, so a reset never re-expands.)
  if (typeof MutationObserver !== "undefined") {
    const trailStreamObserver = new MutationObserver((records) => {
      // Expand only for a genuinely LIVE run. A reload replay (reattachRunIntoDock) also appends step rows, but
      // isRunActive() is false then, so the last run's journaled trail stays COLLAPSED behind the pill.
      if (isRunActive() && records.some((r) => r.addedNodes.length > 0)) setRunExpanded(true);
    });
    trailStreamObserver.observe(trail, { childList: true });
  }
  // hydra ISSUE-7 (founder 2026-07-08): the log is drag-resizable (CSS resize:vertical sets inline
  // style.height). Persist the dragged height so it survives navigation + reload; apply it on mount. The
  // resize-grip release fires pointerup on the trail, so capture there.
  const savedTrailHeight = typeof sessionStorage !== "undefined" ? sessionStorage.getItem("kipiTrailHeight") : null;
  if (savedTrailHeight) trail.style.height = savedTrailHeight;
  trail.addEventListener("pointerup", () => {
    if (typeof sessionStorage !== "undefined" && trail.style.height) sessionStorage.setItem("kipiTrailHeight", trail.style.height);
  });
  trailWrap.appendChild(trailToggle);
  trailWrap.appendChild(trail);
  // remove-chat-findings (founder 2026-07-08): the in-chat entity-chip column (#findings/#leads) is GONE
  // — "I absolutely don't need it, it messes up the chat." The same entities still live on the graph and on
  // the /runs Run-trail page (both project the run store, recordRunFindings). Only this chat surface is cut.
  const briefRow = elem(`<div id="brief-row" class="brief-row" hidden></div>`);
  const briefBtn = elem(`<button id="briefBtn" class="ghost">Generate brief</button>`);
  const dlBriefBtn = elem(`<button id="dlBriefBtn" class="ghost">Download .md</button>`);
  briefRow.appendChild(briefBtn);
  briefRow.appendChild(dlBriefBtn);
  const brief = elem(`<pre id="brief" class="brief"></pre>`);
  const busyRow = elem(`<div id="chat-busy" class="chat-busy" hidden></div>`);
  // Animated three-dot "typing" indicator (chat-feels-like-a-product) — reads as the assistant thinking,
  // not a static grey line. The label follows it (e.g. "investigating evil.com…").
  const busyDots = elem(`<span class="thinking-dots" aria-hidden="true"><span></span><span></span><span></span></span>`);
  const busyText = elem(`<span id="chat-busy-text" class="truncate"></span>`);
  busyRow.appendChild(busyDots);
  busyRow.appendChild(busyText);

  // scope-scroll-fix (founder 2026-07-07): the LOG (#trail) is NOT in the conversation scroll anymore — it
  // lives in a fixed panel ABOVE the conversation (appended to root below). The founder wants the chat at
  // the bottom by the input and the log running on its own up top, without scrolling up through it to talk.
  for (const n of [empty, messages, briefRow, brief, busyRow]) scroll.appendChild(n);

  const form = elem(`<form id="chat-form" class="chat-form"></form>`);
  const input = elem(`<input id="chat-input" type="text" placeholder="ask or command…" autocomplete="off" />`) as HTMLInputElement;
  // #stopBtn lives in the input row, hidden by default. app.ts (the run owner) toggles its
  // visibility for the WHOLE run lifecycle — including a run started outside the chat (the
  // __kipi scripted-run hook the agent smoke uses) — so Stop is reachable whenever a run is live.
  const stopBtn = elem(`<button id="stopBtn" type="button" class="ghost chat-stop" hidden>Stop</button>`) as HTMLButtonElement;
  const send = elem(`<button id="chat-send" type="submit">Send</button>`) as HTMLButtonElement;
  // clu-chat-intake: attach files/images right from the chat (the one front door). The file input is
  // hidden; the 📎 button opens it. Drag-drop + clipboard-image paste route to the same handler.
  const attachBtn = elem(`<button id="chat-attach" type="button" class="ghost chat-attach" title="Attach files or images" aria-label="Attach files or images">📎</button>`) as HTMLButtonElement;
  const fileInput = elem(`<input id="chat-file" type="file" multiple accept="image/*,.pdf,.docx,.txt,.md,.markdown,.log,.csv,.tsv,.xlsx,.json" hidden />`) as HTMLInputElement;
  form.appendChild(attachBtn);
  form.appendChild(input);
  form.appendChild(stopBtn);
  form.appendChild(fileInput);
  form.appendChild(send);

  // cd-tradecraft: the analytical-gate bar (Scope/Challenge/Premortem + Timeline/Target/Reality-check),
  // ported from the Python webapp's chat checklist. Buttons mirror the typed commands; a gate shows ✓ once
  // its artifact exists. Built imperatively (textContent — never markup from data).
  const tcBar = elem(`<div class="tc-bar" role="toolbar" aria-label="Tradecraft"></div>`);
  // The inline Scope form (hidden until Scope is pressed) — question / hypotheses / proof.
  const scopeForm = elem(`<div class="tc-scope" hidden></div>`);
  const scopeQ = elem(`<input class="tc-scope-q" type="text" placeholder="The question this case must answer…" />`) as HTMLInputElement;
  const scopeH = elem(`<input class="tc-scope-h" type="text" placeholder="Hypotheses (optional)" />`) as HTMLInputElement;
  const scopeP = elem(`<input class="tc-scope-p" type="text" placeholder="What counts as proof (optional)" />`) as HTMLInputElement;
  const scopeSave = elem(`<button type="button" class="tc-scope-save">Save scope</button>`) as HTMLButtonElement;
  const scopeCancel = elem(`<button type="button" class="ghost tc-scope-cancel">Cancel</button>`) as HTMLButtonElement;
  const scopeRow = elem(`<div class="tc-scope-row"></div>`);
  scopeRow.appendChild(scopeSave);
  scopeRow.appendChild(scopeCancel);
  for (const n of [scopeQ, scopeH, scopeP, scopeRow]) scopeForm.appendChild(n);

  function refreshTradecraftBar(): void {
    const done = new Set(deps.tradecraftState().filter((s) => s.done).map((s) => s.step));
    tcBar.replaceChildren();
    // The primary action button — the CLICKABLE equivalent of typing "start investigation" (founder
    // 2026-06-24: the start/continue phrases must be buttons, not only typed). runCaseMode is incremental
    // (it reports the still-uninvestigated seeds), so one button both starts and continues the case.
    const startBtn = elem(`<button type="button" class="tc-start"></button>`) as HTMLButtonElement;
    startBtn.textContent = "▶ Start investigation";
    startBtn.title = "Run the whole case (continues from where it left off)";
    startBtn.disabled = busy;
    startBtn.addEventListener("click", () => { if (!busy) void runCaseMode(); });
    tcBar.appendChild(startBtn);
    for (const s of TRADECRAFT_STEPS) {
      const b = elem(`<button type="button" class="tc-step ${s.kind}"></button>`) as HTMLButtonElement;
      b.title = s.blurb;
      b.dataset.step = s.key;
      b.textContent = `${s.icon} ${s.label}${done.has(s.key) ? " ✓" : ""}`;
      b.addEventListener("click", () => onTradecraftStep(s.key));
      tcBar.appendChild(b);
    }
  }

  function onTradecraftStep(step: TradecraftStep): void {
    if (busy) return;
    if (step === "scope") {
      scopeForm.hidden = !scopeForm.hidden;
      if (!scopeForm.hidden) {
        // Re-hydrate from the saved scope so the form shows what was captured (it read as un-persisted when
        // it always opened blank — founder 2026-07-07). No saved scope → the empty form.
        const saved = deps.readScope();
        if (saved) { scopeQ.value = saved.question; scopeH.value = saved.hypotheses; scopeP.value = saved.proof; }
        scopeQ.focus();
      }
      return;
    }
    if (step === "challenge" || step === "premortem") { void runGate(step); return; }
    // helper: route the templated prompt through the normal dispatch (steers the investigator/Q&A).
    void dispatch(helperPromptFor(step, ""));
  }

  async function saveScope(): Promise<void> {
    if (!scopeQ.value.trim()) { scopeQ.focus(); return; }
    // hydra ISSUE-2 (secondary, founder 2026-07-07): a Save while a run is live used to silently no-op —
    // the busy branch just refocused with no feedback, so the founder saw "it didn't save." Surface it and
    // keep the typed text (no clear) so nothing is lost; stop the run, then Save again.
    if (busy) { pushAgent("a run is in progress — stop it and try again"); scopeQ.focus(); return; }
    try {
      // await: the durable scope write must land BEFORE we start the run / clear the form (hydra ISSUE-2).
      await deps.recordScope({ question: scopeQ.value, hypotheses: scopeH.value, proof: scopeP.value });
      scopeForm.hidden = true;
      scopeQ.value = scopeH.value = scopeP.value = "";
      pushAside("scope captured — starting investigation");
      refreshTradecraftBar();
    } catch (e) {
      pushAgent(e instanceof Error ? e.message : "Could not save scope.");
      return;
    }
    // Founder 2026-06-24: framing the scope IS the go signal — submitting it starts the whole-case run
    // (the 4points loop: frame the question → drive it). The scope is already composed into the case task.
    await runCaseMode();
  }
  scopeSave.addEventListener("click", () => void saveScope());
  scopeCancel.addEventListener("click", () => { scopeForm.hidden = true; });
  scopeQ.addEventListener("keydown", (e) => { if (e.key === "Enter") void saveScope(); });

  async function runGate(step: "challenge" | "premortem"): Promise<void> {
    const label = step === "challenge" ? "Challenge" : "Premortem";
    setBusy(true, `running ${label}…`);
    let res: { content: string } | null = null;
    try {
      res = await deps.runGate(step);
    } catch (e) {
      res = null;
      pushAgent(e instanceof Error ? e.message : `Could not run ${label}.`);
    }
    setBusy(false);
    if (res) {
      pushAgent(`**${label}**\n\n${res.content}`);
      refreshTradecraftBar();
      pushSuggestion(); // clu-conductor: after a gate, coach the next sequenced step (premortem → …)
    }
  }

  // scope-scroll-fix (founder 2026-07-07): LOG on top (own bounded scroll, streams on its own), then the
  // conversation scroll (flex:1), then the tradecraft bar + input at the bottom. #trail:empty is display:none
  // so the panel takes NO space until a run is live — an idle dock is all conversation.
  root.appendChild(trailWrap);
  root.appendChild(scroll);
  root.appendChild(tcBar);
  root.appendChild(scopeForm);
  root.appendChild(form);
  container.appendChild(root);
  refreshTradecraftBar();

  // ---- helpers ----
  function scrollDown(): void {
    requestAnimationFrame(() => { scroll.scrollTop = scroll.scrollHeight; });
  }
  function hideEmptyOnce(): void { empty.hidden = true; }
  // The chat's own busy state: shows the thinking line. #stopBtn visibility is owned by app.ts (the run
  // lifecycle), so a run started outside the chat still exposes Stop.
  // interrupt-redirect (founder 2026-07-03): the composer STAYS LIVE during a run so the analyst can steer
  // it mid-burst. Locking it (the old behavior) was the whole reason there was "no way to redirect" — you
  // couldn't type. While busy, Send relabels to "Redirect": submitting aborts the current run and starts a
  // new one with the typed text (handleSend → redirectTo). The separate #stopBtn just halts.
  function setBusy(on: boolean, label = ""): void {
    busy = on;
    input.disabled = false; // never lock the composer — the analyst must be able to redirect mid-run
    send.disabled = !input.value.trim();
    send.textContent = on ? "Redirect" : "Send";
    input.placeholder = on ? "redirect the investigation… (or press Stop)" : "ask or command…";
    busyRow.hidden = !on;
    busyText.textContent = label;
  }
  function pushYou(text: string): HTMLElement {
    hideEmptyOnce();
    const row = elem(`<div class="msg you"></div>`);
    const byline = elem(`<span class="msg-byline"></span>`);
    byline.textContent = "You"; // identity: byline, never markup from data
    const bubble = elem(`<span class="bubble you-bubble"></span>`);
    bubble.textContent = text; // literal: never reformat what the user typed
    row.appendChild(byline);
    row.appendChild(bubble);
    messages.appendChild(row);
    scrollDown();
    record({ role: "you", text }); // clu-chat-persist (no-op while replaying)
    return row;
  }
  function pushAgent(text: string, sources?: QaSource[]): HTMLElement {
    hideEmptyOnce();
    const row = elem(`<div class="msg agent"></div>`);
    const byline = elem(`<span class="msg-byline"></span>`);
    byline.textContent = "Investigator";
    row.appendChild(byline);
    const bubble = elem(`<span class="markdown bubble agent-bubble"></span>`);
    bubble.innerHTML = renderMarkdown(text); // escape-first XSS-safe (D10)
    row.appendChild(bubble);
    if (sources && sources.length) {
      const cite = elem(`<div class="sources"></div>`);
      cite.textContent = `grounded · ${sources.length} source(s)`;
      row.appendChild(cite);
    }
    messages.appendChild(row);
    scrollDown();
    record({ role: "agent", text, ...(sources && sources.length ? { sources } : {}) }); // clu-chat-persist
    return row;
  }
  // clu-conductor: post the conductor's suggested next step (the analyst acts on it — never auto-run).
  // Skipped on "done" so a finished case isn't nagged.
  function pushSuggestion(): void {
    const s = deps.conductorSuggestion();
    if (!s || s.step === "done") return;
    pushAgent(`**Next: ${s.title}**\n\n${s.detail}`);
  }
  function pushAside(text: string): HTMLElement {
    hideEmptyOnce();
    const row = elem(`<div class="msg aside"></div>`);
    const span = elem(`<span class="aside-text"></span>`);
    span.textContent = `· ${text} ·`;
    row.appendChild(span);
    messages.appendChild(row);
    scrollDown();
    return span; // clu-chat-intake: callers update an OCR progress line in place
  }

  // ---- live streaming bubble (chat-feels-like-a-product) ----
  // ONE live assistant bubble that the run loop types into token-by-token. It carries a `.streaming`
  // class (blinking caret) while live; streamEnd removes it so the curated final briefing (pushAgent)
  // is the durable turn — the stream is the "typing", the briefing is the "sent". Not persisted (record
  // is only for finished turns); a nav/refresh mid-run drops the half-bubble, which is correct.
  let streamRow: HTMLElement | null = null;
  let streamBuf = "";
  function streamDelta(text: string): void {
    if (!text) return;
    hideEmptyOnce();
    if (!streamRow) {
      streamBuf = "";
      streamRow = elem(`<div class="msg agent streaming"><span class="msg-byline">Investigator</span><span class="markdown bubble agent-bubble stream-bubble"></span></div>`);
      messages.appendChild(streamRow);
    }
    streamBuf += text;
    const bubble = streamRow.querySelector(".stream-bubble") as HTMLElement | null;
    if (bubble) bubble.innerHTML = renderMarkdown(streamBuf); // escape-first, redacted upstream
    scrollDown();
  }
  function streamEnd(): void {
    if (streamRow) { streamRow.remove(); streamRow = null; }
    streamBuf = "";
  }

  // ---- chronological ordering (holistic-fix P1) ----
  // scope-scroll-fix (founder 2026-07-07): the LOG (#trail) is a fixed top panel — NOT moved into the
  // conversation flow (the founder does not want to scroll up through the log to talk). remove-chat-findings
  // (2026-07-08): the #findings/#leads chip column that used to relocate to the conversation bottom here is
  // gone — the results now live on the graph + /runs. This just hides the empty-state on the first run.
  function relocateRunBlockToBottom(): void {
    hideEmptyOnce();
    scrollDown();
  }

  // ---- the three modes ----
  function describeCommand(c: GraphCommand): string {
    switch (c.kind) {
      case "showAll": return "showing everything";
      case "fit": return "fit to view";
      case "relayout": return "re-laying out";
      case "setLayout": return `layout: ${c.layout}`;
      case "search": return `searching "${c.query}"`;
      case "minScore": return `min score ≥ ${c.score}`;
      case "filterType": return `only ${c.etype}`;
      case "removeNode": return c.target ? `removing "${c.target}"` : "removing the selected node";
    }
  }
  function applyCommand(c: GraphCommand): void {
    const g = deps.graph();
    if (!g || !g.hasGraph()) { pushAside("no graph yet — run an investigation first"); return; }
    switch (c.kind) {
      case "showAll": g.showAll(); break;
      case "fit": g.fit(); break;
      case "relayout": g.reLayout(); break;
      case "setLayout": g.setLayout(c.layout); break;
      case "search": g.searchGraph(c.query); break;
      case "minScore": g.applyFilter({ minScore: c.score }); break;
      case "filterType": g.applyFilter({ etype: c.etype }); break;
      case "removeNode": g.removeNode(c.target); break; // node-removal: resolve target → exclude (app.ts shows Undo)
    }
    pushAside(describeCommand(c));
  }

  // Neutralize markdown-significant chars so a run objective stays LITERAL in the markdown bubble (the old
  // card used textContent). renderMarkdown already escapes HTML (XSS, D10); this stops a name like
  // "[x](javascript:…)" or "**x**" from becoming a link/emphasis in the summary line.
  function escapeMd(s: string): string {
    return (s || "").replace(/[\\`*_[\]()<>#!|~-]/g, (c) => `\\${c}`);
  }
  // remove-cards (founder 2026-07-03): the findings/runs summary is now a plain chat message, not a
  // `.runs-card`. The data is unchanged; only the surface is the conversation instead of a card.
  function showRunsSummary(mode: "findings" | "trail"): void {
    const runs = deps.listRuns();
    const total = runs.reduce((a, r) => a + r.promoted, 0);
    const head = mode === "findings" ? "Findings" : "Run trail";
    if (!runs.length) {
      pushAgent(`**${head}** — no runs yet. Investigate something to start.`);
      return;
    }
    const lines = runs
      .map((r) => `- ${escapeMd(r.objective)} — ${r.promoted} promoted · ${r.leads} leads · ${r.stopReason}`)
      .join("\n");
    pushAgent(`**${head}** — ${total} finding(s) across ${runs.length} run(s)\n\n${lines}`);
  }

  async function runObjectiveMode(raw: string): Promise<void> {
    const objective = objectiveFrom(raw);
    setBusy(true, `investigating ${objective}…`);
    setRunExpanded(true); // hydra ISSUE-6: a live run auto-opens the log so the analyst watches it stream
    let summary: { stopReason: string; promoted: number; leads: number; worked?: boolean; degradedReason?: string; briefing?: string } | null = null;
    let thrown: unknown = null;
    try {
      summary = await deps.runObjective(objective);
    } catch (e) {
      thrown = e; // runObjective normally swallows + returns null; this is the belt
      summary = null;
    }
    setBusy(false);
    setRunExpanded(false); // run over → fall back to the collapsed default (or the analyst's saved choice)
    if (summary && summary.stopReason !== "aborted" && summary.worked === false) {
      // kweb-findings-cutoff: same honesty as the case path — a cutoff / degraded objective run saved nothing.
      pushAgent(
        `The run didn't finish, so nothing was saved. ${summary.degradedReason ?? "It was cut off before a clean finish — raise the budget and re-run."}`,
      );
    } else if (summary && summary.stopReason !== "aborted") {
      lastObjective = objective;
      briefRow.hidden = false;
      // video-review 2026-06-25: show the agent's actual co-investigator briefing; fall back to the count line
      // only when the briefing couldn't be composed (no key / empty / error — runBriefingFor returns "").
      pushAgent(
        summary.briefing?.trim() ||
          `Done — **${summary.promoted}** promoted, **${summary.leads}** leads (${summary.stopReason}). ` +
            "Generate a brief below, or ask a question about what landed.",
      );
      pushSuggestion(); // clu-conductor: coach the next step (e.g. run Challenge before the brief)
    } else if (summary && summary.stopReason === "aborted") {
      // clu-error-output: a real Stop returns a result with stopReason "aborted" (not a throw) — show the
      // honest "stopped" line, NOT "Done … (aborted)" (codex). Partial findings are already in the graph.
      // interrupt-redirect: a redirect ALSO aborts this run — stay silent then (the new run speaks next).
      if (!pendingRedirect) pushAgent("Run stopped.");
    } else if (!pendingRedirect) {
      // clu-error-output: the HONEST cause — a mapped 401 / network / no-key (routing already handled by
      // app.ts), or "Run stopped." for an abort/superseded run. Never the old "no key / setup strip" guess.
      const err = thrown ? mapRunError(thrown) : deps.lastRunError();
      pushAgent(err ? err.message : "Run stopped.");
    }
    await maybeConsumeRedirect(); // interrupt-redirect: if a redirect was queued mid-run, run it now
  }

  // A3: the whole-case sweep — one un-caged pass over every seed; then surface the still-uninvestigated
  // entities as the analyst's next moves (suggest-not-auto: we list them, the analyst directs).
  async function runCaseMode(): Promise<void> {
    setBusy(true, "investigating the whole case…");
    setRunExpanded(true); // hydra ISSUE-6: a live run auto-opens the log so the analyst watches it stream
    let summary: Awaited<ReturnType<ChatDeps["runCase"]>> = null;
    let thrown: unknown = null;
    try {
      summary = await deps.runCase();
    } catch (e) {
      thrown = e;
      summary = null;
    }
    setBusy(false);
    setRunExpanded(false); // run over → fall back to the collapsed default (or the analyst's saved choice)
    if (summary && summary.stopReason !== "aborted" && summary.worked === false) {
      // kweb-findings-cutoff (founder 2026-06-24): a cutoff / degraded run saved NOTHING — never dress it up
      // as "the roster is worked" (the lie that hid this: a fully-worked case truncated its findings JSON,
      // returned 0, and still read as success). Surface the honest reason so the analyst raises budget + re-runs.
      pushAgent(
        `The case run didn't finish, so nothing was saved. ${summary.degradedReason ?? "It was cut off before a clean finish — raise the per-case budget and run the case again."}`,
      );
    } else if (summary && summary.stopReason !== "aborted") {
      briefRow.hidden = false;
      // video-review 2026-06-25: the agent's actual co-investigator briefing is the reply. Fall back to the
      // deterministic count line ONLY when the briefing couldn't be composed (no key / empty / error).
      let msg = summary.briefing?.trim() ?? "";
      if (!msg) {
        msg =
          `Worked the whole case (${summary.rosterSize} seed${summary.rosterSize === 1 ? "" : "s"}) — ` +
          `**${summary.promoted}** promoted, **${summary.leads}** leads (${summary.stopReason}).`;
        if (summary.pivots.length) {
          const names = summary.pivots.slice(0, 8).map((p) => p.name).join(", ");
          msg += ` Still uninvestigated: ${names}${summary.pivots.length > 8 ? "…" : ""}. ` +
            "Direct the next move (e.g. `investigate " + summary.pivots[0].name + "`), or generate a brief.";
        } else {
          msg += " The roster is worked. Generate a brief, or ask about what landed.";
        }
      }
      pushAgent(msg);
      pushSuggestion();
    } else if (summary && summary.stopReason === "aborted") {
      if (!pendingRedirect) pushAgent("Case run stopped."); // interrupt-redirect: silent if redirecting
    } else if (!pendingRedirect) {
      const err = thrown ? mapRunError(thrown) : deps.lastRunError();
      pushAgent(err ? err.message : "Case run stopped.");
    }
    await maybeConsumeRedirect(); // interrupt-redirect: run the queued redirect now, if any
  }

  async function questionMode(raw: string): Promise<void> {
    setBusy(true, "thinking…");
    try {
      // Statelessness fix (founder 2026-07-03): hand the recent real turns to Q&A so a follow-up works.
      // `history` already holds the just-pushed current question (dispatch pushYou'd it) — drop that tail
      // so the model sees it once, as QUESTION, not twice. Asides are never turns.
      const prior = history
        .filter((m) => m.role === "you" || m.role === "agent")
        .map((m) => ({ role: m.role as "you" | "agent", text: m.text }));
      if (prior.length && prior[prior.length - 1].role === "you" && prior[prior.length - 1].text === raw) prior.pop();
      // Node-reference: pass the analyst's SELECTED graph node so "what is this?" resolves to it.
      const { answer, sources } = await deps.answer(raw, deps.selectedName(), prior);
      pushAgent(answer, sources);
    } catch (e) {
      pushAgent(e instanceof Error ? e.message : "Could not answer that.");
    }
    setBusy(false);
  }

  function tradecraftMode(raw: string): Promise<void> | void {
    const c = parseTradecraftCommand(raw);
    if (!c) return;
    if (c.kind === "scope") {
      scopeForm.hidden = false;
      if (c.question.trim()) scopeQ.value = c.question.trim();
      scopeQ.focus();
      return;
    }
    if (c.kind === "gate") return runGate(c.step);
    return dispatch(helperPromptFor(c.step, c.subject)); // helper: route the templated prompt normally
  }

  function policyLine(policy: ChatActionPolicy): string {
    if (policy.kind === "blocked") {
      if (policy.risk === "raw_upload_dump") {
        return "I can’t dump raw uploads onto the graph. Raw uploads need extraction, typing, and gating before they affect graph state.";
      }
      return "I can’t do that directly. Destructive durable-state changes cannot be committed from chat text alone.";
    }
    if (policy.kind === "needs_capability") {
      return `${policy.capability ?? "That provider"} is not configured. I can use available pivots now, or you can add the key in Account.`;
    }
    if (policy.kind === "propose") {
      if (policy.risk === "ungrounded_edge") return "I can treat that as a relationship proposal, but co-occurrence is only a hint. verify with evidence before adding an edge.";
      if (policy.target === "finding") return "I can treat that as a proposed finding, but it needs evidence and gating before it is saved.";
      if (policy.target === "relationship") return "I can treat that as a relationship proposal, but it needs investigated evidence before it is saved.";
      return "I can propose that change, but I won’t commit durable state from chat text alone.";
    }
    return policy.reason;
  }

  function proposedActionFor(policy: ChatActionPolicy): ProposedActionCard {
    if (policy.target === "graph") {
      return {
        id: `act-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
        kind: "remove_graph_node",
        title: "Remove graph node?",
        body: `Remove "${policy.targetValue ?? "selected node"}" from this case view. This is reversible from the undo toast.`,
        target: policy.targetValue ?? "",
        approveLabel: "Remove",
        cancelLabel: "Cancel",
      };
    }
    if (policy.target === "finding") {
      return {
        id: `act-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
        kind: "promote_finding",
        title: "Proposed finding",
        body: "This needs evidence and gating before it can be saved as a finding.",
        approveLabel: "Review",
        cancelLabel: "Cancel",
      };
    }
    return {
      id: `act-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
      kind: "add_relationship",
      title: "Proposed relationship",
      body: policyLine(policy),
      approveLabel: "Review",
      cancelLabel: "Cancel",
    };
  }

  // remove-cards (founder 2026-07-03): a durable change (e.g. remove a node) is confirmed by TYPING `yes` in
  // the chat, not an Approve/Cancel card. proposeAction states the change + parks a pending confirmation; the
  // next turn's yes/no resolves it (handled at the top of dispatch). A non-committable proposal (a finding /
  // relationship that still needs evidence) just explains itself — nothing to confirm, so no pending state.
  let pendingConfirm: { policy: ChatActionPolicy; action: ProposedActionCard } | null = null;
  const YES_RE = /^(y|yes|yep|yeah|confirm|do it|go)$/i;
  function proposeAction(policy: ChatActionPolicy): void {
    const action = proposedActionFor(policy);
    // Only a graph mutation (remove_graph_node) has a client-side commit path; the others are explanatory.
    if (action.kind === "remove_graph_node") {
      pendingConfirm = { policy, action };
      pushAgent(`${action.body}\n\nReply **yes** to confirm, or anything else to cancel.`);
    } else {
      pushAgent(policyLine(policy)); // finding/relationship proposal: needs evidence + gating, nothing to confirm
    }
  }
  // Resolve a parked confirmation with the analyst's reply. Returns true if it consumed the input.
  async function resolvePendingConfirm(raw: string): Promise<boolean> {
    if (!pendingConfirm) return false;
    const { policy, action } = pendingConfirm;
    pendingConfirm = null;
    pushYou(raw);
    if (!YES_RE.test(raw.trim())) { pushAgent("Cancelled."); return true; }
    const result = await commitChatAction({ policy, action }, deps.commitProposedAction);
    pushAgent(result.ok ? `Done — ${action.title.replace(/\?$/, "")}.` : result.reason);
    return true;
  }

  // The single router. handleSend feeds the typed input here; the tradecraft helpers feed a templated
  // prompt here so they take the SAME path (objective/Q&A) — one classify, one place.
  async function dispatch(raw: string): Promise<void> {
    const t = raw.trim();
    if (!t || busy) return;
    // remove-cards: a parked durable-change confirmation consumes the next turn (yes/no), before any classify.
    if (await resolvePendingConfirm(t)) return;
    const policy = classifyChatAction(t);
    if (policy.kind === "blocked" || policy.kind === "needs_capability") {
      pushYou(t);
      pushAgent(policyLine(policy));
      return;
    }
    if (policy.kind === "propose") {
      pushYou(t);
      proposeAction(policy);
      return;
    }
    const mode = classifyInput(t);
    if (mode === "command") { const c = parseGraphCommand(t); if (c) applyCommand(c); return; }
    if (mode === "runs") { pushYou(t); showRunsSummary(/find/i.test(t) ? "findings" : "trail"); return; }
    if (mode === "help") { pushYou(t); pushAgent(TOOL_GUIDE); return; }
    if (mode === "tradecraft") { await tradecraftMode(t); return; }
    pushYou(t);
    if (mode === "case") await runCaseMode(); // A3: whole-case sweep
    else if (mode === "objective") await runObjectiveMode(t);
    else await questionMode(t);
  }

  async function handleSend(): Promise<void> {
    const raw = input.value.trim();
    if (!raw) return;
    input.value = "";
    send.disabled = true;
    // interrupt-redirect: a submit WHILE a run is live is a redirect — abort the current run and re-run with
    // the new text. Otherwise it's a normal dispatch. (busy is set by setBusy at run start.)
    if (busy) { redirectTo(raw); return; }
    await dispatch(raw);
  }

  // interrupt-redirect (founder 2026-07-03): steer a running investigation mid-burst. kipi-web runs the agent
  // as a browser Messages-API loop (no warm-session interrupt+requery), so "redirect" = abort the in-flight
  // run and start a fresh one with the new text, keeping every finding already persisted. `pendingRedirect`
  // is consumed by the run functions the instant the aborted run settles (maybeConsumeRedirect), so the new
  // run starts AFTER the current one has fully unwound — never two live runs racing the same graph.
  let pendingRedirect: string | null = null;
  function redirectTo(raw: string): void {
    pendingRedirect = raw;
    pushAside(`redirecting — stopping the current run, starting: ${raw}`);
    deps.stop(); // abort the live run's AbortController; it resolves stopReason "aborted" → maybeConsumeRedirect
  }
  // Called at the end of a run function once it has settled. If a redirect is queued, run it now (busy is
  // already false, so dispatch proceeds). Returns true if it consumed one (the caller then skips its own
  // terminal messaging path already guarded above).
  async function maybeConsumeRedirect(): Promise<void> {
    if (!pendingRedirect) return;
    const next = pendingRedirect;
    pendingRedirect = null;
    await dispatch(next);
  }

  // ---- clu-chat-intake: file/image/paste intake → ingest → completeness check ----
  // One front door: attach/drop/paste evidence; each file decodes (OCR'd with a live progress line) and
  // persists through the ingestText gate (app.ts); then the conductor posts an honest completeness read.
  async function ingestFiles(files: File[]): Promise<void> {
    if (!files.length || busy) return;
    setBusy(true, files.length === 1 ? "Reading evidence…" : `Reading ${files.length} files…`);
    const all: ExtractedEntity[] = [];
    const warnings: string[] = [];
    try {
      for (let i = 0; i < files.length; i++) {
        // The raw File.name is NEVER rendered (a key in a filename would leak to the chat DOM before
        // redaction; codex). The progress line is positional; the final line uses the redacted safeName.
        const which = files.length > 1 ? ` (${i + 1}/${files.length})` : "";
        const line = pushAside(`reading file${which}…`);
        const onProgress: OcrProgressCb = (p: OcrProgress) => {
          line.textContent = `· OCR${which}: ${p.stage} ${Math.round((p.progress || 0) * 100)}% ·`;
        };
        try {
          const res = await deps.ingestFile(files[i], onProgress);
          all.push(...res.entities);
          if (res.warnings) warnings.push(...res.warnings);
          const n = res.entities.length;
          line.textContent = `· ${res.safeName}: ${n} entit${n === 1 ? "y" : "ies"}${res.kind === "image" ? " (OCR)" : ""} ·`;
        } catch {
          line.textContent = `· could not read that file${which} ·`; // neutral; E owns precise error wording
        }
      }
      pushAgent(renderCompleteness(intakeCompleteness(all)));
      for (const w of warnings) pushAside(w);
      deps.onIngested?.();
      pushSuggestion(); // clu-conductor: coach the next step after intake
    } finally {
      setBusy(false);
    }
  }

  /** Ingest pasted PLAIN TEXT as a document (the chat's paste-a-report path). */
  async function ingestText(text: string): Promise<void> {
    if (!text.trim() || busy) return;
    setBusy(true, "Reading pasted text…");
    try {
      const res = await deps.ingestPastedText(text);
      pushAgent(renderCompleteness(intakeCompleteness(res.entities)));
      deps.onIngested?.();
      pushSuggestion(); // clu-conductor: coach the next step after intake
    } catch {
      pushAside("could not ingest the pasted text"); // neutral; E owns wording
    } finally {
      setBusy(false);
    }
  }

  // ---- events ----
  form.addEventListener("submit", (e) => { e.preventDefault(); void handleSend(); });
  input.addEventListener("input", () => { send.disabled = !input.value.trim(); }); // live during a run (redirect)
  stopBtn.addEventListener("click", () => deps.stop());

  // clu-chat-intake: the attach button opens the hidden file picker; selection ingests.
  attachBtn.addEventListener("click", () => { if (!busy) fileInput.click(); });
  fileInput.addEventListener("change", () => {
    const files = Array.from(fileInput.files ?? []);
    fileInput.value = ""; // reset so re-selecting the same file fires change again
    void ingestFiles(files);
  });
  // Clipboard paste: files/images (e.g. a pasted screenshot) ingest; a LARGE multi-line text paste into
  // an empty box is treated as a pasted report; short text pastes type normally (no typing hijack).
  input.addEventListener("paste", (e) => {
    const cd = e.clipboardData;
    if (!cd) return;
    const files = Array.from(cd.files ?? []);
    if (files.length) { e.preventDefault(); void ingestFiles(files); return; }
    const text = cd.getData("text") ?? "";
    if (!input.value.trim() && text.length >= 400 && /\n/.test(text)) { e.preventDefault(); void ingestText(text); }
  });
  // Drag-drop files onto the dock.
  root.addEventListener("dragover", (e) => { e.preventDefault(); root.classList.add("drag-over"); });
  root.addEventListener("dragleave", (e) => { if (e.target === root) root.classList.remove("drag-over"); });
  root.addEventListener("drop", (e) => {
    e.preventDefault();
    root.classList.remove("drag-over");
    const files = Array.from(e.dataTransfer?.files ?? []);
    if (files.length) void ingestFiles(files);
  });
  briefBtn.addEventListener("click", () => { if (lastObjective) void deps.generateBrief(lastObjective); });
  dlBriefBtn.addEventListener("click", () => deps.downloadBrief());
  // Click a node name (`code`/**bold**) in a reply → spotlight it on the canvas (chat → graph).
  messages.addEventListener("click", (e) => {
    const el = (e.target as HTMLElement).closest(".chat-node");
    if (!el) return;
    deps.graph()?.highlightByName((el.textContent || "").trim());
  });
  send.disabled = true;

  // clu-chat-persist: rehydrate the prior conversation for the active case BEFORE the bridge is live, so a
  // refresh / nav / tab-switch reopens onto the same chat instead of an empty dock (the founder-reported
  // bug). `replaying` suppresses re-persist; we seed `history` directly so future turns append onto it.
  replaying = true;
  try {
    for (const m of deps.loadChat()) {
      if (m.role === "you") pushYou(m.text);
      else if (m.role === "agent") pushAgent(m.text, m.sources as QaSource[] | undefined);
      else pushAside(m.text);
      history.push(m);
    }
  } finally {
    replaying = false;
  }

  // ---- the chat bridge (graph → chat). Payloads are already key-redacted client data (D4). ----
  const bridge: KipiChatBridge = {
    // remove-cards: node/edge clicks no longer push a card into the chat (selection is graph-side). These
    // stay as no-ops so any stray caller is inert; node detail comes via askInChat (the right-click menu).
    showNode: () => {},
    showEdge: () => {},
    askInChat: (t) => { void dispatch(t); },
    showNodeDetails: (node) => { pushAgent(formatNodeDetail(node, deps.entityView(node))); },
    pushAgent: (t) => pushAgent(t),
    pushAside: (t) => pushAside(t),
    streamDelta: (t) => streamDelta(t),
    streamEnd: () => streamEnd(),
    relocateRunBlockToBottom: () => relocateRunBlockToBottom(),
  };
  window.__kipiChat = bridge;
  const onUnload = () => { window.__kipiChat = null; };
  window.addEventListener("beforeunload", onUnload);

  teardown = () => {
    window.__kipiChat = null;
    window.removeEventListener("beforeunload", onUnload);
    teardown = null;
  };
}

/** Clear the chat dock's global bridge registration (called on lock / unlock / re-render). */
export function unmountChatDock(): void {
  if (teardown) teardown();
  else window.__kipiChat = null;
}

// remove-cards (founder 2026-07-03): the DETERMINISTIC entity detail (score / typed rels / appears-in /
// dossier) rendered as a CHAT MESSAGE — the old node card's data, no LLM, as markdown text. renderMarkdown
// escapes HTML (D10); mdLiteral neutralizes markdown so a hostile entity value stays literal. Only sections
// with data render (honest empty: an un-Processed node shows just the header line).
function mdLiteral(s: string): string {
  // Only neutralize STRUCTURAL markdown (emphasis / code / link brackets / the escape char). `<`/`>` are left
  // to renderMarkdown's escape-first HTML-escaping (they render as literal text, XSS-safe) so we don't paint
  // visible backslashes over every angle bracket, dash, or paren.
  return (s || "").replace(/[\\`*_[\]]/g, (c) => `\\${c}`);
}
function formatNodeDetail(node: CyNodeData, view: EntityView): string {
  const parts: string[] = [];
  const scoreLine = view.score ? ` — attention score **${view.score.total}** (${mdLiteral(view.score.role)})` : "";
  parts.push(`**${mdLiteral(node.full_name)}**${scoreLine}`);
  // status line from the graph node itself (always available, even pre-Process): the same promoted/lead/seed
  // meta the old node card showed. type · origin · gate status.
  const status = node.kind === "objective" ? "seed objective" : node.promoted ? "promoted (on graph)" : "lead (held)";
  const origin = node.origin === "osint" ? "investigated" : "seed";
  parts.push(`${mdLiteral(node.type || "node")} · ${origin} · ${status}`);
  if (!view.found) {
    parts.push("_No further computed detail yet — Process the case, or ask me about it._");
    return parts.join("\n\n");
  }
  if (view.dossier && view.dossier.lines.length) {
    parts.push([`_${mdLiteral(view.dossier.headline)}_`, ...view.dossier.lines.map((l) => `- ${mdLiteral(l)}`)].join("\n"));
  }
  if (view.typedRels.length) {
    const rels = view.typedRels.slice(0, 8).map((r) => {
      const arrow = r.direction === "in" ? "←" : "→";
      return `- ${arrow} ${mdLiteral(r.relType)} ${mdLiteral(r.otherLabel)} (${mdLiteral(r.confidence)})`;
    });
    parts.push(["**Typed relationships**", ...rels].join("\n"));
  }
  if (view.connections.length) {
    const cons = view.connections.slice(0, 8).map((c) => `- ${mdLiteral(c.otherLabel)} (${mdLiteral(c.otherType)}, ${mdLiteral(c.confidence)})`);
    parts.push(["**Connections**", ...cons].join("\n"));
  }
  if (view.appearances.length) {
    const aps = view.appearances.slice(0, 8).map((a) => {
      const tag = a.promoted ? `promoted${a.grade ? ` ${mdLiteral(a.grade)}` : ""}` : "lead";
      return `- ${mdLiteral(a.objective)} — ${tag}`;
    });
    parts.push(["**Appears in**", ...aps].join("\n"));
  }
  return parts.join("\n\n");
}

function elem(html: string): HTMLElement {
  const d = document.createElement("div");
  d.innerHTML = html.trim();
  return d.firstElementChild as HTMLElement;
}
