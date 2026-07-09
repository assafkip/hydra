// kipi-web spine app: a real (minimal) UI plus a window.__kipi debug API the
// Playwright smoke drives deterministically. All durable state is the encrypted
// vault; the backend is chosen at launch (PRD-11): a user-picked disk folder when
// configured + supported + granted, else OPFS. OSINT runs live from the browser.
// No inline handlers (script-src 'self').

import { Vault, VaultError } from "./vault/vault.js";
import { opfsStorage, type VaultStorage } from "./vault/store.js";
import { buildFeedbackUrl, FEEDBACK_DISCLOSURE, buildBugReportUrl, BUG_DISCLOSURE } from "./feedback.js";
import { registerServiceWorker } from "./pwa.js";
import {
  pickBackend,
  diskBackend,
  opfsBackend,
  supportsDiskPicker,
  exportVault,
  importVault,
  VAULT_FILE,
  type Backend,
} from "./vault/location.js";
import { pickDirectory, saveHandle, loadHandle, requestGranted, clearHandle } from "./vault/handle.js";
import { rememberDataKey, recallDataKey, forgetDataKey } from "./vault/session.js";
import { runPivot } from "./osint/index.js";
import { pivotLinks } from "./osint/pivots.js"; // A5: per-entity external OSINT pivot links (analyze.py:526)
import {
  runInvestigation,
  investigateCase,
  type InvestigateCaseResult,
  generateBrief,
  graphModelForRunNetwork,
  graphModelForCase,
  growCaseGraph,
  growCaseNetwork,
  expandFromNode,
  answerQuestion,
  runBriefingFor,
  recordScope,
  getScopeFields,
  runTradecraftGate,
  tradecraftState,
  entityDbFor,
  aiDossierFor,
  DOSSIER_PREFIX,
  semanticRelationsFor,
  consolidateEntities,
  typeEntities,
  availableTransforms,
  transformNode,
  setAnalyst,
  getAnalyst,
  applyCorrection,
  revertCorrection,
  listCorrections,
  excludeEntity,
  restoreEntity,
  type CorrectionRow,
  alertsFor,
  ackAlert,
  ackAllAlerts,
  setReportNotes,
  getReportNotes,
  runEntities,
  clustersFor,
  crossDomainEntities,
  bridgesFor,
  focusFor,
  ingestText,
  type CrossDomainEntity,
  type Bridge,
  type Focus,
  listRuns,
  listBriefs,
  getBrief,
  getBriefMeta,
  liveReportCount,
  synthesizeCaseBrief,
  generateGroupBriefs,
  setApiKey,
  hasApiKey,
  getApiKey,
  SECRET_PREFIX,
  providerStatus,
  setProviderKey,
  clearProviderKey,
  getProviderKey,
  enrichTarget,
  enrichStats,
  listEnrichRuns,
  getEnrichRunDetail,
  getWorkerUrl,
  setWorkerUrl,
  getOnboarded,
  setOnboarded,
  enrichViaProxy,
  runProcess,
  PROCESS_STEPS,
  analysisFor,
  // sf-entity-detail: the per-entity DETAIL-fold projections (the entity.html depth). All READ-ONLY +
  // key-redacted at the session layer, except setEntityDossierOverride (the ONE editable persisted key).
  entityScoreBreakdownFor,
  typedRelationshipsFor,
  entityCorrectionsFor,
  entityAppearancesFor,
  getEntityDossierOverride,
  setEntityDossierOverride,
  activityFor,
  exportFilesFor,
  scopedVault,
  activeCaseId,
  setActiveCase,
  listCases,
  createCase,
  deleteCase,
  migrateLegacyData,
  reportModelFor,
  saveReportSummaryEdit,
  clearReportSummaryEdit,
  loadChatHistory,
  saveChatHistory,
  persistLiveRun,
  readLiveRun,
  clearLiveRun,
  persistLiveRunSteps,
  readLiveRunSteps,
  type ProvidersView,
  type EnrichResult,
  type ChatMessage,
} from "./agent/session.js";
import { enrichProvider } from "./osint/enrich.js";
import { probeWorker, type WorkerProbe } from "./osint/proxy.js"; // hydra-see-sites: "Test connection" probe
import { lifecycleStages, conductorStateFor, suggestNextStep } from "./lifecycle.js";
import { isDetailRoute, routeKind, detailRouteLabel, mountCanvasTakeover } from "./canvas-mode.js";
import { connId, type SemanticRelation } from "./entity/relations.js";
import type { ConsolidateSuggestion, TypingSuggestion } from "./entity/consolidate.js";
import { clusterFor, type Cluster } from "./entity/clusters.js";
import { SupabaseAuth, AuthError } from "./auth/supabase.js";
import { loadGithubStars, githubStarAnchor } from "./github-stars.js";
import { Identity } from "./auth/identity.js";
import { fileToText } from "./ingest/files.js";
import { extractEntities } from "./ingest/extract.js"; // clu-chat-intake: count entities for the completeness check
import { mergeEntities } from "./ingest/record.js"; // ig-record: union structured CSV/XLSX entities with flat extraction
import { renderMarkdown } from "./chat/markdown.js";
import type { Step, InvestigateResult, ObservedEvent } from "./agent/loop.js";
import { isAdmissible, collapseObservedTwins } from "./agent/gate.js";
import { createRunEventBus, type RunEventSummary } from "./agent/live-events.js";
// rsn-run-store: the run's durable state, decoupled from the dock/view DOM (so a nav-away never orphans
// the trail — rca-nav-during-run-orphans-run-and-graph). app.ts is the single writer; the dock projects it.
import { beginRun, recordRunStep, recordRunFindings, setRunStatus, getRunStore, resetRunStore, isRunActive, formatRunProgress, formatRunDone } from "./run-store.js";
import { displayTrail } from "./agent/runtrail.js";
import { CyGraph, type SetMember } from "./graph/cy-graph.js";
import type { CyNodeData } from "./graph/cy-adapter.js";
import { legendSpec } from "./graph/cy-adapter.js"; // A4: drift-checked legend source of truth
import type { GraphModel } from "./graph/model.js";
import { getEntity, connectionsFor, coOccurrencesFor, edgeEvidence, buildDossier, allEntities, canonKey, type EntityStore, type EntityRecord, type Connection } from "./entity/db.js";
import type { AnalysisRecord } from "./entity/analysis.js";
import { mountChatDock, unmountChatDock, type ChatDeps, type KipiGraph, type EntityView, type EdgeView, type EdgeCardData } from "./chat/dock.js";
import { mapRunError, expandResultLine, isAbortError, type MappedError } from "./chat/errors.js";
import {
  renderEntitiesPage,
  renderClustersPage,
  renderBridgesPage,
  renderFocusPage,
  renderRunsPage,
  renderDeliverablesPage,
  renderGroupedBriefsPage,
  renderCrossCasePage,
  renderReportsPage,
  renderEnrichPage,
  renderCapabilitiesPage,
  renderFullToolPage,
  renderToolsPage,
  renderInboxPage,
  renderCrossDomainPage,
  renderCorrectionsPage,
  renderActivityPage,
  renderExportsPage,
  renderCasesPage,
  renderReportPage,
  renderAlertsPage,
  closeAllEntityMenus,
  type PageDeps,
  type ProcessUiState,
} from "./pages.js";
import type { FetchLike } from "./osint/types.js";

// sf-cases: `vault` is the case-SCOPED VIEW every projection/writer uses; `rawVault` is the real unlocked
// vault (lock/changePassword/case-management). applyVault sets both, deriving the scoped view from the active
// case — scoped only when a case is active (no implicit default; a caseless vault renders the empty state).
let rawVault: Vault | null = null;
let vault: Vault | null = null;
// auth-gate-nav (founder 2026-06-25): the Anthropic + OSINT provider keys are GLOBAL (the secret: namespace,
// shared across cases — session.ts:1959), but the key cards keyed off the SCOPED `vault`, which is NULL until
// the first case exists. So a brand-new user could not add ANY key before creating a case — and the no-case
// gate also blocked the key pages. keyVault() falls back to the unscoped rawVault so the global keys work
// BEFORE the first case (secret: keys live on the raw vault; scopedVault forwards them unchanged anyway).
function keyVault(): Vault | null { return vault ?? rawVault; }
function applyVault(v: Vault | null): void {
  // sec (FAANG HIGH): a vault-IDENTITY change (unlock a different vault, lock, reset) clears the prior
  // session's case-derived in-memory state — else its decrypted graph bleeds into the new vault on a
  // non-home route (clustersFor/exportFilesFor/reportModelFor read lastGraphModel as `current`). A
  // same-instance re-scope (a case switch calls applyVault(rawVault)) is NOT an identity change and is
  // already cleared by switchCase, so v === rawVault must NOT re-clear.
  if (v !== rawVault) clearCaseDerivedState();
  rawVault = v;
  // sf-cases: scope to the active case ONLY when one is active. No implicit "default" — a fresh vault (or one
  // whose last case was deleted) has activeCaseId()==="" → scoped `vault` is null → the create-first-case
  // empty state renders. scopedVault throws on an empty id, so the guard is required, not cosmetic.
  vault = v && activeCaseId(v) ? scopedVault(v, activeCaseId(v)) : null;
  // stay-signed-in (clu-auth): persist the non-extractable data key on every unlock site (this is the
  // single chokepoint — create/login/recovery/restore/case-switch all pass through here). A lock passes
  // null and is skipped, so the persisted key survives an idle-lock / reload; only Sign out forgets it.
  if (v && !v.locked) void rememberDataKey(v.sessionKey());
  armIdleLock(); // sec: (re)arm the idle auto-lock on unlock; clear it on lock (vault === null)
}

// stay-signed-in (clu-auth): on load, if there is no in-memory vault but the device holds a vault file
// AND a persisted session key, restore the unlocked session with NO password. A key that no longer
// matches the file (e.g. after a reset) throws in restore → self-heal by forgetting it.
// sf-cases: the SINGLE unlock chokepoint — migrate any un-prefixed legacy data into a real case (idempotent;
// no-op after the first time + on a brand-new vault) BEFORE scoping, so the active case is correct on first
// render. Every freshly-unlocked vault (restore / login / recovery) routes through here.
async function unlockInto(v: Vault): Promise<void> {
  await migrateLegacyData(v);
  applyVault(v);
}

async function bootstrapSession(): Promise<void> {
  if (rawVault) return;
  try {
    if (!(await Vault.exists(storage))) return;
    const key = await recallDataKey();
    if (!key) return;
    await unlockInto(await Vault.restore(storage, key));
  } catch {
    await forgetDataKey().catch(() => {});
  }
}

// sec / sf-cases: clear ALL case-derived in-memory state. It survives independent of the vault keys —
// projections read lastGraphModel as `current`, the node/transform/drawer sets are per-graph-generation,
// the suggestion caches are per-case — so both a vault-identity change (applyVault) AND a case switch
// (switchCase) must wipe it. Pure + synchronous (the switchCase fence relies on no await here).
function clearCaseDerivedState(): void {
  processAbort?.abort();
  processAbort = null;
  if (autoProcessTimer) { clearTimeout(autoProcessTimer); autoProcessTimer = null; } // a pending auto-process must NOT fire into the new case
  autoProcessPending = false;
  activeAbort?.abort();
  activeAbort = null;
  // rsn-case-switch-wipe: the run store outlives render() (that is the point — a nav must not lose the
  // trail), so a case switch / lock / reset MUST wipe it here, next to the activeAbort+lastGraphModel
  // clears. Otherwise a run started in case A would replay its trail/findings into case B on reattach —
  // a confidentiality bug in a zero-retention app, not just a UX glitch (prd-run-survives-navigation).
  resetRunStore();
  runEvents.reset();
  runEventMeta.clear();
  // rsn-run-chip: hide the off-Workspace chip SYNCHRONOUSLY here, the instant the run is aborted + the store
  // reset — do not wait for the trailing render(). switchCase awaits setActiveCase() before that render(); if
  // it is slow the chip would briefly show a false "running", and if it throws render() never runs and the
  // aborted run's finally is fenced out by the runSeq++ below — either way the chip could otherwise linger with
  // a now-dead Stop (codex). updateRunChip is pure-synchronous, so it respects this function's no-await invariant.
  // A case switch also CANCELS any terminal-flash hold: inside the 5s "✓ Done" window updateRunChip early-returns,
  // which would carry case A's objective label into case B (codex blocker, kweb-run-chip-control-contract).
  // Cancel the flash TIMER too, or a stale case-A timeout fires inside case B and clears B's own flash early
  // (codex adversarial). Both the hold and its timer die with the case.
  if (runChipFlashTimer != null) { clearTimeout(runChipFlashTimer); runChipFlashTimer = null; }
  runChipFlashUntil = 0;
  updateRunChip();
  runSeq++;
  graphGen++;
  caseGen++;
  lastGraphModel = null;
  consolidateCache.clear();
  typeCache.clear();
  expandedNodeIds.clear();
  inFlightNodeIds.clear();
  transformDone.clear();
  transformInFlight.clear();
  lastTransformResult.clear();
  selectedNodeData = null;
  pendingFocusKey = null;
  pendingKeyFocus = false;
  pendingBriefObjective = null;
  processJob = { status: "idle", steps: PROCESS_STEPS.map((s) => ({ key: s.key, label: s.label, status: "pending" as const })), log: [] };
  cyGraph?.destroy();
  cyGraph = null;
}

// sf-cases: switch the active case. Re-deriving the scoped vault is NOT enough (codex blocker) — the
// case-DERIVED in-memory state (lastGraphModel, the consolidate/type caches, the run/Process job, the
// pending focus, the live graph) survives independent of the vault keys and clustersFor/bridgesFor/focusFor/
// exportFilesFor/reportModelFor read lastGraphModel as `current`. So: ABORT in-flight run/Process, CLEAR all
// case-derived state, THEN re-scope + re-render — a switch shows ZERO of the prior case's data.
async function switchCase(id: string): Promise<void> {
  if (!rawVault) return;
  // sync pre-validate so an invalid id never aborts an in-flight run (setActiveCase re-validates below). "" is
  // valid — it clears the active case (the empty state, e.g. after deleting the last case).
  if (id !== "" && !listCases(rawVault).some((c) => c.id === id)) return;
  // (1) FENCE SYNCHRONOUSLY — BEFORE any await (codex round-2): setActiveCase's await yields, and a late
  // run/Process/expand completion that captured the OLD case's scoped vault could slip through and render
  // case A's result into B. So abort + bump the generation guards + clear case-derived in-memory state FIRST,
  // with no intervening await. The run gate `if (myRun !== runSeq) return` + the expand gate `gen === graphGen`
  // then fail for every in-flight async; processAbort aborts the Process job.
  clearCaseDerivedState();
  // (2) persist the active case (GLOBAL setting:, re-validated) + re-derive the scoped vault + re-render.
  await setActiveCase(rawVault, id);
  applyVault(rawVault);
  await render();
}
let backend: Backend = opfsBackend();
let storage: VaultStorage = backend.storage;

// PRD-3: per-run fence — a newer run supersedes an older one's trail/render.
let runSeq = 0;
let activeAbort: AbortController | null = null;
// clu-error-output: the honest cause of the LAST investigator run failure (null when it succeeded or was
// aborted). startInvestigation swallows the throw to do its own UI, so the dock reads this to show WHY a
// run didn't finish — never the old "no key / setup strip" guess.
let lastInvestigateError: MappedError | null = null;

// cd-ui: the chat dock drives runs/Q&A/brief through the SAME app.ts chokepoints. The test seam
// (installChatWire) injects a scripted Anthropic wire so the live-streaming smoke drives the REAL
// loop without a key/network; production leaves it null (real fetch).
let chatWire: {
  runFetch?: FetchLike;
  toolOpts?: { fetchImpl?: FetchLike; retries?: number };
  qaFetch?: FetchLike;
  dossierFetch?: FetchLike; // adr-wire: scripted AI-dossier wire (smoke); production = real fetch
  relationsFetch?: FetchLike; // adr-wire: scripted semantic-relations wire (smoke)
  enrichFetch?: FetchLike; // en-wire: scripted provider wire (smoke); production = real fetch
  consolidateFetch?: FetchLike; // ct-wire: scripted consolidate classify wire (smoke)
  typeFetch?: FetchLike; // ct-wire: scripted typing classify wire (smoke)
  schemaFetch?: FetchLike; // pf-process: scripted understand-pass wire (smoke); production = real fetch
  analyzeFetch?: FetchLike; // ca-analyze (INC-3): scripted analyze-pass wire (smoke); production = real fetch
  synthesizeFetch?: FetchLike; // INC-4b: scripted case-brief wire (smoke); production = real fetch
  groupBriefFetch?: FetchLike; // sf-briefs: scripted group-summary wire (smoke); production = real fetch
} | null = null;

// video-review 2026-06-25: gate the post-run co-investigator briefing's model call. Production (no scripted
// wire) always briefs; in a SMOKE (chatWire set) only brief when the briefing fetch (qaFetch) is scripted, so
// the call never escapes to the real network — a run-only smoke (turns, no qaText) skips it and keeps the
// deterministic count line. The briefing reuses the qaFetch wire (it is a single judgment completion, like Q&A).
function briefingAllowed(): boolean {
  return !chatWire || !!chatWire.qaFetch;
}

// pf-process (INC-1): the Process pipeline job state — the app-level source of truth (PRD D8). runProcess
// runs CLIENT-SIDE; onStep/onLog callbacks aggregate into processJob, which is pushed to the subscribed
// /reports panel. A run fence (processAbort) lets a new Process click supersede a prior in-flight run.
let processJob: ProcessUiState = { status: "idle", steps: PROCESS_STEPS.map((s) => ({ key: s.key, label: s.label, status: "pending" as const })), log: [] };
let processAbort: AbortController | null = null;
let processSub: ((s: ProcessUiState) => void) | null = null;
// auto-process (founder 2026-06-22: "the Process button is redundant — automate it"): the chat-led nav
// dropped /reports where the manual Process button lived, so adding data via chat never ran the analysis
// (consolidate/typing) that assigns entity ROLES — every domain stayed roleFor()=infra (a square). This
// runs Process automatically a beat after intake settles, so the graph comes out labelled with no click.
// Reverses the upload/process split (prd-kipi-web-process-foundation) per the founder's explicit call.
let autoProcessTimer: ReturnType<typeof setTimeout> | null = null;
let autoProcessPending = false; // new evidence landed WHILE Process was running — re-run once it finishes (codex)
const AUTO_PROCESS_DEBOUNCE_MS = 1500; // coalesce a burst of adds into ONE Process run (then supersede on more)
/** Schedule an auto-Process a beat after intake. Caller guarantees intake produced NEW entities (so a
 *  failed/empty upload never spends — codex). Case-fenced + key-guarded + re-runs if a run was in flight. */
function scheduleAutoProcess(): void {
  if (autoProcessTimer) clearTimeout(autoProcessTimer);
  const gen = caseGen; // fence: the case THIS intake belongs to. A mid-flight case switch must not process B (codex High).
  autoProcessTimer = setTimeout(() => {
    autoProcessTimer = null;
    if (gen !== caseGen) return; // the case switched after this intake — never process the wrong case
    if (!vault) return;
    if (!hasApiKey(vault)) {
      // VISIBLE no-key state (Maya persona / "hang vs progress"): roles need an AI pass, which needs the
      // BYO key. Silent-skipping is why the graph "stays squares forever" with no explanation. Tell them.
      notifyUser("Add your Anthropic key on the API page to analyze the case — entity roles (the node shapes) need an AI pass.");
      return;
    }
    if (processJob.status === "running") { autoProcessPending = true; return; } // a run is in flight — re-run on its completion (codex)
    void runProcessJob({ auto: true }); // assigns roles → on done, runProcessJob re-hydrates the graph (circles, not squares)
  }, AUTO_PROCESS_DEBOUNCE_MS);
}
function emitProcess(): void {
  // Push a SHALLOW COPY so the panel never aliases the mutable job (and a stale subscriber after a nav
  // writes only into a detached DOM — harmless; the re-mounted panel re-subscribes).
  processSub?.({ ...processJob, steps: processJob.steps.map((s) => ({ ...s })), log: [...processJob.log] });
}

// PRD-7: the last rendered findings-graph model (already key-redacted by the session
// layer). Exposed via __kipi.graphModel() for the DOM proof.
let lastGraphModel: GraphModel | null = null;
const runEvents = createRunEventBus();
const runEventMeta = new Map<string, { objective: string; mode: "objective" | "case" }>();
// kweb-live-graph (founder 2026-06-24, KEEP-ALL): observations grown live during a dig STAY as real osint
// nodes — dead-ends included — and the analyst prunes manually (the live-real-graph-build decision). There
// is NO auto-prune. This counter is just the smoke proof that the dig grew the graph as it found things.
let liveGrowAdds = 0;
// Cytoscape graph clone (supersedes the own-SVG render). The instance binds to a stable #cy
// element and is preserved across expands so the graph GROWS instead of re-popping (D1). A
// generation id fences stale expands; the sets stop a node being dug twice (codex-2, codex-9).
let cyGraph: CyGraph | null = null;
let graphGen = 0;
// sf-cases: bumped ONLY on a case switch (precise — not on a run/expand like graphGen). Any in-flight async
// that WRITES case-derived state after an await (an OSINT transform's done/result memory, a pivot's vault.put)
// captures caseGen at start + skips its write if the case changed — so case A's late result never lands in B.
let caseGen = 0;
const expandedNodeIds = new Set<string>();
const inFlightNodeIds = new Set<string>();

// Select the durable backend before the first render. Never throws (falls back to
// OPFS); never prompts (pickBackend uses queryPermission only).
async function initBackend(): Promise<void> {
  try {
    backend = await pickBackend();
  } catch {
    backend = opfsBackend();
  }
  storage = backend.storage;
}
stripAuthFragment(); // D1: drop any Supabase token from the URL before the first render
const ready = initBackend();

const root = () => document.getElementById("app")!;

function el(html: string): HTMLElement {
  const d = document.createElement("div");
  d.innerHTML = html.trim();
  return d.firstElementChild as HTMLElement;
}

function setStatus(msg: string, kind: "ok" | "err" = "ok") {
  const s = document.getElementById("status");
  if (s) {
    s.textContent = msg;
    s.className = kind;
  }
}

// sp-e730d030 (route-safe status): auto-Process / no-key messages must be visible on EVERY route, not
// just home. window.__kipiChat is mounted ONLY in renderSplitView (home); off-home (e.g. /reports, where
// "Start here" funnels new users) a bare `window.__kipiChat?.pushAside` SILENTLY no-ops — the documented
// "tell them what's happening" fix never reached the route the UI steers to. setStatus is NOT a fallback:
// its #status element exists only on home (verified live — missing on /reports). So off-home we show a
// self-styled toast (no CSS-file dependency, so it can't be a silent-no-op like #status was).
function notifyUser(text: string): void {
  if (window.__kipiChat) { window.__kipiChat.pushAside(text); return; }
  showToast(text);
}

// Route-independent toast: a fixed, fully inline-styled banner appended to <body>, so it renders on ANY
// route regardless of which page's CSS/anchors are mounted. Auto-dismisses; re-uses one host element.
let toastTimer: ReturnType<typeof setTimeout> | null = null;
function showToast(text: string): void {
  let host = document.getElementById("kipi-toast");
  if (!host) {
    host = document.createElement("div");
    host.id = "kipi-toast";
    host.setAttribute("role", "status");
    // hydra ISSUE-4 family (founder 2026-07-07): was a forced-dark toast (#16202e/#e8eef6) → a dark island in
    // LIGHT mode. Route to the themed card/ink/border tokens so it matches whichever theme is active.
    host.style.cssText =
      "position:fixed;bottom:18px;left:50%;transform:translateX(-50%);z-index:9999;max-width:560px;" +
      "background:var(--card);color:var(--ink);border:1px solid var(--border);border-radius:10px;padding:11px 16px;" +
      "font:13px/1.45 system-ui,-apple-system,sans-serif;box-shadow:0 8px 28px rgba(0,0,0,.4);text-align:center";
    document.body.appendChild(host);
  }
  host.textContent = text;
  host.style.display = "block";
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { const h = document.getElementById("kipi-toast"); if (h) h.style.display = "none"; }, 9000);
}

/** node-removal (founder 2026-06-25): a toast carrying an Undo action — the reachable reversal for an
 *  analyst node-exclude (the data is retained; this restores the projection). textContent only (XSS-safe). */
function showUndoToast(text: string, onUndo: () => void | Promise<void>): void {
  showToast(text); // reuse the host + styling
  const host = document.getElementById("kipi-toast");
  if (!host) return;
  host.replaceChildren();
  const label = document.createElement("span");
  label.textContent = text;
  const undo = document.createElement("button");
  undo.textContent = "Undo";
  undo.style.cssText = "margin-left:12px;background:none;border:1px solid #39b3a6;color:#39b3a6;border-radius:6px;padding:2px 10px;font:inherit;cursor:pointer";
  undo.addEventListener("click", () => {
    host.style.display = "none";
    if (toastTimer) clearTimeout(toastTimer);
    void onUndo();
  });
  host.append(label, undo);
  host.style.display = "block";
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { const h = document.getElementById("kipi-toast"); if (h) h.style.display = "none"; }, 12000); // longer — Undo must stay reachable
}

/** node-removal: exclude an entity (node) from the case — reversible. Drops the node + its edges from the
 *  graph AND /entities (the projection chokepoints skip it), re-hydrates, and offers an Undo. The seed
 *  objective is never removable. Shared by the node-card Delete button + the chat "remove <node>" command. */
async function excludeNodeFromCase(type: string, value: string, label: string): Promise<void> {
  if (!vault || type === "objective") return;
  try {
    const key = await excludeEntity(vault, type, value);
    document.querySelector("#chat-host .node-card")?.remove(); // the removed node's detail card is now stale
    hydrateCaseGraph(); // re-project the graph: the node + every edge touching it drop
    if (currentRoute() !== "/") void render(); // on /entities etc., re-render so the removal shows there too
    showUndoToast(`Removed "${label}" from the case.`, async () => {
      if (!vault) return;
      await restoreEntity(vault, key);
      hydrateCaseGraph();
      if (currentRoute() !== "/") void render();
    });
  } catch (e) {
    showToast(msg(e));
  }
}

/** node-removal: resolve a chat "remove <target>" command to a graph node, then exclude it. An empty target
 *  means the currently-selected node; a named target matches a node by exact label first, then a unique
 *  substring (ambiguous/no match → an honest toast, nothing removed). The objective seed is never a target. */
async function removeNodeByTarget(target: string): Promise<void> {
  const t = target.trim().toLowerCase();
  const entityNodes = (lastGraphModel?.nodes ?? []).filter((n) => n.kind !== "objective");
  let pick: { type: string; value: string } | null = null;
  if (!t) {
    if (selectedNodeData && selectedNodeData.kind !== "objective") pick = { type: selectedNodeData.type ?? "", value: selectedNodeData.full_name };
    else { showToast("No node is selected — click a node first, or say “remove <name>”."); return; }
  } else {
    const exact = entityNodes.filter((n) => n.label.toLowerCase() === t);
    const matches = exact.length ? exact : entityNodes.filter((n) => n.label.toLowerCase().includes(t));
    if (!matches.length) { showToast(`No graph node matches “${target}”.`); return; }
    if (matches.length > 1) { showToast(`“${target}” matches ${matches.length} nodes — be more specific.`); return; }
    pick = { type: matches[0].entityType ?? "", value: matches[0].label };
  }
  await excludeNodeFromCase(pick.type, pick.value, pick.value);
}

// ---- client-side hash router: the home ("/") is the graph+chat split-view; the other
// sidebar items are real pages (src/pages.ts). Every nav link goes somewhere real — never
// a dead href="#" (the built-not-wired scar). Unknown hashes fall back to home. ----
const ROUTES = new Set(["/", "/entities", "/clusters", "/bridges", "/focus", "/runs", "/deliverables", "/briefs", "/cross-case", "/reports", "/enrich", "/capabilities", "/full-tool", "/tools", "/inbox", "/cross-domain", "/corrections", "/activity", "/exports", "/report", "/cases", "/alerts", "/account"]);

function currentRoute(): string {
  const h = location.hash.replace(/^#/, "");
  return ROUTES.has(h) ? h : "/";
}

function navigate(route: string): void {
  if (location.hash !== `#${route}`) location.hash = `#${route}`; // triggers hashchange -> render()
  else void render(); // same route: force a re-render
}

// Highlight the active sidebar item (the links carry data-route in index.html) AND derive the
// breadcrumb from the active route (cl-ui: was a hardcoded "Home > Chat + graph" — parity m1).
function highlightNav(route: string): void {
  let activeLabel = "";
  document.querySelectorAll<HTMLElement>("[data-route]").forEach((a) => {
    const on = a.dataset.route === route;
    a.classList.toggle("nav-active", on);
    if (on) activeLabel = (a.textContent || "").trim();
  });
  const bc = document.getElementById("breadcrumb");
  if (bc) bc.textContent = activeLabel ? `Home › ${activeLabel}` : "Home";
  // sf-cases: the top-bar chip shows the ACTIVE case name (the switcher). textContent — a hostile name is literal.
  const chip = document.getElementById("case-chip");
  if (chip) {
    const active = rawVault ? listCases(rawVault).find((c) => c.active) : null;
    chip.textContent = active ? active.name : "No case";
  }
  renderCaseMenu(); // ux (brief §Cases #16): keep the header switcher dropdown fresh after create/switch
  renderLifecycleRail(route); // ux-rail (nav overhaul 1c): keep the lifecycle rail in sync with route + data
  // ch-buttons-audit (controls-honesty): Back is meaningful ONLY on a real in-app route while unlocked — it
  // returns home (wireChromeBack). Hide it otherwise so it can never read as a dead no-op: on home itself,
  // and on the locked login gate / create-first-case screen (codex: those call highlightNav("/account") with
  // a DISPLAY label while currentRoute() is "/" and the vault is locked/absent — keying off the passed
  // `route` label wrongly showed Back there). Drive visibility off the REAL route + unlock state. Use inline
  // style.display, NOT the `hidden` attribute: #chrome-back carries Tailwind `.flex`, which overrides the UA
  // `[hidden]{display:none}` rule (verified live — `hidden` left it visible). Inline style wins.
  const back = document.getElementById("chrome-back") as HTMLElement | null;
  const backUseful = !!vault && !vault.locked && currentRoute() !== "/";
  if (back) back.style.display = backUseful ? "" : "none";
}

// ux-rail (nav overhaul 1c): render the persistent lifecycle rail (Intake→Investigate→Deliver→
// Portfolio). Reads the key-safe lifecycle.ts projection over the active scoped vault; the stage
// owning the active route is marked current; each chip navigates to its stage route. Hidden when no
// vault is loaded (the create/unlock screens). textContent only — every label is a fixed literal.
function renderLifecycleRail(_route: string): void {
  // ccc-lifecycle-strip: the strip lives at the TOP of the chat now (#chat-lifecycle-rail, built in
  // renderDock), not the top bar. It only exists on the home workspace (where the chat is mounted); on
  // other routes there is no chat rail, so this is a no-op. Visibility is driven by inline display (the
  // container carries inline styles since app.css is out of this issue's scope).
  const rail = document.getElementById("chat-lifecycle-rail");
  if (!rail) return;
  if (!vault) {
    rail.style.display = "none";
    rail.replaceChildren();
    return;
  }
  const stages = lifecycleStages(vault);
  // "current" = the first stage not yet done (where the analyst is in the flow); all done → the last.
  const current = stages.find((s) => !s.done)?.key ?? stages[stages.length - 1].key;
  rail.replaceChildren();
  rail.style.display = "flex";
  stages.forEach((s, i) => {
    if (i > 0) {
      const sep = document.createElement("span");
      sep.className = "lc-sep";
      sep.textContent = "›";
      rail.appendChild(sep);
    }
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "lc-stage"
      + (s.done ? " lc-done" : "")
      + (s.key === current ? " lc-current" : "");
    chip.dataset.stage = s.key;
    if (s.key === current) chip.setAttribute("aria-current", "step");
    chip.title = `${s.label} — ${s.detail}`;
    const mark = document.createElement("span");
    mark.className = "lc-mark";
    mark.textContent = s.done ? "✓" : String(s.num);
    const label = document.createElement("span");
    label.className = "lc-label";
    label.textContent = s.label;
    const detail = document.createElement("span");
    detail.className = "lc-detail";
    detail.textContent = s.detail;
    chip.append(mark, label, detail);
    // ccc-lifecycle-strip: clicking a stage PREFILLS the chat input with that stage's prompt + focuses
    // it (the analyst sends), instead of navigating to a route. Prefill — never auto-send — so a click
    // can't kick off a spendy run by surprise.
    chip.addEventListener("click", () => {
      const input = document.getElementById("chat-input") as HTMLInputElement | null;
      if (!input) return;
      input.value = s.prompt;
      input.focus();
      input.dispatchEvent(new Event("input", { bubbles: true })); // let the dock's input listeners react
      flashPrefill(input); // ch-lifecycle-cue: visible, assertable confirmation the click registered (sp-bacfd8f0)
    });
    rail.appendChild(chip);
  });
}

// ch-lifecycle-cue (controls-honesty / sp-bacfd8f0): the lifecycle strip prefilled #chat-input and focused
// it, but gave ZERO visible feedback — so to the founder the click read as a dead no-op. Add a deterministic,
// assertable cue: scroll the input into view + add the `lc-prefilled` class (a smoke asserts it is present
// right after the click; the CSS gives a ring + one pulse). The class clears on the analyst's first REAL
// EDIT, detected by a TRUSTED `input` event — NOT a raw keydown (codex: Tab/arrows/Escape/modifiers fire
// keydown but aren't edits, so a keydown listener cleared the cue too early) and NOT the synthetic `input`
// the click dispatches (that fires BEFORE this listener registers, and `isTrusted` is false anyway). The
// remove+reflow re-triggers the CSS pulse so a SECOND stage click visibly re-fires. Prefill-never-auto-send
// is unchanged. {once} bounds the listener — stacked listeners from rapid re-clicks all clear idempotently.
function flashPrefill(input: HTMLInputElement): void {
  input.scrollIntoView({ block: "nearest" });
  input.classList.remove("lc-prefilled");
  void input.offsetWidth; // force reflow so re-adding the class re-triggers the pulse animation on re-click
  input.classList.add("lc-prefilled");
  input.addEventListener(
    "input",
    (e) => { if (e.isTrusted) input.classList.remove("lc-prefilled"); },
    { once: true },
  );
}

// ux (brief §Cases #16): fill the header case-switcher dropdown (#case-menu) from the vault's cases; each
// row switches the active case via switchCase from ANY page (vs a /cases round-trip). textContent only — a
// hostile case name is literal. switchCase clears in-memory state + re-renders; the menu closes via the
// `close-case-menu` event the Alpine panel listens for. The "Manage cases →" footer lives in index.html.
function renderCaseMenu(): void {
  const menu = document.getElementById("case-menu");
  if (!menu) return;
  menu.replaceChildren();
  const cases = rawVault ? listCases(rawVault) : [];
  if (!cases.length) {
    const empty = document.createElement("div");
    empty.className = "case-menu-empty";
    empty.textContent = "No cases yet.";
    menu.appendChild(empty);
    return;
  }
  for (const c of cases) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "case-menu-item" + (c.active ? " active" : "");
    const name = document.createElement("span");
    name.className = "case-menu-name";
    name.textContent = c.name;
    btn.appendChild(name);
    if (c.active) {
      const mark = document.createElement("span");
      mark.className = "case-menu-check";
      mark.textContent = "✓";
      btn.appendChild(mark);
    }
    btn.addEventListener("click", () => {
      if (c.active) {
        window.dispatchEvent(new CustomEvent("close-case-menu"));
        return;
      }
      void switchCase(c.id).then(() => window.dispatchEvent(new CustomEvent("close-case-menu")));
    });
    menu.appendChild(btn);
  }
}

function pageDeps(): PageDeps {
  // adr-wire D6 / cl-wire D2: pages.ts gets the AI passes + clusters as deps supplied HERE (app.ts
  // owns the vault + lastGraphModel + the scripted-wire seam); pages.ts never builds a client or
  // reads the key or reaches lastGraphModel directly.
  return {
    vault: vault!,
    navigate,
    download,
    aiDossier: runAiDossier,
    semanticRelations: runSemanticRelations,
    consolidateEntities: runConsolidate,
    typeEntities: runTypeEntities,
    takePendingFocus, // kk-search D11: the /entities page focuses the searched entity
    // ca-ui: analyst corrections (the top-authority write). After an apply/revert we clear the
    // consolidate/type caches + re-render so /entities, the graph, and the brief reflect the override (D11).
    applyCorrection: async (type, value, predicate, newValue) => {
      if (!vault) throw new Error("Unlock your vault to apply a correction.");
      await applyCorrection(vault, type, value, predicate, newValue);
      await afterCorrection();
    },
    revertCorrection: async (canonicalKey, predicate) => {
      if (!vault) throw new Error("Unlock your vault to revert.");
      await revertCorrection(vault, canonicalKey, predicate);
      await afterCorrection();
    },
    listCorrections: () => (vault ? listCorrections(vault) : []),
    getAnalyst: () => (vault ? getAnalyst(vault) : "analyst"),
    setAnalyst: async (name) => {
      if (!vault) throw new Error("Unlock your vault to set your name.");
      await setAnalyst(vault, name);
    },
    // sf-activity: the "who did what, when" feed — the key-redacted projection over timestamped records.
    activity: () => (vault ? activityFor(vault) : []),
    // sf-cases: the multi-case switcher deps. listCases/createCase/setActiveCase read/write GLOBAL setting:
    // keys (shared per-user); switchCase clears the case-derived in-memory state then re-renders (app.ts owns it).
    cases: () => (rawVault ? listCases(rawVault) : []),
    createCase: async (name) => {
      if (!rawVault) throw new Error("Unlock your vault to create a case.");
      const id = await createCase(rawVault, name);
      await switchCase(id); // a new case becomes active immediately
    },
    switchCase: (id) => switchCase(id),
    // sf-cases: per-case data counts for the delete-confirm (scoped READ of a NON-active case; objective seed
    // nodes excluded so the number matches what the analyst sees). Cheap — runs once on a Delete click.
    caseCounts: (id) => {
      if (!rawVault) return { runs: 0, entities: 0 };
      const sv = scopedVault(rawVault, id);
      const entities = Object.values(entityDbFor(sv).entities).filter((e) => e.type !== "objective").length;
      return { runs: liveReportCount(sv), entities };
    },
    // sf-cases: delete a case + ALL its data. Auto-switch off the active case first (founder UX choice), so the
    // running view never points at a case mid-delete; then drop the namespace + re-render the switcher.
    deleteCase: async (id) => {
      if (!rawVault) throw new Error("Unlock your vault to delete a case.");
      // switch off the doomed case FIRST (clears its in-memory state — the security fence): to another case
      // if one remains, else to the empty state ("") when this was the last one.
      if (activeCaseId(rawVault) === id) {
        const other = listCases(rawVault).find((c) => c.id !== id);
        await switchCase(other ? other.id : "");
      }
      await deleteCase(rawVault, id);
      await render();
    },
    // sf-exports: the STIX/MISP/CSV files serialized from the redacted export model (key-safe, in-browser).
    exports: () => (vault ? exportFilesFor(vault, lastGraphModel) : { stix: "", misp: "", entitiesCsv: "", relationshipsCsv: "", clustersCsv: "" }),
    // sf-report-builder: the branded-report model (key-redacted, in-browser).
    reportModel: () => (vault ? reportModelFor(vault, lastGraphModel) : { caseName: "", stats: { reports: 0, entities: 0 }, execSummary: "", topActors: [], dossiers: [], iocs: [], crossCase: [], sources: [] }),
    // clu-auto-report: persist the analyst's exec-summary edit / re-render (drop it). app.ts owns the vault.
    saveReportSummary: (text) => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to save the report."));
      return saveReportSummaryEdit(vault, text);
    },
    clearReportSummary: () => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to re-render the report."));
      return clearReportSummaryEdit(vault);
    },
    // rb-ui: alerts + per-report notes, routed through the session (key-safe).
    alerts: () => (vault ? alertsFor(vault) : []),
    // sf-alerts: the acknowledge write-path (single-writer alert:<id>:ack, redacted, tainted-id rejected).
    acknowledgeAlert: async (id) => {
      if (!vault) throw new Error("Unlock your vault to acknowledge alerts.");
      await ackAlert(vault, id);
    },
    acknowledgeAllAlerts: async (ids) => {
      if (!vault) throw new Error("Unlock your vault to acknowledge alerts.");
      await ackAllAlerts(vault, ids);
    },
    reportEntities: (objective) => (vault ? runEntities(vault, objective) : []),
    getReportNotes: (objective) => (vault ? getReportNotes(vault, objective) : ""),
    setReportNotes: async (objective, text) => {
      if (!vault) throw new Error("Unlock your vault to save notes.");
      await setReportNotes(vault, objective, text);
    },
    // sf-entity-detail: the per-entity DETAIL-fold projections routed through the session (key-safe).
    // The score needs the entity's role+promoted (from the record); the rest key off ref / canonKey.
    // setDossierOverride is the ONE editable write (single-writer, mirrors setReportNotes EXACTLY — no
    // global re-render; the section's own paint() re-reads the vault in place, so the open fold stays open).
    entityScore: (e) => (vault ? entityScoreBreakdownFor(vault, e.ref, e.role, e.promoted) : null),
    typedRelationships: (canonicalKey) => (vault ? typedRelationshipsFor(vault, canonicalKey) : []),
    entityCorrections: (canonicalKey) => (vault ? entityCorrectionsFor(vault, canonicalKey) : []),
    entityAppearances: (e) => (vault ? entityAppearancesFor(vault, e.ref) : []),
    getDossierOverride: (e) => (vault ? getEntityDossierOverride(vault, e.ref) : null),
    setDossierOverride: async (e, text) => {
      if (!vault) throw new Error("Unlock your vault to save the dossier note.");
      await setEntityDossierOverride(vault, e.ref, text);
    },
    clusters: () => (vault ? clustersFor(vault, lastGraphModel) : []),
    bridges: () => (vault ? bridgesFor(vault, lastGraphModel) : []),
    // sf-focus: the top-N threat-ranked items + the deterministic gaps (read-only, key-redacted, no LLM).
    focus: () => (vault ? focusFor(vault, lastGraphModel) : { items: [], gaps: [] }),
    // sf-focus: a gap-chip click → focus the entity on /entities (the same pendingFocus seam ⌘K uses —
    // the original's /entity/{id} link, folded onto /entities like sf-entity-detail).
    focusEntity: (ref) => {
      pendingFocusKey = canonKey(ref.type, ref.value);
      navigate("/entities");
    },
    // ux-rowmenu (item 4): the /entities row ⋯ menu actions. openInGraph navigates home + focuses the
    // node; enrichEntity navigates to /enrich with the entity prefilled. takePendingEnrich is consumed
    // by renderEntityEnrich. Mirror the focusEntity seam (pending var + navigate).
    openInGraph: (e) => {
      pendingGraphFocus = { value: e.ref.value, label: e.label };
      navigate("/");
    },
    enrichEntity: (value) => {
      pendingEnrichTarget = value;
      navigate("/enrich");
    },
    takePendingEnrich,
    crossDomain: () => (vault ? crossDomainEntities(vault) : []),
    // sf-deliverables: the page "Regenerate brief" button — the SAME single-writer brief:case synthesize
    // the Process step uses, offline-seamed (chatWire.synthesizeFetch) so the smoke drives it keyless.
    // synthesizeCaseBrief throws SessionError when no key — surfaced inline by the page (red status).
    synthesize: () => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to synthesize the brief."));
      // The brief is NOT gated (founder: it's auto-created, no blocking). Challenge stays a SOFT conductor
      // suggestion, never a wall — same philosophy as the chat tradecraft nudges (tradecraft.ts).
      return synthesizeCaseBrief(vault, { fetchImpl: chatWire?.synthesizeFetch });
    },
    // sf-deliverables: the stale-banner inputs for a brief — builtOn (the run count it was synthesized
    // over) vs the live run count. null when there is no count (a brief predating the field) → no banner.
    briefStale: (objective) => {
      if (!vault) return null;
      const meta = getBriefMeta(vault, objective);
      return meta ? { builtOn: meta.builtOn, live: liveReportCount(vault) } : null;
    },
    // sf-briefs: run the grouped-relatedness engine + per-group LLM summaries (single-writer groupbrief:*,
    // offline-seamed via chatWire.groupBriefFetch). Mirrors the synthesize wiring (app.ts owns the vault).
    groupBriefs: () => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to group reports."));
      // Not gated (founder: no blocking on the brief) — Challenge is a soft suggestion, not a wall.
      return generateGroupBriefs(vault, { fetchImpl: chatWire?.groupBriefFetch });
    },
    ingest: (name, text) => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to ingest."));
      // sp-2942cb65: re-project the home graph after intake (the chat path already does this at ingestFile→
      // hydrate). Under discovery-grow the graph stays sparse on upload (promoted-only, d2b98925) — hydrate
      // refreshes lastGraphModel + re-renders if the graph is mounted, so the canvas is never stale.
      return ingestText(vault, name, text).then((r) => { if (r.count > 0) { scheduleAutoProcess(); hydrateCaseGraph(); } return r; }); // auto-analyze only on real new data
    },
    ingestFile: async (file) => {
      if (!vault) throw new Error("Unlock your vault to ingest.");
      // ocr-ingest: images + scanned-PDF pages are OCR'd inside fileToText (the OCR engine loads
      // lazily on demand); the OCR'd text flows through the SAME ingestText gate as any other input.
      const ingestVault = vault; // sf-cases: capture THIS case's scoped vault — a slow OCR + a mid-extraction
      const cgen = caseGen; //            case switch must NOT land A's file in B (codex). Write to A or skip.
      const { text, kind, warnings, entities } = await fileToText(file);
      if (kind === "unsupported" || !text.trim()) throw new Error(warnings?.length ? `Could not read that file: ${warnings.join(" ")}` : "Could not read text from that file (unsupported, unreadable, or no text found).");
      if (cgen !== caseGen) throw new Error("Case switched during ingest — re-upload in the active case.");
      // ig-record: a CSV/TSV/XLSX carries column-typed entities (person/handle columns the flat regex misses);
      // pass them to ingestText, which redacts + re-gates + unions them with the flat-text extraction.
      const result = await ingestText(ingestVault, file.name, text, entities ?? []);
      if (warnings?.length) setStatus(`Note: ${warnings.join(" ")}`); // D9: surface OCR caps, never console
      if (result.count > 0) { scheduleAutoProcess(); hydrateCaseGraph(); } // sp-2942cb65: auto-analyze + re-project the graph after upload
      return result;
    },
    // en-wire: enrich deps routed through app.ts (which owns the vault + the scripted-wire seam).
    // pages.ts never reads/writes a key; production uses the real fetch.
    // auth-gate-nav: OSINT provider keys are GLOBAL — use keyVault() so they save/read before the first case.
    providers: () => { const kv = keyVault(); return kv ? providerStatus(kv) : { providers: [], blocked: [] }; },
    saveProviderKey: (id, key) => {
      const kv = keyVault();
      if (!kv) return Promise.reject(new Error("Unlock your vault to save your key."));
      return setProviderKey(kv, id, key);
    },
    clearProviderKey: (id) => {
      const kv = keyVault();
      if (!kv) return Promise.reject(new Error("Unlock your vault to clear your key."));
      return clearProviderKey(kv, id);
    },
    testProvider: (id) => runTestProvider(id),
    enrich: (id, target) => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to enrich."));
      return enrichTarget(vault, id, target, { fetchImpl: chatWire?.enrichFetch });
    },
    enrichStats: () => (vault ? enrichStats(vault) : { runCount: 0, distinctEntities: 0 }),
    listEnrichRuns: () => (vault ? listEnrichRuns(vault) : []),
    getEnrichRunDetail: (objective) => (vault ? getEnrichRunDetail(vault, objective) : null),
    // pb-csp-ui: the user-proxy tier — the worker URL setting + the proxied (blocked-provider) enrich.
    workerUrl: () => (vault ? getWorkerUrl(vault) : null),
    saveWorkerUrl: (url) => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to save the worker URL."));
      return setWorkerUrl(vault, url);
    },
    enrichViaProxy: (id, target) => {
      if (!vault) return Promise.reject(new Error("Unlock your vault to enrich."));
      return enrichViaProxy(vault, id, target, { fetchImpl: chatWire?.enrichFetch });
    },
    // hydra-see-sites: probe the saved worker for the "Test connection" button.
    testWorkerProxy: () => {
      const w = vault ? getWorkerUrl(vault) : null;
      if (!w) return Promise.resolve("unset" as WorkerProbe);
      return probeWorker(w, { fetchImpl: chatWire?.enrichFetch });
    },
    // pf-process (INC-1): the Process pipeline deps. app.ts owns the runner + the job state + the run
    // fence + the scripted wire; pages.ts only renders + subscribes.
    processState: () => processJob,
    subscribeProcess: (fn) => {
      processSub = fn;
    },
    abortProcess: () => processAbort?.abort(),
    schemaSummary: () => {
      if (!vault) return null;
      const a = analysisFor(vault);
      if (!a?.schema) return null;
      return `${a.schema.domain} · ${a.schema.roles.length} roles`;
    },
    schemaDetail: () => (vault ? analysisFor(vault)?.schema ?? null : null),
    startProcess: runProcessJob,
  };
}

// pf-process: start (or restart) the Process pipeline. The run fence (PRD D8 + codex BLOCKER): a new
// click aborts the prior in-flight run, and `current()` (processAbort === this run's controller) gates
// EVERY processJob mutation/emit — so a superseded run's late resolve/reject can never clobber the fresh
// run's state or paint over its panel. Success clears the AI-pass caches (the analysis overlay moved
// roles/types, so the cached suggestions + graph are stale).
async function runProcessJob(opts?: { auto?: boolean }): Promise<void> {
  if (!vault) throw new Error("Unlock your vault to process the case.");
  if (autoProcessTimer) { clearTimeout(autoProcessTimer); autoProcessTimer = null; } // this run supersedes a pending auto-run (codex)
  autoProcessPending = false;
  // VISIBLE state in the always-on chat (the Process progress panel lives on /reports, which the chat-led
  // nav removed — so an auto-run had NO indicator). Only for the auto path; the manual /reports button has its panel.
  if (opts?.auto) notifyUser("Analyzing the case — assigning entity roles… (the graph will update with circles/squares)");
  processAbort?.abort(); // supersede any prior run
  const ac = new AbortController();
  processAbort = ac;
  const current = (): boolean => processAbort === ac; // generation guard: this run is still the active one
  processJob = { status: "running", steps: PROCESS_STEPS.map((s) => ({ key: s.key, label: s.label, status: "pending" as const })), log: [] };
  emitProcess();
  try {
    await runProcess(vault, {
      signal: ac.signal,
      wire: { schemaFetch: chatWire?.schemaFetch, consolidateFetch: chatWire?.consolidateFetch, typeFetch: chatWire?.typeFetch, analyzeFetch: chatWire?.analyzeFetch, synthesizeFetch: chatWire?.synthesizeFetch, dossierFetch: chatWire?.dossierFetch },
      onStep: (key, status) => {
        if (!current()) return; // a superseded run's late callback is ignored
        const st = processJob.steps.find((s) => s.key === key);
        if (st) st.status = status;
        emitProcess();
      },
      onLog: (line) => {
        if (!current()) return;
        processJob.log = [...processJob.log, line].slice(-200); // bound the log tail
        emitProcess();
      },
    });
    if (!current()) return; // superseded mid-flight — the fresh run owns processJob; do not clobber it
    consolidateCache.clear();
    typeCache.clear(); // the AI overlay moved roles/types — cached suggestions are stale
    processJob = { ...processJob, status: "done" };
    hydrateCaseGraph(); // re-project so the just-assigned roles drive node shapes/colors NOW (the squares→circles fix)
    if (opts?.auto) notifyUser("Analysis complete — roles assigned; the graph updated.");
    if (autoProcessPending) { autoProcessPending = false; scheduleAutoProcess(); } // evidence arrived mid-run — re-process it (codex)
  } catch (e) {
    if (!current()) return; // superseded — its abort threw; the fresh run owns the state
    processJob = { ...processJob, status: ac.signal.aborted ? "idle" : "error", error: msg(e) };
    if (opts?.auto && !ac.signal.aborted) notifyUser(`Could not analyze the case: ${msg(e)}`); // visible cause (likely a key issue)
  }
  emitProcess();
}

// en-wire: one live probe against the provider's benign canonical target with the saved key. The
// detail is already sanitized (the adapters throw provider + HTTP status only, never the key). It
// lands NO entities — it is a connectivity/auth check, separate from the enrich action.
async function runTestProvider(id: string): Promise<{ ok: boolean; detail: string }> {
  const kv = keyVault(); // auth-gate-nav: global provider keys — testable before the first case
  if (!kv) return { ok: false, detail: "unlock your vault" };
  const provider = enrichProvider(id);
  if (!provider) return { ok: false, detail: "unknown provider" };
  const key = getProviderKey(kv, id);
  if (!key) return { ok: false, detail: "no key configured" };
  try {
    const r = await provider.run(provider.probe, key, { fetchImpl: chatWire?.enrichFetch });
    return { ok: true, detail: `${r.entities.length} result(s)` };
  } catch (e) {
    return { ok: false, detail: msg(e) }; // sanitized adapter error (no key)
  }
}

// adr-wire: the AI passes routed through the wire (production = real fetch; the smoke injects a
// scripted wire). app.ts owns the vault + the wire; the drawer + pages call THESE, never the
// client directly. lastGraphModel is folded so an in-session expansion's entity can be analyzed.
async function runAiDossier(type: string, value: string): Promise<string | null> {
  if (!vault) return null;
  // INC-4b (codex A1): prefer the dossier the Process dossiers step already generated + persisted at
  // dossier:<canonKey of the entity's IDENTITY> (the SAME key persistCaseDossiers wrote; already redacted
  // at persist time) — so the batch is consumed, not built-for-no-one. Resolve the node to its store
  // entity for the identity key; fall back to on-demand generation if the Process hasn't run for it.
  const store = entityStore();
  const rec = store ? getEntity(store, type, value) : null;
  if (rec) {
    try {
      const cached = vault.get(`${DOSSIER_PREFIX}${canonKey(rec.ref.type, rec.ref.value)}`);
      if (cached && typeof cached === "object" && typeof (cached as { dossier?: unknown }).dossier === "string") {
        return (cached as { dossier: string }).dossier;
      }
    } catch {
      /* unreadable cache — fall through to generate */
    }
  }
  return aiDossierFor(vault, type, value, { fetchImpl: chatWire?.dossierFetch, current: lastGraphModel });
}
async function runSemanticRelations(type: string, value: string): Promise<SemanticRelation[]> {
  if (!vault) return [];
  return semanticRelationsFor(vault, type, value, { fetchImpl: chatWire?.relationsFetch, current: lastGraphModel });
}

// ct-wire (codex D9): the case-level consolidate/typing passes are EXPENSIVE (up to 80 entities) and
// non-deterministic, so a repeat click on an unchanged case must not re-spend. The result is cached in
// MEMORY (never the vault) keyed by a cheap digest of the run-record set + the live graph size; a new
// run or an expansion changes the digest and re-runs. Routed with current=lastGraphModel (D10 parity).
const consolidateCache = new Map<string, ConsolidateSuggestion[]>();
const typeCache = new Map<string, TypingSuggestion[]>();

function caseDigest(): string {
  if (!vault) return "locked";
  // sf-cases (codex): key the consolidate/type cache by the ACTIVE CASE id too — two cases with the same
  // run-key set + node count would otherwise share a digest, so a late old-case completion repopulating the
  // cache after a switch could bleed A's suggestions into B. The per-case prefix makes a collision impossible.
  const caseId = rawVault ? activeCaseId(rawVault) : ""; // vault non-null ⇒ a case is active (guarded above)
  let runKeys = "";
  try {
    runKeys = vault.keys().filter((k) => k.startsWith("run:")).sort().join("|");
  } catch {
    return "locked";
  }
  let h = 5381;
  for (let i = 0; i < runKeys.length; i++) h = ((h << 5) + h + runKeys.charCodeAt(i)) | 0; // djb2
  return `${caseId}:${h}:${lastGraphModel?.nodes.length ?? 0}`;
}

async function runConsolidate(): Promise<ConsolidateSuggestion[]> {
  if (!vault) return [];
  const digest = caseDigest();
  const hit = consolidateCache.get(digest);
  if (hit) return hit; // D9: no re-spend on an unchanged case
  const sugs = await consolidateEntities(vault, { fetchImpl: chatWire?.consolidateFetch, current: lastGraphModel });
  consolidateCache.set(digest, sugs);
  return sugs;
}
async function runTypeEntities(): Promise<TypingSuggestion[]> {
  if (!vault) return [];
  const digest = caseDigest();
  const hit = typeCache.get(digest);
  if (hit) return hit;
  const sugs = await typeEntities(vault, { fetchImpl: chatWire?.typeFetch, current: lastGraphModel });
  typeCache.set(digest, sugs);
  return sugs;
}

// ca-ui D11: after a correction the suggestion caches are stale (their digest ignores corrections) and
// the graph still shows the old role — clear the caches + re-render the current route (and, on home, the
// graph) so the analyst override is reflected everywhere.
async function afterCorrection(): Promise<void> {
  consolidateCache.clear();
  typeCache.clear();
  await render();
}

function renderRoutePage(route: string): HTMLElement {
  const d = pageDeps();
  switch (route) {
    case "/entities": return renderEntitiesPage(d);
    case "/clusters": return renderClustersPage(d);
    case "/bridges": return renderBridgesPage(d);
    case "/focus": return renderFocusPage(d);
    case "/runs": return renderRunsPage(d);
    case "/deliverables": return renderDeliverablesPage(d);
    case "/briefs": return renderGroupedBriefsPage(d);
    case "/cross-case": return renderCrossCasePage(d);
    case "/reports": return renderReportsPage(d);
    case "/enrich": return renderEnrichPage(d);
    case "/capabilities": return renderCapabilitiesPage(d);
    case "/full-tool": return renderFullToolPage(d);
    case "/tools": return renderToolsPage(d);
    case "/inbox": return renderInboxPage(d);
    case "/cross-domain": return renderCrossDomainPage(d);
    case "/corrections": return renderCorrectionsPage(d);
    case "/activity": return renderActivityPage(d);
    case "/exports": return renderExportsPage(d);
    case "/cases": return renderCasesPage(d);
    case "/report": return renderReportPage(d);
    case "/alerts": return renderAlertsPage(d);
    default: return el(`<section class="pg"><p class="pg-empty">Page not found.</p></section>`);
  }
}

// ccc-hybrid-routes: surface a detail route OVER the just-rendered workspace. The SAME renderXPage output
// is used (parity: the route's renderer is still called) — only WHERE it mounts changes: dense/tabular
// routes take over the graph canvas as an animated overlay (close → graph); narrative routes post as a
// chat card. A dense page's row-click navigates (pages.ts owns that) → re-renders + refocuses the graph
// underneath; the analyst closes the takeover to see it.
function surfaceDetailRoute(route: string): void {
  const content = renderRoutePage(route);
  if (routeKind(route) === "dense") {
    const pane = document.getElementById("graph");
    if (pane) mountCanvasTakeover(pane, detailRouteLabel(route), content, () => navigate("/"));
    else root().appendChild(content); // defensive: no graph pane (shouldn't happen on the workspace)
    return;
  }
  postNarrativeCard(route, content);
}

// ccc-hybrid-routes: post a narrative route's content as a card in the chat stream (the conversation is
// where the analyst reads runs / briefs / alerts / activity). A "← graph" affordance returns home.
function postNarrativeCard(route: string, content: HTMLElement): void {
  const host = document.getElementById("chat-host");
  if (!host) { root().appendChild(content); return; } // defensive: no chat mounted
  const card = el(`<div class="msg route-card"></div>`);
  const head = el(`<div class="route-card-head" style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:6px;"></div>`);
  const title = document.createElement("span");
  title.textContent = detailRouteLabel(route); // textContent — never markup
  title.style.fontWeight = "600";
  const back = el(`<button type="button" class="ghost" style="margin:0;font-size:12px;">← graph</button>`);
  back.addEventListener("click", () => navigate("/"));
  head.append(title, back);
  card.append(head, content);
  host.appendChild(card);
  card.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function render() {
  const hasVault = await Vault.exists(storage);
  // rsn-reattach INVARIANT (prd-run-survives-navigation): this teardown runs on nav DURING a live run, and
  // it intentionally does NOT abort activeAbort — the run SURVIVES navigation. Its trail/findings live in the
  // run store (rsn-run-store), not this DOM, so tearing the DOM down is non-destructive: reattachRunIntoDock()
  // replays the store when renderSplitView re-mounts the Workspace, and onStep re-resolves #trail so a still-
  // live run keeps streaming. The ONLY paths that abort a run are case-switch/lock/reset (clearCaseDerivedState,
  // which ALSO wipes the store), run-supersede, and the Stop button — never a plain nav. A run is therefore
  // never silently orphaned here: it is either preserved-and-reattached or explicitly aborted-and-wiped.
  // cd-ui (D5): clear the bridge globals BEFORE the DOM is torn down so a stale chat callback can
  // never drive a destroyed CyGraph or write into removed DOM. render() runs on lock/unlock/reset/nav.
  window.__kipiGraph = null;
  unmountChatDock(); // clears window.__kipiChat
  // ux-rowmenu (verify-fix): close any open /entities row ⋯ menu BEFORE the DOM is wiped, so its document
  // click/keydown listeners don't leak when render() fires via a non-click teardown (back/forward, idle
  // auto-lock, bfcache) — the in-component close paths only cover click/Escape/outside-click.
  closeAllEntityMenus();
  cyGraph?.destroy(); // the #cy element is about to be rebuilt — drop the stale instance
  cyGraph = null;
  root().innerHTML = "";
  updateRunChip(); // rsn-run-chip: route changed — show/hide the off-Workspace run chip for the new route
  // auth-gate-nav (founder 2026-06-25): while the vault is locked / absent, render() ignores route changes and
  // shows the login gate — so the left nav LOOKED clickable but did nothing ("I can't click the items on the
  // left when I start the tool"). Mark the body so the nav reads as DISABLED-until-sign-in (greyed, not-allowed),
  // making the required order obvious: sign in here first, THEN the OSINT + API key pages open. Cleared on unlock.
  document.body.classList.toggle("vault-locked", !rawVault || rawVault.locked);

  // sf-cases: unlocked but NO active case (a fresh vault, or the last case was just deleted) → the
  // create-first-case surface. The case-scoped surfaces (the workspace) need a scoped vault, so force the
  // Cases page (its create form IS the surface). Distinct from the locked gate below (which shows login).
  // auth-gate-nav (founder 2026-06-25): EXCEPT the GLOBAL config pages — the API/keys page (/account) and the
  // OSINT keys page (/enrich) only need the raw vault (keys are shared across cases), so they MUST be reachable
  // before the first case. Forcing them to /cases trapped a new user: every left-nav tap bounced back to Cases
  // ("the buttons on the left I can't press them"), and the keys were unreachable. Let those two routes through.
  if (rawVault && !rawVault.locked && !vault) {
    const route = currentRoute();
    if (route === "/account") {
      highlightNav("/account");
      root().className = "page-view";
      renderAccountView();
      return;
    }
    if (route === "/enrich") {
      highlightNav("/enrich");
      root().className = "page-view";
      root().appendChild(renderRoutePage("/enrich"));
      return;
    }
    if (route === "/capabilities") {
      // The capabilities catalog is a read-only global surface (no case, no keys) — reachable
      // before the first case exists, same as the two config screens above, so a user evaluating
      // Hydra can browse the full OSINT toolkit without first creating a case.
      highlightNav("/capabilities");
      root().className = "page-view";
      root().appendChild(renderRoutePage("/capabilities"));
      return;
    }
    if (route === "/full-tool") {
      // free/pro split: the "Full tool" upsell — a read-only global surface (no case, no keys),
      // reachable before the first case so a prospect can see everything the paid tool adds.
      highlightNav("/full-tool");
      root().className = "page-view";
      root().appendChild(renderRoutePage("/full-tool"));
      return;
    }
    highlightNav("/account");
    root().className = "page-view";
    root().appendChild(renderRoutePage("/cases"));
    return;
  }

  if (vault && !vault.locked) {
    const route = currentRoute();
    // kf-fix (codex P2): a deferred keyless key-focus only applies to the /account render that the
    // keyless route triggers. If we render anything else first, drop it so a later /account visit
    // can't inherit a stale focus-steal. renderAccountView consumes (takes) it for the /account case.
    if (route !== "/account") pendingKeyFocus = false;
    if (route !== "/") pendingBriefObjective = null; // kf-fix (codex): a deferred brief-reopen only applies to home; drop it elsewhere
    highlightNav(route);
    if (route === "/") {
      // Home: the graph-dominant split-view (D2 full-height; D8 only here, not create/unlock).
      root().className = "splitview";
      renderSplitView();
    } else if (route === "/account") {
      // ac-ui: the Account page — login/session + vault storage + Anthropic key, moved off the graph.
      root().className = "page-view";
      renderAccountView();
    } else if (isDetailRoute(route)) {
      // ccc-hybrid-routes: detail routes surface OVER the persistent workspace (graph + chat) — narrative
      // routes as a chat card, dense/tabular routes as an animated canvas takeover (close → graph) —
      // instead of replacing the app with a full page.
      root().className = "splitview";
      renderSplitView();
      surfaceDetailRoute(route);
    } else {
      // The remaining config screen (/enrich = OSINT tools) stays a full page-view; issue 5 collapses
      // the config screens + the nav.
      root().className = "page-view";
      root().appendChild(renderRoutePage(route));
    }
  } else {
    // Create / unlock: the login gate. It highlights the Account nav item (not Chat + graph) so login
    // is no longer shown on the graph page. The gate is modal — the vault must be unlocked before any
    // page is reachable, so login itself can't become an ordinary in-menu page.
    pendingKeyFocus = false; // kf-fix: a locked render has no key card to focus; drop any deferred focus
    pendingBriefObjective = null; // kf-fix (codex): a locked render has no dock; drop any deferred brief-reopen
    highlightNav("/account");
    root().className = "centered";
    root().appendChild(renderStorageBar());
    root().appendChild(el(`<p id="status" class="ok"></p>`));
    renderAuth(hasVault);
  }
}

// ---- PRD-11 storage bar: which storage am I in + pick/re-grant/export/import ----

function storageBannerText(): string {
  if (backend.conflict) return "This folder and your browser copy disagree. Using the folder (canonical).";
  if (backend.mode === "disk") return `Saving to your folder: ${backend.folderName ?? "(folder)"}`;
  if (backend.needsRegrant) return `Folder access lapsed (${backend.folderName ?? "your folder"}). Re-grant to resume saving there.`;
  return "Saved in this browser, encrypted — nothing leaves. Optional: back up to a folder.";
}

function renderStorageBar(): HTMLElement {
  const bar = el(`
    <section class="storagebar">
      <span id="storagebanner" class="${backend.conflict ? "warn" : backend.mode}">${backend.conflict ? '<svg class="ico" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:5px"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' : ""}${escapeHtml(storageBannerText())}</span>
      <span class="storagebtns"></span>
    </section>`);
  const btns = bar.querySelector(".storagebtns")!;

  if (supportsDiskPicker() && backend.mode !== "disk") {
    btns.appendChild(button(backend.needsRegrant ? "Re-grant folder" : "Save to a folder…", backend.needsRegrant ? onRegrant : onPickFolder));
  }
  btns.appendChild(button("Export vault", onExport, "ghost"));
  btns.appendChild(importButton());
  return bar;
}

function button(label: string, handler: () => void, cls = ""): HTMLElement {
  const b = el(`<button class="${cls}">${escapeHtml(label)}</button>`);
  b.addEventListener("click", handler);
  return b;
}

function importButton(): HTMLElement {
  const wrap = el(`<span class="importwrap"><button class="ghost">Import vault</button><input type="file" hidden /></span>`);
  const input = wrap.querySelector("input") as HTMLInputElement;
  wrap.querySelector("button")!.addEventListener("click", () => input.click());
  input.addEventListener("change", () => onImport(input));
  return wrap;
}

async function onPickFolder() {
  // Must run inside this click gesture: pick -> persist handle -> request permission.
  try {
    const handle = await pickDirectory();
    const persisted = await saveHandle(handle);
    const granted = await requestGranted(handle);
    if (!granted) {
      setStatus("Folder access not granted. Still using browser storage.", "err");
      return;
    }
    backend = await diskBackend(handle);
    storage = backend.storage;
    // copy any existing browser-storage vault onto the folder so nothing is left behind
    const existing = await exportVault(opfsStorage);
    if (existing && !(await Vault.exists(storage))) await importVault(storage, existing);
    setStatus(persisted ? "Saving to your folder now." : "Using your folder this session (could not persist the choice).");
    await render();
  } catch (e) {
    if (isAbort(e)) return; // user cancelled the picker
    setStatus(msg(e), "err");
  }
}

async function onRegrant() {
  try {
    const handle = await loadHandle();
    if (!handle) return onPickFolder();
    if (!(await requestGranted(handle))) {
      setStatus("Still no access. Using browser storage.", "err");
      return;
    }
    backend = await diskBackend(handle);
    storage = backend.storage;
    setStatus("Folder access restored.");
    await render();
  } catch (e) {
    setStatus(msg(e), "err");
  }
}

async function onExport() {
  const bytes = await exportVault(storage);
  if (!bytes) {
    setStatus("No vault to export yet.", "err");
    return;
  }
  download(VAULT_FILE, bytes);
  setStatus("Exported your encrypted vault file.");
}

async function onImport(input: HTMLInputElement) {
  const file = input.files?.[0];
  if (!file) return;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    await importVault(storage, bytes);
    applyVault(null);
    setStatus("Vault imported. Unlock with its password.");
    await render();
  } catch (e) {
    setStatus(msg(e), "err");
  } finally {
    input.value = "";
  }
}

function download(name: string, bytes: Uint8Array) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function isAbort(e: unknown): boolean {
  return e instanceof DOMException && e.name === "AbortError";
}

// ---- vault cards ----

// ---- chunk-6 auth: sign up / log in / confirm-pending / forgot-password, driven by identity.ts ----
// The bare create/unlock password cards become real auth screens. The __kipi.createVault/unlock seam is
// UNCHANGED (it drives the vault directly for the non-auth smokes); this is the HUMAN path. The Supabase
// fetch is injected via authWire for the a6-smoke (no network).

type AuthMode = "login" | "signup" | "confirm" | "forgot" | "no-vault" | "needs-recovery" | "fresh-recovery";
let authMode: AuthMode = "login";
let authPhrase = ""; // the once-shown recovery phrase (D12: cleared when the user continues)
let authEmail = ""; // carried across modes (forgot/no-vault prefill)
let authPassword = ""; // the just-entered login password, retained ONLY to start a fresh vault on this
// browser (no-vault / needs-recovery). Cleared the moment it is used or the user reaches the home.
let authWire: { authFetch?: FetchLike } | null = null;

function buildIdentity(): Identity {
  // Production uses the real fetch; the smoke injects a scripted Supabase wire (no network).
  return new Identity({ client: new SupabaseAuth(authWire?.authFetch), storage });
}

/** D11: map an auth failure to a sanitized, user-safe line (never the raw Supabase message). */
function authMsg(e: unknown): string {
  if (e instanceof AuthError) {
    switch (e.code) {
      case "vault_exists":
        return e.message; // already a friendly, password-free sentence
      case "email_not_confirmed":
        return "Confirm your email first — check your inbox for the link.";
      case "invalid_grant":
      case "invalid_credentials":
        return "Wrong email or password.";
      case "user_already_exists":
      case "email_exists":
        return "That email is already registered. Log in instead.";
      case "weak_password":
        return "Pick a stronger password (at least 6 characters).";
      case "over_email_send_rate_limit":
      case "http_429":
        return "Please wait a minute, then request the confirmation email again.";
      case "network":
        return "Could not reach the login service. Check your connection.";
      default:
        return "Login failed. Try again.";
    }
  }
  if (e instanceof VaultError) return "Wrong password for your local vault.";
  return "Something went wrong. Try again.";
}

function renderAuth(hasVault: boolean): void {
  // A fresh browser (no local vault) defaults to sign up; a browser that already has a vault defaults to
  // log in. Once the user toggles or advances (confirm/forgot/no-vault), that mode is preserved.
  if (!hasVault && authMode === "login") authMode = "signup";
  if (hasVault && authMode === "signup") authMode = "login";
  // gh-stars: social proof BEFORE login too — a star button above the auth card (the app top strip with
  // its own button only shows after login). loadGithubStars fills every .js-gh-stars, so this one and the
  // top-strip one both get the count.
  const ghBar = el(`<div class="flex justify-center pt-6 pb-2"></div>`);
  ghBar.appendChild(githubStarAnchor());
  root().appendChild(ghBar);
  const host = el(`<div id="auth-host"></div>`);
  root().appendChild(host);
  paintAuth(host);
  void loadGithubStars(); // fill the star count once the pre-login button is in the DOM
}

function paintAuth(host: HTMLElement): void {
  host.innerHTML = "";
  if (authMode === "signup") host.appendChild(authSignupCard(host));
  else if (authMode === "confirm") host.appendChild(authConfirmCard(host));
  else if (authMode === "forgot") host.appendChild(authForgotCard(host));
  else if (authMode === "no-vault") host.appendChild(authVaultProblemCard(host, false));
  else if (authMode === "needs-recovery") host.appendChild(authVaultProblemCard(host, true));
  else if (authMode === "fresh-recovery") host.appendChild(authFreshRecoveryCard(host));
  else host.appendChild(authLoginCard(host));
}

function authToggle(host: HTMLElement, label: string, to: AuthMode): HTMLElement {
  const b = el(`<button class="link"></button>`);
  b.textContent = label;
  b.addEventListener("click", () => {
    authMode = to;
    setStatus("");
    paintAuth(host);
  });
  return b;
}

function authLoginCard(host: HTMLElement): HTMLElement {
  const f = el(`
    <section class="card auth-card">
      <h2>Log in</h2>
      <p class="muted">Your email is your login. Your password never leaves this browser un-hashed; we store nothing about your cases.</p>
      <input id="auth-email" type="email" placeholder="email" autocomplete="username" />
      <input id="auth-pw" type="password" placeholder="password" autocomplete="current-password" />
      <button id="auth-login-btn">Log in</button>
      <div class="auth-links"></div>
    </section>`);
  const links = f.querySelector(".auth-links")!;
  links.appendChild(authToggle(host, "Create an account", "signup"));
  links.appendChild(authToggle(host, "Forgot password", "forgot"));
  // Didn't get the confirmation link (or it went to spam)? Resend it, reading the email already typed above.
  // This is where a stuck user lands: they try to log in, get "confirm your email first", and resend here.
  const resend = el(`<button class="link"></button>`);
  resend.textContent = "Resend confirmation email";
  resend.addEventListener("click", () =>
    doResendConfirmation(() => (document.getElementById("auth-email") as HTMLInputElement).value),
  );
  links.appendChild(resend);
  f.querySelector("#auth-login-btn")!.addEventListener("click", () => doLogin(host));
  return f;
}

/** Resend the signup-confirmation email for `getEmail()`. Used from the login card (came back, never got
 *  the link) and the confirm card (just signed up). Supabase 200s whether or not the address exists
 *  (anti-enumeration), so showing success is always safe; a 429 maps to a wait message via authMsg. */
async function doResendConfirmation(getEmail: () => string): Promise<void> {
  const email = getEmail().trim();
  if (!email) {
    setStatus("Enter your email first, then resend.", "err");
    return;
  }
  try {
    await buildIdentity().resendConfirmation(email);
    setStatus("Confirmation email sent — check your inbox and your spam folder.");
  } catch (e) {
    setStatus(authMsg(e), "err");
  }
}

async function doLogin(host: HTMLElement): Promise<void> {
  const email = (document.getElementById("auth-email") as HTMLInputElement).value.trim();
  const pwInput = document.getElementById("auth-pw") as HTMLInputElement;
  const password = pwInput.value;
  if (!email || !password) {
    setStatus("Enter your email and password.", "err");
    return;
  }
  try {
    const out = await buildIdentity().logIn(email, password);
    pwInput.value = ""; // D12: clear the password input after submit
    if (out.status === "unlocked") {
      await unlockInto(out.vault);
      authPassword = "";
      setStatus("Logged in.");
      void render();
    } else if (out.status === "no-vault") {
      // confirmed, but no local vault on this browser (new device / a half-signup)
      authEmail = email;
      authPassword = password; // retained so "start fresh" can create a vault bound to this account
      authMode = "no-vault";
      setStatus("");
      paintAuth(host);
    } else {
      // needs-recovery: Supabase OK but THIS browser's local vault is on a different password
      authEmail = email;
      authPassword = password;
      authMode = "needs-recovery";
      setStatus("");
      paintAuth(host);
    }
  } catch (e) {
    setStatus(authMsg(e), "err");
  }
}

function authSignupCard(host: HTMLElement): HTMLElement {
  const f = el(`
    <section class="card auth-card">
      <h2>Create your account</h2>
      <p class="muted">We collect only your email. Your password derives your local vault key and is never sent to us in the clear; your cases stay encrypted on this device.</p>
      <p class="muted" style="margin-top:-2px">Sign in first — then add your Anthropic + OSINT keys from the left nav (they live in your encrypted vault).</p>
      <input id="auth-email" type="email" placeholder="email" autocomplete="username" />
      <input id="auth-pw" type="password" placeholder="password (8+ characters)" autocomplete="new-password" />
      <input id="auth-pw2" type="password" placeholder="confirm password" autocomplete="new-password" />
      <button id="auth-signup-btn">Sign up</button>
      <div class="auth-links"></div>
    </section>`);
  f.querySelector(".auth-links")!.appendChild(authToggle(host, "I already have an account", "login"));
  f.querySelector("#auth-signup-btn")!.addEventListener("click", () => doSignup(host));
  return f;
}

async function doSignup(host: HTMLElement): Promise<void> {
  const email = (document.getElementById("auth-email") as HTMLInputElement).value.trim();
  const pw = (document.getElementById("auth-pw") as HTMLInputElement);
  const pw2 = (document.getElementById("auth-pw2") as HTMLInputElement);
  if (!email || !pw.value) {
    setStatus("Enter your email and a password.", "err");
    return;
  }
  if (pw.value !== pw2.value) {
    setStatus("The two passwords do not match.", "err");
    return;
  }
  try {
    const out = await buildIdentity().signUp(email, pw.value);
    authPhrase = out.recoveryPhrase;
    authEmail = email;
    pw.value = "";
    pw2.value = "";
    authMode = "confirm";
    setStatus("");
    paintAuth(host);
  } catch (e) {
    setStatus(authMsg(e), "err");
  }
}

function authConfirmCard(host: HTMLElement): HTMLElement {
  const f = el(`
    <section class="card auth-card">
      <h2>Save your recovery key</h2>
      <p class="muted">This is the ONLY way to recover your cases if you forget your password. Save it somewhere safe — we cannot recover it for you.</p>
      <pre id="auth-recovery" class="recovery"></pre>
      <p class="muted">Then check your inbox (and your spam folder) for a confirmation link. After you confirm, log in.</p>
      <button id="auth-confirm-continue">I saved it — continue to log in</button>
      <button id="auth-resend" class="link">Didn't get the email? Resend it</button>
    </section>`);
  (f.querySelector("#auth-recovery") as HTMLElement).textContent = authPhrase; // textContent, never innerHTML
  f.querySelector("#auth-resend")!.addEventListener("click", () => doResendConfirmation(() => authEmail));
  f.querySelector("#auth-confirm-continue")!.addEventListener("click", () => {
    authPhrase = ""; // D12: drop the phrase from memory + the DOM is rebuilt without it
    authMode = "login";
    setStatus("Confirm your email, then log in.");
    paintAuth(host);
  });
  return f;
}

function authForgotCard(host: HTMLElement): HTMLElement {
  const f = el(`
    <section class="card auth-card">
      <h2>Reset your password</h2>
      <p class="muted">Step 1 — we email you a reset link (you set a new password on the secure page it opens). Step 2 — come back here with your recovery key and the new password to unlock your cases.</p>
      <input id="auth-email" type="email" placeholder="email" autocomplete="username" />
      <button id="auth-reset-send">Send reset email</button>
      <hr class="auth-sep" />
      <p class="muted">Already reset your password? Recover your cases:</p>
      <input id="auth-phrase" type="text" placeholder="recovery key" autocomplete="off" />
      <input id="auth-newpw" type="password" placeholder="your new password" autocomplete="new-password" />
      <button id="auth-recover-btn">Recover my cases</button>
      <div class="auth-links"></div>
    </section>`);
  (f.querySelector("#auth-email") as HTMLInputElement).value = authEmail;
  f.querySelector(".auth-links")!.appendChild(authToggle(host, "Back to log in", "login"));
  f.querySelector("#auth-reset-send")!.addEventListener("click", async () => {
    const email = (document.getElementById("auth-email") as HTMLInputElement).value.trim();
    if (!email) {
      setStatus("Enter your email.", "err");
      return;
    }
    try {
      await buildIdentity().requestReset(email);
      setStatus("If that email has an account, a reset link is on its way.");
    } catch (e) {
      setStatus(authMsg(e), "err");
    }
  });
  f.querySelector("#auth-recover-btn")!.addEventListener("click", () => doRecover());
  return f;
}

async function doRecover(): Promise<void> {
  const email = (document.getElementById("auth-email") as HTMLInputElement).value.trim();
  const phraseInput = document.getElementById("auth-phrase") as HTMLInputElement;
  const newpwInput = document.getElementById("auth-newpw") as HTMLInputElement;
  const phrase = phraseInput.value.trim();
  const newpw = newpwInput.value;
  if (!email || !phrase || !newpw) {
    setStatus("Enter your email, recovery key, and new password.", "err");
    return;
  }
  try {
    const out = await buildIdentity().completeRecovery(email, phrase, newpw);
    phraseInput.value = "";
    newpwInput.value = "";
    await unlockInto(out.vault);
    setStatus("Recovered. You're in.");
    void render();
  } catch (e) {
    setStatus(authMsg(e), "err");
  }
}

// no-vault (no local vault here) and needs-recovery (a local vault on a different password) are the same
// situation: you're authenticated, but THIS browser's cases can't be opened with this password. Offer the
// real escapes — start fresh here, import a vault file, or (when a drifted vault exists) recover it. Never
// a dead-end (the gap the founder hit on 2026-06-18).
function authVaultProblemCard(host: HTMLElement, drifted: boolean): HTMLElement {
  const headline = drifted ? "This browser's vault is on a different password" : "No cases on this browser";
  const explain = drifted
    ? "Your account is fine. This browser already has a local vault that was created with a different password, so it can't be opened with the one you just used. Pick how to continue:"
    : "Your account is confirmed, but this browser has no local cases yet (a new device, or a sign-up that didn't finish here). Pick how to continue:";
  const f = el(`
    <section class="card auth-card">
      <h2>${escapeHtml(headline)}</h2>
      <p class="muted">${escapeHtml(explain)}</p>
      <button id="auth-fresh-btn">Start fresh on this browser</button>
      <p class="muted">Creates a clean vault tied to your account (you'll get a new recovery key).${drifted ? " This erases the old vault on this browser — which you can't open anyway." : ""} To bring cases from another device instead, use <b>Import vault</b> in the bar above.</p>
      <div class="auth-links"></div>
    </section>`);
  const links = f.querySelector(".auth-links")!;
  if (drifted) links.appendChild(authToggle(host, "I have this browser's recovery key — recover it", "forgot"));
  links.appendChild(authToggle(host, "Back to log in", "login"));
  f.querySelector("#auth-fresh-btn")!.addEventListener("click", () => doStartFresh(host));
  return f;
}

async function doStartFresh(host: HTMLElement): Promise<void> {
  if (!authPassword) {
    setStatus("Log in again, then choose start fresh.", "err");
    authMode = "login";
    paintAuth(host);
    return;
  }
  try {
    // wipe any existing local vault on this backend (+ the OPFS mirror), then create a clean one bound to
    // the account password the user just authenticated with.
    await storage.remove(VAULT_FILE);
    await opfsStorage.remove(VAULT_FILE).catch(() => {});
    const r = await createVaultFlow(authPassword); // creates + unlocks, sets `vault`
    authPassword = "";
    authPhrase = r.recoveryPhrase;
    authMode = "fresh-recovery";
    setStatus("");
    paintAuth(host);
  } catch (e) {
    setStatus(authMsg(e), "err");
  }
}

// After "start fresh": show the NEW recovery key once, then continue into the (already unlocked) app.
function authFreshRecoveryCard(host: HTMLElement): HTMLElement {
  const f = el(`
    <section class="card auth-card">
      <h2>Save your new recovery key</h2>
      <p class="muted">This browser now has a clean vault. Save this recovery key — it's the only way back in if you forget your password.</p>
      <pre id="auth-recovery" class="recovery"></pre>
      <button id="auth-fresh-continue">I saved it — open kipi</button>
    </section>`);
  (f.querySelector("#auth-recovery") as HTMLElement).textContent = authPhrase;
  f.querySelector("#auth-fresh-continue")!.addEventListener("click", () => {
    authPhrase = ""; // D12: drop the phrase; the vault is already unlocked -> render the home
    authMode = "login"; // reset for next time
    void render();
  });
  void host; // host kept for signature parity with the other cards
  return f;
}

/** D1: strip any Supabase auth/recovery token from the URL on load (a reset redirect can carry one in
 *  the fragment). It is NEVER parsed/consumed; kipi recovers via the local recovery phrase. Route
 *  hashes (#/enrich) are untouched — only token fragments match. */
function stripAuthFragment(): void {
  if (/access_token=|refresh_token=|type=recovery/.test(location.hash + location.search)) {
    history.replaceState(null, "", location.pathname);
  }
}

// The unlocked home: a graph-dominant split-view cloning graph.html's right column — a compact
// setup strip (storage / key / history, all VISIBLE by default — D6), the cytoscape graph filling
// the content area (visible + initialized ON UNLOCK — D1), and a collapsible Investigator dock
// holding the relocated run controls + the OSINT pivot.
function renderSplitView() {
  // ac-ui: setup (vault storage / Anthropic key / history / feedback) moved to the Account page
  // (#/account) so the home is purely graph + chat. A bare #status anchor stays so home actions that
  // call setStatus() still have a target.
  root().appendChild(el(`<p id="status" class="ok"></p>`));

  // ccc-workspace-shell: graph canvas (left, fills) + chat control bar (right, resizable/collapsible)
  // sit in a flex ROW so the chat is a vertical bar. #status stays a thin top line above the row.
  const wsRow = el(`<div class="ws-row"></div>`);
  wsRow.appendChild(renderGraphPane());
  wsRow.appendChild(renderDock());
  root().appendChild(wsRow);
  // ccc-lifecycle-strip: paint the chat lifecycle strip now that the dock (and its #chat-lifecycle-rail)
  // is ATTACHED to the document — renderLifecycleRail resolves the rail by id, so it must run post-attach.
  renderLifecycleRail(currentRoute());

  // Initialize cytoscape on the sized, visible #cy so the surface is non-blank on unlock (D1).
  ensureCyGraph();
  // cd-ui (D5/D6): register the graph bridge the chat drives, now that #cy + the chat exist.
  window.__kipiGraph = kipiGraphApi();
  // gh-hydrate (parity G1): paint the WHOLE-CASE graph from prior runs so a returning user / a
  // reload lands on the accumulated graph, not a blank canvas.
  // rsn-graph-model-precedence: preferInMemory — if a run is live/just-finished, keep its in-memory model
  // instead of cold-reading the (possibly-stale) vault, so navigating back mid-run does NOT revert the graph.
  hydrateCaseGraph({ preferInMemory: true });
  // sp-782e139a/d9fe0620: subscribe the home Process-progress affordance + paint the CURRENT processJob (a
  // run may already be in flight — auto-Process kicks off from intake before the user lands here). Routes
  // are mutually exclusive, so re-owning the single processSub on each home mount is safe (the /reports
  // panel re-subscribes when IT mounts).
  processSub = paintHomeProcess;
  paintHomeProcess(processJob);
  // ux-rowmenu (item 4): an /entities row "Open in graph" routed here — focus the node now the graph exists.
  applyPendingGraphFocus();
  // rsn-reattach: replay an in-flight / just-finished run into this freshly-mounted dock (#trail/#findings +
  // Stop). Covers BOTH teardown paths — a full page-view teardown (/enrich, /account) and a renderSplitView
  // re-mount (a detail route) — because renderSplitView is the single Workspace-mount path they both return to.
  reattachRunIntoDock();
  // ob-tour: a fresh user (never onboarded, zero runs) gets the one-time first-run overlay.
  maybeShowOnboarding();
  // hist-reopen (kf-fix): a brief reopened from History (/account) routed home; the dock now exists, show it.
  if (pendingBriefObjective) {
    const o = pendingBriefObjective;
    pendingBriefObjective = null;
    viewBrief(o);
  }
}

// ac-ui: the Account page — login/session lives here (the unlock gate highlights this nav item),
// plus the vault storage controls and the Anthropic key. Moved off the graph home so the graph is
// purely graph + chat. Rendered by app.ts (not pages.ts) because it touches the vault + the key,
// which pages.ts is deliberately barred from doing.
function renderAccountView(): void {
  const page = el(`<section class="pg"></section>`);
  page.appendChild(
    el(
      `<div class="pg-head"><h1 class="pg-title">LLM API &amp; account</h1><p class="pg-sub">Your Anthropic key, login &amp; session, vault storage, and recovery. Everything stays encrypted on this device.</p></div>`,
    ),
  );
  const body = el(`<div class="pg-body"></div>`);
  body.appendChild(el(`<p id="status" class="ok"></p>`));
  // ux (brief §Account #17): order by frequency — the Anthropic key (breaks the tool if unset) FIRST,
  // then the session lock, then storage, then history/feedback.
  body.appendChild(renderKeysCard());
  body.appendChild(renderSessionCard());
  body.appendChild(renderStorageBar());
  body.appendChild(renderHistoryCard());
  body.appendChild(renderFeedbackRow());
  page.appendChild(body);
  root().appendChild(page);
  // ob-keyprompt (kf-fix): a keyless run set pendingKeyFocus + routed here. The keys card is now
  // ATTACHED (appendChild above), so highlight it and focus #apikey. rAF so layout has settled on the
  // just-appended subtree (focusing a detached/unlaid-out node no-ops — codex P1).
  if (takePendingKeyFocus()) {
    setKeyNeeded(true);
    requestAnimationFrame(() => {
      document.getElementById("keycard")?.scrollIntoView({ behavior: "smooth", block: "center" });
      (document.getElementById("apikey") as HTMLInputElement | null)?.focus();
    });
  }
}

// sec (FAANG MED): a visible Lock / Sign-out control. Locking zeroes the in-memory data key (vault.lock)
// AND clears case-derived state via the applyVault(null) chokepoint, then re-renders to the login gate.
// (Also closes the prior gap: there was NO user-facing lock control after the ac-ui move.)
function lockVault(): void {
  vault?.lock();
  applyVault(null);
  void render();
}
// stay-signed-in (clu-auth): Sign out is the REAL lock — it forgets the persisted session key so the
// next load lands on the login screen. (lockVault alone keeps the key, so an idle-lock/reload restores.)
async function signOut(): Promise<void> {
  await forgetDataKey().catch(() => {});
  lockVault();
}
function renderSessionCard(): HTMLElement {
  const card = el(`
    <section class="card" id="sessioncard">
      <h2>Session</h2>
      <p class="muted">You stay signed in on this device. Sign out to lock this browser and return to the login screen.</p>
      <button id="lockBtn">Sign out</button>
    </section>`);
  card.querySelector("#lockBtn")!.addEventListener("click", () => void signOut());
  return card;
}

// ob-tour: the first-run onboarding overlay — shown ONCE per vault. Gated on getOnboarded==false
// AND zero runs (a returning user with cases is never interrupted). Dismiss writes setOnboarded
// through the session chokepoint. role=dialog + aria-modal, Escape dismisses, focus the button
// (codex finding-3, folded). It is an overlay with a dismiss, never a blocking gate.
function maybeShowOnboarding(): void {
  if (!vault) return;
  if (getOnboarded(vault)) return;
  if (listRuns(vault).length > 0) return; // a user with existing cases is past onboarding
  // Append to the app root (cleared on every render → torn down on nav). The overlay is position:fixed,
  // so it covers the whole viewport and is never clipped by the compressed graph pane.
  const host = root();
  const card = el(`
    <div id="onboard" class="onboard-overlay">
      <section class="card onboard-card" role="dialog" aria-modal="true" aria-labelledby="onboard-h">
        <h2 id="onboard-h">Welcome to kipi</h2>
        <ul class="onboard-steps">
          <li><b>Nothing leaves your browser.</b> Your cases, keys, and findings stay encrypted on this device. We store nothing.</li>
          <li><b>Bring your own Anthropic key.</b> Add it on the API page (left nav); you only need it the first time you run an investigation, not now.</li>
          <li><b>Start anywhere.</b> Paste a report under Reports, or type an objective in the Investigator and run it.</li>
          <li><b>Own your data.</b> Open the API page (left nav) and use "Save to a folder…" to keep the encrypted vault on your own disk.</li>
        </ul>
        <button id="onboard-dismiss" class="onboard-dismiss">Got it</button>
      </section>
    </div>`);
  const dismiss = async () => {
    if (!vault) return;
    try {
      await setOnboarded(vault);
    } catch {
      /* locked — the overlay still goes away; it re-shows next unlock, which is fine */
    }
    card.remove();
    document.removeEventListener("keydown", onKey);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") void dismiss();
  };
  card.querySelector("#onboard-dismiss")!.addEventListener("click", () => void dismiss());
  document.addEventListener("keydown", onKey);
  host.appendChild(card);
  (card.querySelector("#onboard-dismiss") as HTMLElement).focus(); // move focus into the dialog
}

/**
 * gh-hydrate G1: on split-view MOUNT, render the WHOLE-CASE graph (every run folded, gate-faithful,
 * key-redacted at the session layer via graphModelForCase) so a returning user sees the ACCUMULATED
 * findings instead of a blank canvas — the headline parity regression. A FULL render is correct on
 * the initial mount (there are no in-place positions to preserve). The mount RESETS the expand fence
 * (D4: graphGen++ + clear the expand sets) so a stale in-flight expand can never merge into the
 * freshly-hydrated case. #cy-empty shows iff the model has zero FINDING/LEAD nodes — an objective-only
 * model (runs exist but nothing graphed) still shows the hint (D10). Zero runs -> graphModelForCase
 * returns null -> keep the hint.
 */
// rsn-graph-model-precedence: `preferInMemory` is set ONLY by the Workspace MOUNT (renderSplitView). At that
// one site, while a run is LIVE (status "running"), a cold graphModelForCase(vault) re-read would REVERT the
// graph — the run grew lastGraphModel in memory with live observations the durable run: record does NOT hold
// yet (runInvestigation persists run: only at finalize). The founder hit exactly this: "the graph reverted
// and stopped populating." So a live run's in-memory model wins on the mount (graph-hydration smoke test
// covers this precedence).
//
// The executable gate (code, not prose) checks ONLY "running", NOT "done": runInvestigation `await`s
// vault.put(run:…) (session.ts:433) BEFORE it
// returns, so by the time the run store flips to "done" the record is already persisted — a cold read of a
// finalized run is correct, not stale (finding-7's hypothesized finalize-vs-mount race does not exist given
// the awaited persist). Gating "done" would be actively WRONG: afterCorrection() and Process re-render via
// render() while status is still "done" this session, and pinning the in-memory model would make an analyst
// correction or a Process re-projection NOT show up on the graph. Those (and every non-mount caller) leave
// preferInMemory false and force the cold read; the mount only protects the still-streaming case.
function hydrateCaseGraph(opts?: { preferInMemory?: boolean }): void {
  if (!vault) return;
  // D4: a fresh mount FULLY resets the graph state — a stale model / expand set from a prior
  // vault, lock, or reset must never be grown into by the next run (the run-start path now
  // PRESERVES lastGraphModel so the graph accumulates, so the reset lives here, once, on mount).
  graphGen++;
  expandedNodeIds.clear();
  inFlightNodeIds.clear();
  transformDone.clear(); // nd-drawer (D6): transform state is per-graph-generation
  transformInFlight.clear();
  lastTransformResult.clear();
  // keepInMemory: ONLY a LIVE (streaming) run owns the in-memory model (its in-flight nodes aren't persisted
  // yet); a finalized/idle case reads the durable model from the vault (which already holds the finished run).
  const keepInMemory = !!opts?.preferInMemory && getRunStore().status === "running" && !!lastGraphModel;
  // hydra ISSUE-1 + ISSUE-5: when NOT holding the live in-memory model (a fresh mount / reload / post-abort),
  // prefer the durable run journal if it carries in-flight entities the finalized fold hasn't captured yet. A
  // CLEAN finalize clears the journal, so once a run completes graphModelForCase (which now includes it) wins.
  const liveJournal = keepInMemory ? null : readLiveRun(vault);
  const caseModel = keepInMemory
    ? lastGraphModel
    : liveJournal && liveJournal.nodes.some((n) => n.kind !== "objective")
      ? liveJournal
      : graphModelForCase(vault); // null on zero runs; secrets already redacted at the session layer
  lastGraphModel = caseModel;
  const empty = document.getElementById("cy-empty");
  // clu-docx-and-empty-graph: "has real data" = at least one NON-objective node. An objective-only model
  // (zero runs → null, OR runs that produced no entities — e.g. a failed/empty ingest) is the EMPTY state.
  const hasEntities = !!caseModel && caseModel.nodes.some((n) => n.kind !== "objective");
  if (!hasEntities) {
    if (empty) empty.hidden = false; // show the Start-here hint
    // Render a CLEAR canvas — do NOT draw the lone seed/objective node behind the Start-here overlay
    // (that was the "random square" the founder saw). The overlay is the empty state, not a 1-node graph.
    const g = ensureCyGraph();
    if (g) g.render({ objective: caseModel?.objective ?? "", nodes: [], edges: [] });
    return;
  }
  const g = ensureCyGraph();
  if (g) {
    g.render(caseModel);
    g.setSpineFocus(graphFocusThreats); // G2a: default the view to the threat spine (keep-all data untouched)
  }
  if (empty) empty.hidden = true; // real entities exist → no hint
}

// sp-782e139a + sp-d9fe0620: the home Process-progress affordance. The ~10min consolidate pass used to show
// only a static "Analyzing…" chat aside on the home graph (reads as hung) — no per-step progress, no graph
// cue. This paints a thin "Analyzing: <step> · done/total" bar over the graph from the SAME processJob the
// /reports panel subscribes to, and toggles a #graph.processing class; it hides + clears on idle/done/error.
// Inline-styled (no CSS-file dependency) + textContent only (XSS-safe). Subscribed in renderSplitView.
function paintHomeProcess(state: ProcessUiState): void {
  const graph = document.getElementById("graph");
  const running = state.status === "running";
  if (graph) graph.classList.toggle("processing", running);
  const host = document.getElementById("graph-proc");
  if (!host) return;
  if (!running) { host.hidden = true; host.replaceChildren(); return; }
  const total = state.steps.length;
  const done = state.steps.filter((s) => s.status === "ok" || s.status === "skipped").length;
  const current = state.steps.find((s) => s.status === "running") ?? state.steps.find((s) => s.status === "pending");
  host.hidden = false;
  // hydra ISSUE-4 family (founder 2026-07-07): was forced-dark (#16202e/#e8eef6) → a dark island over the
  // LIGHT-mode graph. Route to the themed card/ink/border tokens so the progress popover follows the theme.
  host.style.cssText =
    "position:absolute;top:10px;left:50%;transform:translateX(-50%);z-index:5;max-width:520px;min-width:260px;" +
    "background:var(--card);color:var(--ink);border:1px solid var(--border);border-radius:9px;padding:8px 13px;" +
    "font:12px/1.4 system-ui,-apple-system,sans-serif;box-shadow:0 6px 22px rgba(0,0,0,.35)";
  const label = document.createElement("div");
  label.textContent = `Analyzing the case — ${current ? current.label : "finishing"} · ${done}/${total}`;
  const barWrap = document.createElement("div");
  barWrap.style.cssText = "margin-top:6px;height:4px;border-radius:2px;background:#26384c;overflow:hidden";
  const bar = document.createElement("div");
  bar.style.cssText = `height:100%;width:${total ? Math.round((done / total) * 100) : 0}%;background:#39b3a6;transition:width .3s`;
  barWrap.appendChild(bar);
  host.replaceChildren(label, barWrap);
}

// The graph surface (#graph) — full-bleed, flex-1, isolated stacking context (D4). NOT hidden:
// it shows the dot-grid + an empty-state hint until the first run renders into it.
function renderGraphPane(): HTMLElement {
  // ux-starthere (brief §1/X-5): the empty-home overlay is a "Start here" hero — three steps with the
  // Investigator as the front door — not a bare hint. Keeps id="cy-empty" so hydrateCaseGraph's
  // existing show/hide (visible iff no finding/lead node) drives it unchanged; it fades to the graph
  // the moment data exists. .start-here re-enables pointer-events (the base .cy-empty is none).
  const pane = el(`
    <div id="graph" class="cygraph-surface graph-pane">
      <div id="cy"></div>
      <div id="cy-controls" class="cy-controls"></div>
      <div id="cy-stats" class="cy-stats"></div>
      <div id="cy-setchip"></div>
      <div id="cy-menu"></div>
      <div id="graph-proc" class="graph-proc" hidden></div>
      <div id="cy-empty" class="cy-empty start-here">
        <div class="sh-card">
          <div class="sh-title">Start here</div>
          <div class="sh-sub">A new case has three steps — or just ask the Investigator below.</div>
          <div class="sh-steps">
            <button type="button" class="sh-step" data-sh="reports"><span class="sh-num">1</span><span class="sh-body"><span class="sh-step-label">Add evidence</span><span class="sh-step-hint">Drop files or paste text on Reports &amp; intake.</span></span></button>
            <button type="button" class="sh-step" data-sh="process"><span class="sh-num">2</span><span class="sh-body"><span class="sh-step-label">Process the case</span><span class="sh-step-hint">Extract entities, build the graph &amp; brief.</span></span></button>
            <button type="button" class="sh-step" data-sh="investigate"><span class="sh-num">3</span><span class="sh-body"><span class="sh-step-label">Investigate</span><span class="sh-step-hint">Ask a question or run <code>investigate &lt;domain&gt;</code>.</span></span></button>
          </div>
        </div>
      </div>
    </div>`);
  pane.querySelector('[data-sh="reports"]')?.addEventListener("click", () => navigate("/reports"));
  // sp-52b54ad2: "Process the case" used to navigate("/reports") — the SAME target as step 1 "Add
  // evidence" — so it never ran Process. Run it in place; auto:true routes the "Analyzing…/complete"
  // status through notifyUser so the user sees it on the home graph (no Process panel mounted here yet).
  pane.querySelector('[data-sh="process"]')?.addEventListener("click", () => { void runProcessJob({ auto: true }).catch((e) => setStatus(msg(e), "err")); });
  pane.querySelector('[data-sh="investigate"]')?.addEventListener("click", focusInvestigator);
  return pane;
}

// ux-starthere: open the Investigator dock (if collapsed) and focus its input — the home front door.
function focusInvestigator(): void {
  const dock = document.querySelector(".dock");
  if (dock && !dock.classList.contains("open")) {
    (document.getElementById("dockToggle") as HTMLElement | null)?.click();
  }
  const input = document.getElementById("chat-input") as HTMLInputElement | null;
  input?.scrollIntoView({ behavior: "smooth", block: "center" });
  input?.focus();
}

// The collapsible Investigator dock (graph.html's docked-chat pattern). Default OPEN when
// kipiDockOpen is unset (D9) so the run controls are visible. Toggling persists the state +
// resizes the graph after the transition (D3, no-op-safe if no graph yet).
function renderDock(): DocumentFragment {
  const open = (typeof sessionStorage !== "undefined" ? sessionStorage.getItem("kipiDockOpen") : null) !== "0";
  // ccc-workspace-shell: the chat is the RIGHT vertical control bar now (was a bottom dock). The left
  // drag handle resizes it; the bar toggle collapses it to a thin rail. The run-output ids
  // (#trail/#findings/#leads/#brief/#stopBtn) live inside #chat-host (mountChatDock) and are untouched.
  const dock = el(`
    <div class="dock ${open ? "open" : ""}">
      <div class="dock-resize" id="dockResize" title="Drag to resize the chat"></div>
      <button class="dock-bar" id="dockToggle" title="Toggle the Investigator">
        <span class="dock-title"><svg class="ico" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg> Investigator</span>
        <span class="dock-caret" id="dockCaret">${open ? "›" : "‹"}</span>
      </button>
      <div class="dock-body" id="dockBody"${open ? "" : " hidden"}></div>
    </div>`);
  // restore the analyst's chosen width (only when open — the collapsed rail uses the CSS width).
  if (open && typeof sessionStorage !== "undefined") {
    const w = sessionStorage.getItem("kipiDockW");
    if (w) dock.style.width = w;
  }
  const body = dock.querySelector("#dockBody") as HTMLElement;
  // cd-ui: the cloned _chat.html unified investigator replaces the placeholder run controls. It
  // carries the run-output ids (#trail/#findings/#leads/#brief/#stopBtn/#briefBtn/#dlBriefBtn) the
  // existing proofs depend on; startInvestigation/startBrief render into them (D7).
  // ccc-lifecycle-strip: the lifecycle progress strip lives at the TOP of the chat now (was the top-bar
  // #lifecycle-rail). renderLifecycleRail fills it; clicking a stage prefills the chat input with that
  // stage's prompt instead of navigating. Inline-styled (app.css is out of this issue's scope); the .lc-*
  // chip styles are global so the chips render the same. Hidden until lifecycleStages populates it.
  const lifeRail = el(`<div id="chat-lifecycle-rail" class="lifecycle-strip" aria-label="Investigation lifecycle" style="align-items:center;gap:4px;flex-wrap:wrap;padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px;display:none;"></div>`);
  body.appendChild(lifeRail);
  const chatHost = el(`<div id="chat-host" class="chat-host"></div>`);
  body.appendChild(chatHost);
  mountChatDock(chatHost, chatDeps());
  // ccc: the chat bar is fully HIDABLE — collapsing removes it entirely (graph goes full-width) and a
  // floating "Chat" button appears over the graph to bring it back (the in-bar caret can't reopen a
  // hidden bar). setDockOpen is the single source of truth for both controls + persistence.
  const reopenBtn = el(`<button id="chatReopen" class="chat-reopen" title="Show the Investigator"><svg class="ico" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg> Chat</button>`) as HTMLButtonElement;
  const setDockOpen = (isOpen: boolean): void => {
    dock.classList.toggle("open", isOpen);
    body.hidden = !isOpen;
    dock.querySelector("#dockCaret")!.textContent = isOpen ? "›" : "‹";
    // open → restore the saved width; hidden → drop the inline width (the dock is display:none anyway).
    if (isOpen) { const w = typeof sessionStorage !== "undefined" ? sessionStorage.getItem("kipiDockW") : null; dock.style.width = w || ""; }
    else { dock.style.width = ""; }
    reopenBtn.hidden = isOpen; // the floating reopen button shows ONLY while the bar is hidden
    if (typeof sessionStorage !== "undefined") sessionStorage.setItem("kipiDockOpen", isOpen ? "1" : "0");
    setTimeout(() => cyGraph?.resize(), 220); // cytoscape doesn't auto-detect the flex resize
  };
  reopenBtn.hidden = open; // initial: visible only if the bar starts hidden
  dock.querySelector("#dockToggle")!.addEventListener("click", () => setDockOpen(!dock.classList.contains("open")));
  reopenBtn.addEventListener("click", () => setDockOpen(true));
  // drag the left edge to resize the chat bar (pointer events = mouse + touch; clamped so the graph
  // always keeps room; persisted so the width survives nav/reload).
  const resizeHandle = dock.querySelector("#dockResize") as HTMLElement;
  let dragging = false, startX = 0, startW = 0;
  // clamp the max so the graph always keeps room (the JS clamp is authoritative — there is no CSS
  // max-width to fight it; codex finding-1). Floor 300px; ceiling = the smaller of 720 and "viewport
  // minus 320 for the graph", never below the floor.
  const maxDockWidth = (): number => Math.max(300, Math.min(720, window.innerWidth - 320));
  const onMove = (e: PointerEvent) => {
    if (!dragging) return;
    const w = Math.min(maxDockWidth(), Math.max(300, startW + (startX - e.clientX))); // drag left ⇒ wider
    dock.style.width = `${w}px`;
  };
  const onUp = () => {
    if (!dragging) return;
    dragging = false;
    document.removeEventListener("pointermove", onMove);
    document.removeEventListener("pointerup", onUp);
    document.removeEventListener("pointercancel", onUp);
    if (typeof sessionStorage !== "undefined") sessionStorage.setItem("kipiDockW", dock.style.width);
    cyGraph?.resize();
  };
  resizeHandle.addEventListener("pointerdown", (e) => {
    const pe = e as PointerEvent;
    dragging = true; startX = pe.clientX; startW = dock.getBoundingClientRect().width;
    // capture the pointer so a release OUTSIDE the window still fires pointerup/pointercancel here —
    // otherwise dragging stays true with listeners bound and the next move jumps the width (codex finding-2).
    try { resizeHandle.setPointerCapture(pe.pointerId); } catch { /* older engines: fall back to doc listeners */ }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    document.addEventListener("pointercancel", onUp);
    e.preventDefault();
  });
  // return BOTH the dock and the floating reopen button as siblings in the workspace row, so the button
  // survives when the dock is hidden (display:none).
  const frag = document.createDocumentFragment();
  frag.append(dock, reopenBtn);
  return frag;
}

// cd-ui: the chat dock's dependency bundle. The dock never touches the vault or the key — every
// AI/graph action routes through these app.ts chokepoints (where redaction + the per-run fence
// live). The scripted-wire seam (chatWire) is injected only by the live-streaming smoke.
function chatDeps(): ChatDeps {
  return {
    async runObjective(objective) {
      const result = await startInvestigation(
        objective,
        chatWire ? { fetchImpl: chatWire.runFetch, toolOpts: chatWire.toolOpts } : {},
      );
      if (!result) return null;
      // co-investigator briefing (video-review 2026-06-25): compose the agent's actual "where we stand" reply
      // from the findings this run produced, replacing the hardcoded count line. Fail-soft → "" (dock falls
      // back to the count summary), so a briefing failure never blocks the run from reporting done.
      // briefingAllowed: in TEST mode (chatWire installed) only brief when the briefing fetch is scripted —
      // otherwise the model call would hit the real network (smoke egress). Production (no wire) always briefs.
      const briefing = vault && briefingAllowed()
        ? await runBriefingFor(
            vault,
            { objective, promoted: result.promoted, leads: result.leads, steps: result.steps, stopReason: result.stopReason },
            { fetchImpl: chatWire?.qaFetch },
          )
        : "";
      return {
        stopReason: result.stopReason,
        promoted: result.promoted.length,
        leads: result.leads.length,
        worked: result.worked,
        degradedReason: result.degradedReason,
        briefing,
      };
    },
    async runCase() {
      // A3: the whole-case pass — one DEEP un-caged run over every seed; renders + grows the graph the
      // same way a per-objective run does, and returns the still-uninvestigated pivots for the analyst.
      const result = await startCaseInvestigation(
        chatWire ? { fetchImpl: chatWire.runFetch, toolOpts: chatWire.toolOpts } : {},
      );
      if (!result) return null;
      // co-investigator briefing (video-review 2026-06-25): the case-mode "where we stand against the whole
      // case" reply — objective-oriented, names the still-uninvestigated pivots as the next move. Fail-soft.
      const briefing = vault && briefingAllowed()
        ? await runBriefingFor(
            vault,
            {
              objective: result.objective || "the whole case",
              promoted: result.promoted,
              leads: result.leads,
              steps: result.steps,
              stopReason: result.stopReason,
              pivots: result.recommendedPivots.map((p) => p.name),
            },
            { fetchImpl: chatWire?.qaFetch },
          )
        : "";
      return {
        stopReason: result.stopReason,
        promoted: result.promoted.length,
        leads: result.leads.length,
        rosterSize: result.rosterSize,
        pivots: result.recommendedPivots.map((p) => ({ name: p.name })),
        worked: result.worked,
        degradedReason: result.degradedReason,
        briefing,
      };
    },
    stop() {
      activeAbort?.abort();
    },
    async commitProposedAction(action) {
      if (action.kind !== "remove_graph_node") {
        return { ok: false, reason: "This proposed action is review-only until it has an evidence-backed commit path." };
      }
      const target = action.target ?? "";
      if (!target.trim()) return { ok: false, reason: "No graph node target was supplied." };
      await removeNodeByTarget(target);
      return { ok: true, actionId: action.id };
    },
    async generateBrief(objective) {
      await startBrief(objective, chatWire?.qaFetch);
    },
    downloadBrief() {
      onDownloadBrief();
    },
    async answer(question, selectedName, history) {
      if (!vault) throw new Error("Unlock your vault to ask questions.");
      // Node-reference (founder 2026-06-24): forward the SELECTED graph node so a deictic question resolves to it.
      // history (founder 2026-07-03): the dock's recent turns, so follow-ups resolve against the prior answer.
      const res = await answerQuestion(vault, question, {
        ...(chatWire?.qaFetch ? { fetchImpl: chatWire.qaFetch } : {}),
        selectedNode: selectedName ?? null,
        history: history ?? [],
      });
      // A5: surface the coverage report + any unverified citation IN the chat answer (else they are
      // computed but invisible — the wiring-check gap). Partial coverage + a hallucinated cite are
      // exactly what an analyst must see before trusting the answer.
      let answer = res.answer;
      if (res.coverage.mode === "partial") {
        answer += `\n\n_Coverage: partial — answered from ${res.coverage.used} of ${res.coverage.total} findings/leads (the case is large; ask a narrower question for full coverage)._`;
      }
      if (res.unsupportedCitations.length) {
        answer += `\n\n**Unverified citations** — ${res.unsupportedCitations.length} sentence(s) cite a fact the cited run does not contain:` +
          res.unsupportedCitations.map((u) => `\n- "${u.sentence}" — unverified: ${u.unsupportedFacts.join(", ")}`).join("");
      }
      return { answer, sources: res.sources };
    },
    // Node-reference (founder 2026-06-24): the analyst's selected graph node, so a deictic Q&A resolves to it.
    selectedName: () => selectedNodeData?.full_name ?? null,
    listRuns() {
      return vault ? listRuns(vault) : [];
    },
    graph() {
      return window.__kipiGraph ?? null;
    },
    entityView(node) {
      return entityViewFor(node.kind, node.type || "", node.full_name);
    },
    edgeView(edge: EdgeCardData) {
      return edgeViewFor(edge.src_id, edge.dst_id);
    },
    // ccc-workspace-shell: the migrated node-drawer content. app.ts owns this (it reaches the entity DB,
    // cyGraph, the OSINT transform menu, and spends the key on the AI dossier / Type-relations passes — all
    // barred from the dock), so the dock hands us the card host and we fill it with the FULL node detail.
    renderNodeBody(host, node) {
      buildNodeCard(host, node);
    },
    // cd-tradecraft: the gates run against the SCOPED vault (key-redacted in the session layer). The dock
    // never sees the vault or the key.
    async recordScope(scope) {
      if (!vault) throw new Error("Unlock your vault to capture scope.");
      await recordScope(vault, scope); // await the durable put (hydra ISSUE-2) so scope survives a reload
    },
    readScope() {
      return vault ? getScopeFields(vault) : null;
    },
    async runGate(step) {
      if (!vault) throw new Error("Unlock your vault to run a tradecraft gate.");
      try {
        return await runTradecraftGate(vault, step, chatWire?.qaFetch ? { fetchImpl: chatWire.qaFetch } : {});
      } catch (e) {
        throw e instanceof Error ? e : new Error(String(e));
      }
    },
    tradecraftState() {
      return vault ? tradecraftState(vault).map((s) => ({ step: s.step, done: s.done })) : [];
    },
    // clu-chat-intake: intake from the chat. Decode (OCR threads onProgress for the chat bar) + persist
    // through the SAME ingestText gate the Reports page uses; return the extracted entities for the
    // completeness check. sf-cases guard: a slow OCR + a mid-extraction case switch must NOT land A's
    // file in B — capture THIS case's scoped vault + caseGen, and refuse if the case switched.
    async ingestFile(file, onProgress) {
      if (!vault) throw new Error("Unlock your vault to ingest.");
      const ingestVault = vault;
      const cgen = caseGen;
      const { text, kind, warnings, entities: structured } = await fileToText(file, undefined, onProgress);
      if (kind === "unsupported" || !text.trim()) throw new Error(warnings?.length ? `Could not read that file: ${warnings.join(" ")}` : "Could not read text from that file (unsupported, unreadable, or no text found).");
      if (cgen !== caseGen) throw new Error("Case switched during ingest — re-upload in the active case.");
      // ig-record: union the CSV/TSV/XLSX column-typed entities with the flat extraction for the completeness
      // check shown in chat (the person/handle columns the flat regex misses); ingestText re-redacts + gates.
      const entities = mergeEntities(structured ?? [], extractEntities(text));
      // ingestText redacts the name into `objective` = "file: <key-redacted-name> #<id>". Reuse THAT
      // redacted name for the chat display so a key embedded in a filename never reaches the chat (codex).
      const { objective } = await ingestText(ingestVault, file.name, text, structured ?? []);
      const safeName = objective.replace(/^file:\s*/, "").replace(/\s+#[0-9a-z]+$/i, "").trim() || "file";
      if (entities.length > 0) scheduleAutoProcess(); // auto-analyze the chat-dropped file, only on real new data (founder + codex)
      return { kind, entities, warnings, safeName };
    },
    async ingestPastedText(text) {
      if (!vault) throw new Error("Unlock your vault to ingest.");
      const ingestVault = vault;
      const cgen = caseGen;
      const entities = extractEntities(text);
      if (cgen !== caseGen) throw new Error("Case switched during ingest — re-paste in the active case.");
      await ingestText(ingestVault, "pasted text", text);
      if (entities.length > 0) scheduleAutoProcess(); // auto-analyze pasted evidence, only on real new data (founder + codex)
      return { entities };
    },
    onIngested() {
      hydrateCaseGraph(); // re-project the home graph so the new entities + network edges show live (as squares)
      // auto-process is scheduled by the ingest methods themselves (guarded by entities-produced), NOT here —
      // onIngested fires even when every file failed, which would spend on nothing (codex).
    },
    // clu-conductor: the conductor SUGGESTS the next step; the dock posts it and the analyst greenlights.
    conductorSuggestion() {
      return vault ? suggestNextStep(conductorStateFor(vault)) : null;
    },
    // clu-error-output: the honest cause of the last run that returned null (startInvestigation swallows
    // the throw to do its own UI). The dock shows this instead of guessing "no key".
    lastRunError() {
      return lastInvestigateError;
    },
    // clu-chat-persist: rehydrate + persist the conversation through the SCOPED vault (key-redacted +
    // capped in the session layer). The dock never touches the vault/key. No-op when no case is active
    // (vault is null) so a fresh user with no case never errors.
    loadChat() {
      return vault ? loadChatHistory(vault) : [];
    },
    saveChat(messages) {
      if (vault) enqueueChatWrite(vault, messages); // serialized writes (codex): newest snapshot wins, no out-of-order overwrite
    },
  };
}

// clu-chat-persist (codex review): saveChat is called from synchronous render paths, so two turns in the
// same tick would fire two un-awaited vault.put writes that could complete OUT OF ORDER — an older snapshot
// overwriting a newer one (data loss). Serialize them through ONE chained promise so each write waits for
// the prior and they apply in call order. Each call snapshots the array (slice) so a later mutation of the
// dock's live `history` can't change what an in-flight write persists. A failed write never breaks the
// chain (the next turn re-persists the full history anyway).
let chatWriteChain: Promise<void> = Promise.resolve();
function enqueueChatWrite(scoped: Vault, messages: ChatMessage[]): void {
  const snapshot = messages.slice();
  chatWriteChain = chatWriteChain.then(() => saveChatHistory(scoped, snapshot)).catch(() => {});
}

// cd-ui (D6): the graph bridge the chat drives — an ADAPTER over CyGraph's REAL methods (no phantom
// API). Each call no-ops safely when there is no graph yet.
function kipiGraphApi(): KipiGraph {
  return {
    searchGraph: (q) => void cyGraph?.searchNode(q),
    highlightByName: (name) => void cyGraph?.searchNode(name),
    // A4: a chat filter command MERGES into the shared state (not clobber the UI facets, and vice-versa).
    applyFilter: (f) => { Object.assign(graphFilterState, f); applyGraphFilter(); refreshFacetControls(); },
    showAll: () => {
      for (const k of Object.keys(graphFilterState) as (keyof typeof graphFilterState)[]) delete graphFilterState[k];
      cyGraph?.clearFilter(); cyGraph?.clearSearch(); refreshFacetControls();
    },
    fit: () => cyGraph?.fit(),
    reLayout: () => cyGraph?.reLayout(),
    setLayout: (n) => cyGraph?.setLayout(n),
    focusDirection: (dir) => cyGraph?.showDirection(dir),
    selectedName: () => selectedNodeData?.full_name ?? null,
    digNode: (id) => {
      const n = lastGraphModel?.nodes.find((x) => x.id === id);
      if (n) void doExpand({ id: n.id, label: n.label, kind: n.kind });
    },
    removeNode: (target) => void removeNodeByTarget(target),
    startInvestigation: (objective) => {
      void startInvestigation(objective, chatWire ? { fetchImpl: chatWire.runFetch, toolOpts: chatWire.toolOpts } : {});
    },
    hasGraph: () => !!cyGraph && (lastGraphModel?.nodes.length ?? 0) > 0,
    setSpineFocus: (on) => { graphFocusThreats = on; cyGraph?.setSpineFocus(on); }, // G2a test seam
    offSpineCount: () => cyGraph?.offSpineCount() ?? 0, // G2a test seam
  };
}

// app.ts owns #stopBtn visibility across the WHOLE run lifecycle (the chat just wires its click),
// so Stop is reachable even for a run started outside the chat (the __kipi scripted-run hook).
function setStopVisible(on: boolean) {
  const b = document.getElementById("stopBtn");
  if (b) (b as HTMLButtonElement).hidden = !on;
}

// rel-bug: the "Report a bug" link lives in the static sidebar footer (index.html, beside Contact /
// Support), present on every screen incl. the login gate. Its static href is a plain mailto fallback
// that works before JS; here we UPGRADE it to the templated mailto from the no-arg buildBugReportUrl
// (structured What-happened / expected / repro prompt). It's a navigation the user's mail client opens
// — nothing is sent programmatically and no case data is interpolated (see feedback.ts rel-bug). The
// title carries the zero-data disclosure on hover.
function wireBugReportLink(): void {
  const a = document.getElementById("bug-report-link") as HTMLAnchorElement | null;
  if (!a) return;
  a.href = buildBugReportUrl();
  a.title = BUG_DISCLOSURE;
}

// rsn-run-chip: an off-Workspace "run in progress" chip with a reachable Stop. The in-dock #stopBtn only
// exists on the Workspace home; on the config pages (/enrich, /account) the dock is torn down, so a run that
// SURVIVES navigation (rsn-reattach) would otherwise be invisible AND uncontrollable — "no silent failure"
// (a PRD goal). The chip lives OUTSIDE root() (appended to <body> once) so render()'s teardown never removes
// it, and its Stop mirrors the dock Stop (activeAbort.abort()). Shown iff a run is live AND we're off home.
function ensureRunChip(): HTMLElement {
  const existing = document.getElementById("run-chip");
  if (existing) return existing;
  const chip = el(`<div id="run-chip" class="run-chip" hidden role="status" aria-live="polite">
    <span class="run-chip-dot" aria-hidden="true"></span>
    <span class="run-chip-label">Investigator running…</span>
    <button id="run-chip-stop" type="button" class="run-chip-stop">Stop</button>
  </div>`);
  chip.querySelector("#run-chip-stop")!.addEventListener("click", () => {
    activeAbort?.abort(); // same control as the dock Stop — abort the live run's AbortController
    updateRunChip(); // hide immediately (the finally also flips the store status to aborted)
  });
  document.body.appendChild(chip);
  return chip;
}
// G1 (video-review 2026-06-25): the run-progress ENVELOPE clock. app.ts owns the wall-clock (run-store
// stays DOM/Date-free); a 1s tick re-labels the chip so "elapsed" advances even between streamed steps.
let runStartedAt = 0;
let runChipTimer: number | null = null;
// While a terminal "✓ Done" / "■ Stopped" flash is showing, hold the chip visible for a few seconds so the
// END is SEEN (the founder: "did it end? I have no idea" — the chip used to vanish silently). A route change
// or finally-hide during this window is suppressed.
let runChipFlashUntil = 0;
let runChipFlashTimer: number | null = null;

function startRunClock(): void {
  runStartedAt = Date.now();
  if (runChipTimer == null) runChipTimer = window.setInterval(() => updateRunChip(), 1000);
}
function stopRunClock(): void {
  if (runChipTimer != null) { clearInterval(runChipTimer); runChipTimer = null; }
}

function updateRunChip(): void {
  const chip = ensureRunChip();
  const label = chip.querySelector(".run-chip-label") as HTMLElement | null;
  const stopBtn = chip.querySelector("#run-chip-stop") as HTMLElement | null;
  // ch-prominent-stop (controls-honesty): the chip shows on EVERY route while a run is live — the ONE
  // unmistakable, always-reachable Stop (pulsing pill, bottom-CENTER, clears the sidebar/.cy-stats/chat bar/
  // toolbar). The in-dock #stopBtn stays as the secondary control; both reuse activeAbort.abort().
  // G1: the label is now LIVE — objective · step N · elapsed — answering "where is it?" at a glance.
  if (isRunActive()) {
    chip.hidden = false;
    chip.classList.remove("run-chip-done", "run-chip-stopped");
    if (stopBtn) stopBtn.hidden = false;
    if (label) label.textContent = formatRunProgress(getRunStore().objective, getRunStore().steps.length, Date.now() - runStartedAt);
    return;
  }
  // Not running: hold a terminal flash if one is active (answers "did it end?"), else hide + stop the clock.
  if (Date.now() < runChipFlashUntil) return;
  chip.hidden = true;
  chip.classList.remove("run-chip-done", "run-chip-stopped");
  stopRunClock();
}

// G1: flash a clear terminal state on the chip for ~5s, then hide — so the END of a run is SEEN, not a
// silent disappearance. `stopped` picks the grey "■ Run stopped" styling over the green "✓ Done".
function flashRunChipDone(text: string, stopped: boolean): void {
  const chip = ensureRunChip();
  const label = chip.querySelector(".run-chip-label") as HTMLElement | null;
  const stopBtn = chip.querySelector("#run-chip-stop") as HTMLElement | null;
  if (label) label.textContent = text;
  if (stopBtn) stopBtn.hidden = true; // nothing to stop once it's terminal
  chip.classList.toggle("run-chip-done", !stopped);
  chip.classList.toggle("run-chip-stopped", stopped);
  chip.hidden = false;
  stopRunClock();
  // Cancel any prior flash timer before arming a new one — a stale timeout from a previous run/case could
  // otherwise fire mid-window and clear THIS flash early (codex adversarial, kweb-run-chip-control-contract).
  if (runChipFlashTimer != null) clearTimeout(runChipFlashTimer);
  runChipFlashUntil = Date.now() + 5000;
  runChipFlashTimer = window.setTimeout(() => { runChipFlashUntil = 0; runChipFlashTimer = null; updateRunChip(); }, 5000);
}

// The brief affordances (#briefBtn/#dlBriefBtn) live in a row hidden until there IS a brief —
// revealed whenever #brief is written (a chat run, a generate-brief, or a history reopen), so the
// download button is reachable (history proof) and not dangling on an empty chat.
function revealBriefRow() {
  const r = document.getElementById("brief-row");
  if (r) (r as HTMLElement).hidden = false;
}


// ob-keyprompt: toggle the "we need your key now" highlight on the key card. The card lives on the
// /account page (ac-ui); a keyless run routes there first (see the catch in runInvestigation +
// pendingKeyFocus), so setKeyNeeded runs once the card is mounted — never a no-op on a stale home.
function setKeyNeeded(on: boolean): void {
  const card = document.getElementById("keycard");
  if (card) card.classList.toggle("key-needed", on);
}

function renderKeysCard(): HTMLElement {
  const kv = keyVault(); // global key — works before the first case exists (auth-gate-nav)
  const configured = !!kv && hasApiKey(kv);
  const card = el(`
    <section class="card" id="keycard">
      <h2>Anthropic key</h2>
      <p class="muted">Your key stays in this encrypted vault and is only sent to api.anthropic.com.</p>
      <input id="apikey" type="password" placeholder="${configured ? "key configured — paste to replace" : "sk-ant-..."}" autocomplete="off" />
      <button id="saveKeyBtn">Save key</button>
      <span id="keychip" class="${configured ? "chip-ok" : "chip-warn"}">${configured ? "configured" : "add a key to investigate"}</span>
    </section>`);
  card.querySelector("#saveKeyBtn")!.addEventListener("click", async () => {
    const input = card.querySelector("#apikey") as HTMLInputElement;
    try {
      const kv2 = keyVault();
      if (kv2) await setApiKey(kv2, input.value);
      input.value = "";
      const chip = card.querySelector("#keychip")!;
      chip.textContent = "configured";
      chip.className = "chip-ok";
      card.classList.remove("key-needed"); // ob-keyprompt: the deferred-key moment is resolved
      setStatus("Anthropic key saved to your vault.");
    } catch (e) {
      setStatus(msg(e), "err");
    }
  });
  return card;
}


const BRIEF_CAP = 256 * 1024; // bound the render/download so a malformed/huge value can't wedge the UI

function renderHistoryCard(): HTMLElement {
  const card = el(`<section class="card"><h2>History</h2><div id="history"></div></section>`);
  refreshHistory(card.querySelector("#history") as HTMLElement);
  return card;
}

// rel-feedback: the user-authored feedback control. An anchor (target=_blank rel=noopener) to a
// pre-filled GitHub issue the user reviews + submits themselves — NOT a fetch, so github.com is never
// a connect-src origin and nothing is sent programmatically. The disclosure states plainly that only
// typed text leaves the browser. The href is built by the no-arg buildFeedbackUrl (no case data).
function renderFeedbackRow(): HTMLElement {
  const row = el(`
    <section class="card feedback-card">
      <a id="feedbackLink" class="feedback-link" target="_blank" rel="noopener">Send feedback</a>
      <span class="muted feedback-note"></span>
    </section>`);
  (row.querySelector("#feedbackLink") as HTMLAnchorElement).href = buildFeedbackUrl();
  (row.querySelector(".feedback-note") as HTMLElement).textContent = FEEDBACK_DISCLOSURE;
  return row;
}

// Repopulate the #history box from the vault (called after a run/brief completes too).
function refreshHistory(box?: HTMLElement | null) {
  const target = box ?? document.getElementById("history");
  if (!target || !vault) return;
  const runs = listRuns(vault);
  const briefs = listBriefs(vault);
  if (!runs.length && !briefs.length) {
    target.innerHTML = `<p class="muted">No past investigations yet.</p>`;
    return;
  }
  target.innerHTML =
    `<h3>Runs (${runs.length})</h3>` +
    runs
      .map(
        (r) =>
          `<div class="histrun">${escapeHtml(r.objective)} <span class="muted">— ${r.promoted} promoted, ${r.leads} leads (${escapeHtml(r.stopReason === "end_turn" ? "complete" : r.stopReason)})</span></div>`,
      )
      .join("") +
    `<h3>Briefs (${briefs.length})</h3>`;
  const list = el(`<div></div>`);
  for (const obj of briefs) {
    const row = el(`<div class="histbrief"><button class="link"></button></div>`);
    const btn = row.querySelector("button")!;
    btn.textContent = obj; // textContent: never interpret an objective as HTML
    btn.addEventListener("click", () => viewBrief(obj));
    list.appendChild(row);
  }
  target.appendChild(list);
}

function viewBrief(objective: string) {
  if (!vault) return;
  const briefEl = document.getElementById("brief");
  if (!briefEl) {
    // hist-reopen (kf-fix): History lives on /account but #brief is the home dock (dock.ts). When a brief
    // is reopened from History, route home and show it once the dock exists (renderSplitView consumes
    // pendingBriefObjective) — never `getElementById("brief")!` on /account, which would throw on null.
    pendingBriefObjective = objective;
    navigate("/");
    return;
  }
  const md = getBrief(vault, objective); // already redacted + type-guarded
  briefEl.textContent = (md ?? "(brief unavailable)").slice(0, BRIEF_CAP);
  revealBriefRow();
}

function onDownloadBrief() {
  const text = document.getElementById("brief")!.textContent ?? "";
  if (!text.trim()) {
    setStatus("No brief to download yet.", "err");
    return;
  }
  download("brief.md", new TextEncoder().encode(text.slice(0, BRIEF_CAP)));
  setStatus("Brief downloaded.");
}

// chat-dock-readable: STICKY-BOTTOM auto-follow. The single #chat-scroll follows streamed steps. rAF so the
// measured scrollHeight includes the just-appended node. (remove-chat-findings 2026-07-08: the only reader
// of a pre-append isChatAtBottom() check was renderFindings, now gone — the helper went with it.)
const CHAT_FOLLOW_SLACK = 80; // px: "near bottom" tolerance (still used by the scroll follower below)
function scrollChatToBottom(): void {
  const s = document.getElementById("chat-scroll");
  if (s) requestAnimationFrame(() => { s.scrollTop = s.scrollHeight; });
}

runEvents.subscribe((ev) => {
  if (ev.type === "run_started") {
    runEventMeta.set(ev.runId, { objective: ev.objective, mode: ev.mode });
    beginRun(ev.mode === "case" ? "the whole case" : ev.objective);
    // holistic-fix P1: put this run's live log block at the CURRENT bottom of the conversation, so a
    // question asked after the run renders BELOW its logs (chronological), not above them.
    window.__kipiChat?.relocateRunBlockToBottom();
    startRunClock();
    updateRunChip();
    return;
  }

  if (ev.type === "agent_step") {
    recordRunStep(ev.step);
    scheduleLiveRunPersist(); // reload-survival: a step alone (no graph observation) must still journal the trail
    updateRunChip();
    const live = document.getElementById("trail");
    if (!live) return;
    // scope-scroll-fix (founder 2026-07-07): follow the LOG's OWN bottom — #trail is a bounded, self-
    // scrolling box now (.livetrail max-height+overflow). Pin-aware: a manual scroll-up INSIDE the log is
    // not yanked. Because the log's outer height is fixed, a new step never reflows the conversation above
    // it (the "log keeps growing and pulls the chat down" bug). The outer #chat-scroll is NOT touched here.
    const trailPinned = live.scrollHeight - live.scrollTop - live.clientHeight <= CHAT_FOLLOW_SLACK;
    live.appendChild(stepRow(ev.step));
    if (trailPinned) requestAnimationFrame(() => { live.scrollTop = live.scrollHeight; });
    return;
  }

  if (ev.type === "agent_text_delta") {
    // chat-feels-like-a-product: the model's tokens (key-redacted upstream) type into ONE live bubble
    // so the reply composes in real time. Previously published and DROPPED (no consumer) — the answer
    // popped in whole. streamEnd (on finalize/abort) clears it; the curated briefing is the durable turn.
    window.__kipiChat?.streamDelta(ev.text);
    return;
  }

  if (ev.type === "agent_observed") {
    const meta = runEventMeta.get(ev.runId);
    liveGrowObserved(ev.observed, meta?.mode === "case" ? "" : meta?.objective ?? "");
    return;
  }

  if (ev.type === "run_finalized") {
    window.__kipiChat?.streamEnd(); // clear the live typing bubble — the curated briefing takes over
    recordRunFindings(ev.promoted, ev.leads);
    // hydra ISSUE-1/5: a CLEAN finalize wrote the durable run: record — the journal is now superseded, so drop
    // it (else hydrate would prefer the stale journal over the richer finalized fold). An aborted-via-finalize
    // keeps its journal as the durable record. Cancel any pending throttle write first so it can't re-create it.
    if (ev.stopReason !== "aborted" && vault) {
      cancelLiveRunPersist();
      void clearLiveRun(vault).catch(() => {});
      // reload-survival: clearLiveRun drops the GRAPH journal (the run: record re-folds it on load), but the step
      // trail has no such re-fold — journal the COMPLETE finished trail so #trail survives a reload (overwritten
      // when the next run streams). getRunStore().steps holds every recorded step by finalize.
      void persistLiveRunSteps(vault, getRunStore().steps).catch(() => {});
    }
    setRunStatus(ev.stopReason === "aborted" ? "aborted" : "done");
    flashRunChipDone(formatRunDone(getRunStore().status, ev.promoted.length, ev.leads.length, ev.stopReason), ev.stopReason === "aborted");
    // remove-chat-findings (founder 2026-07-08): no in-chat chip render. recordRunFindings (above) still holds
    // the promoted findings + leads in the run store — the graph + the /runs Run-trail page project them.
    const result = {
      steps: [],
      promoted: ev.promoted,
      leads: ev.leads,
      relationships: ev.relationships,
      usage: ev.usage,
      stopReason: ev.stopReason,
      worked: ev.worked,
      degradedReason: ev.degradedReason,
    } as InvestigateResult;
    renderRunGraph(ev.objectiveKey, result);
    refreshHistory();
    return;
  }

  if (ev.type === "run_aborted" || ev.type === "run_error") {
    window.__kipiChat?.streamEnd(); // clear any half-typed live bubble on abort/error
    // hydra ISSUE-1: a HARD abort/error SKIPS finalize (no run: record). Flush the journal NOW so the in-flight
    // graph is the durable record — this is exactly the founder's "Done (aborted), but it had found entities"
    // case. Keep it (do NOT clear): hydrate reads it back so the discovered graph survives.
    void flushLiveRunPersist();
    setRunStatus("aborted");
    flashRunChipDone(formatRunDone("aborted", 0, 0, ev.type === "run_error" ? "error" : "aborted"), true);
  }
});

/**
 * Run an investigation and render the live trail. Fenced by a per-run id so a stale
 * or aborted run can never write into a newer run's trail (codex finding-5).
 */
async function startInvestigation(
  objective: string,
  runOpts: { fetchImpl?: FetchLike; toolOpts?: { fetchImpl?: FetchLike; retries?: number } } = {},
): Promise<InvestigateResult | null> {
  if (!vault) return null;
  const myRun = ++runSeq;
  const eventRunId = `ui-${myRun}`;
  activeAbort?.abort();
  const ctrl = new AbortController();
  activeAbort = ctrl;

  const trail = document.getElementById("trail")!;
  trail.innerHTML = "";
  // Reset the graph CHROME only (drawer / menu / stats). gh-hydrate: the graph itself PERSISTS
  // across a run — renderRunGraph GROWS the new run's findings into the accumulated case graph
  // (D5), so lastGraphModel + the expand set are NOT cleared here (clearing them would re-pop the
  // graph and lose the whole-case picture). graphGen++ still invalidates any in-flight expand so a
  // stale one cannot merge into the graph the new run is about to grow (codex-2). The full mount
  // reset lives in hydrateCaseGraph (D4); the cytoscape instance is reused, never torn down here.
  clearGraphChrome();
  graphGen++;
  setKeyNeeded(false); // ob-keyprompt: clear any stale "need a key" highlight before this attempt
  setStatus(`Investigating: ${objective}...`);
  lastInvestigateError = null; // clu-error-output: clear any stale cause before this attempt
  setStopVisible(true); // cd-ui: Stop is reachable for the whole run, regardless of who started it
  runEvents.start({ runId: eventRunId, caseId: rawVault ? activeCaseId(rawVault) : "", mode: "objective", objective });

  const onStep = (s: Step) => {
    if (myRun !== runSeq) return; // a newer run superseded this one
    runEvents.publish({ type: "agent_step", runId: eventRunId, step: s });
  };
  const onObserved = (ev: ObservedEvent) => {
    if (myRun !== runSeq) return; // a superseded run must not grow the live graph (D4 fence)
    runEvents.publish({ type: "agent_observed", runId: eventRunId, observed: ev });
  };
  const onTextDelta = (text: string) => {
    if (myRun !== runSeq) return; // streamed text from a superseded run must not enter the live bus
    runEvents.publish({ type: "agent_text_delta", runId: eventRunId, text });
  };
  // kweb-live-graph: snapshot what was on the graph BEFORE this run, so the end-of-run prune drops only the
  // live observations THIS run added that the gate didn't keep (never a pre-existing node).
  liveGrowAdds = 0; // kweb-live-graph: reset the live-grow counter for this run

  try {
    const result = await runInvestigation({
      vault,
      objective,
      onStep,
      onObserved,
      onTextDelta,
      signal: ctrl.signal,
      fetchImpl: runOpts.fetchImpl,
      toolOpts: runOpts.toolOpts,
    });
    if (myRun !== runSeq) return result; // do not render a stale run's findings
    if (result.stopReason === "aborted") {
      runEvents.publish({ type: "run_aborted", runId: eventRunId, reason: "stop" });
    } else {
      runEvents.publish({
        type: "run_finalized",
        runId: eventRunId,
        stopReason: result.stopReason,
        promoted: result.promoted,
        leads: result.leads,
        relationships: result.relationships,
        usage: result.usage,
        worked: result.worked,
        degradedReason: result.degradedReason,
        objectiveKey: objective,
      });
    }
    setStatus(`Done (${result.stopReason}). ${result.promoted.length} promoted, ${result.leads.length} leads.`);
    return result;
  } catch (e) {
    if (myRun === runSeq) {
      // clu-error-output: map the REAL cause (401 vs no-key vs network vs abort) — no swallowing into a
      // misleading "no key / setup strip" message. The dock reads lastInvestigateError to show it.
      const mapped = mapRunError(e);
      lastInvestigateError = isAbortError(e) ? null : mapped;
      if (isAbortError(e)) runEvents.publish({ type: "run_aborted", runId: eventRunId, reason: "stop" });
      else runEvents.publish({ type: "run_error", runId: eventRunId, message: mapped.message });
      setStatus(mapped.message, "err");
      // A key problem routes to /account (where the key card now lives, ac-ui); keep the focus behaviour
      // for the keyless case (renderAccountView consumes pendingKeyFocus).
      if (mapped.route === "/account") {
        if (vault && !hasApiKey(vault)) pendingKeyFocus = true;
        navigate("/account");
      }
    }
    return null;
  } finally {
    if (activeAbort === ctrl) activeAbort = null;
    if (myRun === runSeq) setStopVisible(false); // only the CURRENT run hides Stop (a superseded run keeps it shown)
    // rsn-run-store: a run that ended without finalizing (abort / error / navigated-away) is terminal-aborted.
    // Guarded by myRun===runSeq so a superseded run never overwrites the NEW run's store (which beginRun reset).
    if (myRun === runSeq && getRunStore().status === "running") setRunStatus("aborted");
    if (myRun === runSeq) updateRunChip(); // rsn-run-chip: a run ending off-Workspace must hide its chip
  }
}

// A3: the whole-case run — same lifecycle as startInvestigation (abort wiring, live trail, grow the case
// graph, render findings) but driven by investigateCase over the WHOLE roster. Returns the result incl.
// recommendedPivots so the dock can surface the analyst's next moves.
async function startCaseInvestigation(
  runOpts: { fetchImpl?: FetchLike; toolOpts?: { fetchImpl?: FetchLike; retries?: number } } = {},
): Promise<InvestigateCaseResult | null> {
  if (!vault) return null;
  const myRun = ++runSeq;
  const eventRunId = `ui-${myRun}`;
  activeAbort?.abort();
  const ctrl = new AbortController();
  activeAbort = ctrl;

  const trail = document.getElementById("trail")!;
  trail.innerHTML = "";
  clearGraphChrome(); // graph PERSISTS + grows (same as startInvestigation); only the chrome resets
  graphGen++;
  setKeyNeeded(false);
  setStatus("Investigating the whole case...");
  lastInvestigateError = null;
  setStopVisible(true);
  runEvents.start({ runId: eventRunId, caseId: rawVault ? activeCaseId(rawVault) : "", mode: "case", objective: "the whole case" });

  const onStep = (s: Step) => {
    if (myRun !== runSeq) return;
    runEvents.publish({ type: "agent_step", runId: eventRunId, step: s });
  };
  const onObserved = (ev: ObservedEvent) => {
    if (myRun !== runSeq) return; // a superseded run must not grow the live graph (D4 fence)
    runEvents.publish({ type: "agent_observed", runId: eventRunId, observed: ev });
  };
  const onTextDelta = (text: string) => {
    if (myRun !== runSeq) return;
    runEvents.publish({ type: "agent_text_delta", runId: eventRunId, text });
  };
  liveGrowAdds = 0; // kweb-live-graph: reset the live-grow counter for this run

  try {
    const result = await investigateCase({
      vault,
      onStep,
      onObserved,
      onTextDelta,
      signal: ctrl.signal,
      fetchImpl: runOpts.fetchImpl,
      toolOpts: runOpts.toolOpts,
    });
    if (myRun !== runSeq) return result; // a newer run superseded this one
    if (result.stopReason === "aborted") {
      runEvents.publish({ type: "run_aborted", runId: eventRunId, reason: "stop" });
    } else {
      runEvents.publish({
        type: "run_finalized",
        runId: eventRunId,
        stopReason: result.stopReason,
        promoted: result.promoted,
        leads: result.leads,
        relationships: result.relationships,
        usage: result.usage,
        worked: result.worked,
        degradedReason: result.degradedReason,
        objectiveKey: result.objective,
      });
    }
    setStatus(`Done (${result.stopReason}). ${result.promoted.length} promoted, ${result.leads.length} leads; ${result.recommendedPivots.length} still to investigate.`);
    return result;
  } catch (e) {
    if (myRun === runSeq) {
      const mapped = mapRunError(e);
      lastInvestigateError = isAbortError(e) ? null : mapped;
      if (isAbortError(e)) runEvents.publish({ type: "run_aborted", runId: eventRunId, reason: "stop" });
      else runEvents.publish({ type: "run_error", runId: eventRunId, message: mapped.message });
      setStatus(mapped.message, "err");
      if (mapped.route === "/account") {
        if (vault && !hasApiKey(vault)) pendingKeyFocus = true;
        navigate("/account");
      }
    }
    return null;
  } finally {
    if (activeAbort === ctrl) activeAbort = null;
    if (myRun === runSeq) setStopVisible(false);
    // rsn-run-store: an unfinalized run (abort / error / navigated-away) is terminal-aborted; myRun===runSeq
    // guards against a superseded run clobbering the NEW run's store (which beginRun already reset).
    if (myRun === runSeq && getRunStore().status === "running") setRunStatus("aborted");
    if (myRun === runSeq) updateRunChip(); // rsn-run-chip: a run ending off-Workspace must hide its chip
  }
}

async function startBrief(objective: string, fetchImpl?: FetchLike): Promise<string | null> {
  if (!vault) return null;
  const box = document.getElementById("brief")!;
  // The brief is NOT gated (founder: auto-created, no blocking). Challenge stays a soft conductor suggestion.
  box.textContent = "Generating brief...";
  try {
    const brief = await generateBrief(vault, objective, { fetchImpl });
    box.textContent = brief.slice(0, BRIEF_CAP); // <pre> preserves the markdown; rendered safely as text
    revealBriefRow();
    refreshHistory();
    setStatus("Brief generated and saved to your vault.");
    return brief;
  } catch (e) {
    box.textContent = "";
    setStatus(msg(e), "err");
    return null;
  }
}

function stepRow(s: Step): HTMLElement {
  if (s.kind === "tool") {
    // ct-trail (parity): the dock trail used to show only "🔧 toolname ok", dropping the tool
    // input + result the original streams (tool->input->result). Reuse displayTrail() — the SAME
    // safe, capped, allowlisted formatter the /runs trail uses — so the dock matches the original.
    const [d] = displayTrail([s]);
    const input = d.inputText ? ` <span class="trail-input">${escapeHtml(d.inputText)}</span>` : "";
    const status = s.isError ? `<span class="err">error</span>` : `<span class="ok">ok</span>`;
    const result = d.resultText ? `<div class="trail-result">→ ${escapeHtml(d.resultText)}</div>` : "";
    return el(`<div class="step tool">🔧 ${escapeHtml(s.tool ?? "")}${input} ${status}${result}</div>`);
  }
  return el(`<div class="step reason">${escapeHtml((s.text ?? "").slice(0, 400))}</div>`);
}

// rsn-reattach: on RETURN to the Workspace, replay the run store into the freshly-mounted dock. A run that
// streamed while the Workspace was torn down (/enrich, /account) or re-mounted (a detail route, ccc-hybrid-
// routes) lost its #trail DOM, but the store kept the trail/findings (rsn-run-store). This repaints them and
// restores Stop for a still-live run; onStep re-resolves #trail so streaming continues into this fresh DOM.
// renderSplitView is the SINGLE Workspace-mount path, so both teardown paths converge through this one call.
function reattachRunIntoDock(): void {
  const store = getRunStore();
  if (store.status === "idle") {
    // reload-survival (founder 2026-07-08): a reload wipes the in-memory store, but the step journal may still
    // hold the last run's trail. Replay it into #trail so the log survives a refresh. isRunActive() is false
    // here, so the dock's stream-observer leaves it COLLAPSED behind the pill (never force-expanded — that is
    // reserved for a genuinely LIVE run). A fresh case / never-ran reads back [] and paints nothing.
    const trail = document.getElementById("trail");
    if (trail && vault) {
      const journaled = readLiveRunSteps(vault);
      if (journaled.length) {
        trail.replaceChildren();
        for (const s of journaled) trail.appendChild(stepRow(s));
      }
    }
    return;
  }
  const trail = document.getElementById("trail");
  if (trail) {
    trail.replaceChildren(); // the fresh dock's #trail is empty — paint the WHOLE store, in order
    for (const s of store.steps) trail.appendChild(stepRow(s));
  }
  // remove-chat-findings (2026-07-08): no #findings/#leads to repaint — the store's findings/leads live on
  // the graph + /runs, not in the chat. Only the #trail log is replayed into the fresh dock (above).
  setStopVisible(store.status === "running"); // a still-live run keeps Stop reachable on return
  scrollChatToBottom();
}

// ---- Cytoscape graph surface (clone of graph.html) + the right slide-in node drawer ----

// The currently-selected node's (key-redacted) data — re-rendered into the drawer after an
// expand so it reflects "Expanded". The CyNodeData comes from the cytoscape element, which the
// adapter built from the already-redacted model, so it never carries the key.
let selectedNodeData: CyNodeData | null = null;

/** Lazily build the CyGraph on the stable #cy element, wiring its callbacks to the drawer /
 *  selection chip / context menu / stats. The graph surface is always VISIBLE (D1) and the pane
 *  is sized (flex-1, explicit min-height), so #cy has real dimensions when cytoscape measures it
 *  (a 0×0 container renders a blank canvas). */
function ensureCyGraph(): CyGraph | null {
  const cyEl = document.getElementById("cy");
  if (!cyEl) return null;
  if (cyGraph) {
    cyGraph.resize();
    return cyGraph;
  }
  cyGraph = new CyGraph(cyEl, {
    onSelectNode: (d) => { selectedNodeData = d; }, // remove-cards: node click SELECTS (deictic target + highlight); detail is pulled via the right-click menu → chat
    onBackground: () => { selectedNodeData = null; clearDrawer(); closeMenu(); },
    onSetChange: renderSetChip,
    onMenu: renderMenu,
    onStats: (s) => { renderStats(s); refreshFacetControls(); }, // A4: facets reflect the live graph after render/grow
  });
  buildControls();
  return cyGraph;
}

/** Render this run's findings into the graph. On the FIRST paint (no accumulated case graph yet) a
 *  FULL render lays out + fits. Once the case graph exists, the run GROWS into it IN PLACE
 *  (growCaseGraph = redact + gate-faithful mergeGraphModel, then cyGraph.grow — NO re-pop, D5) so a
 *  new in-session run keeps the whole-case picture and existing node positions survive. The grow
 *  folds the IN-MEMORY result (not a vault re-read), so a best-effort persist failure never drops the
 *  just-finished run (D6). lastGraphModel stays the accumulated case so one-hop expand grows from it. */
// kweb-live-graph: map a tool to the typed edge it establishes between the target and what it found.
function relForLiveTool(tool: string): string {
  const t = tool.toLowerCase();
  if (t.includes("reverse")) return "hosts";
  if (t.includes("dns")) return "resolves_to";
  if (t.includes("rdap") || t.includes("whois")) return "registered_via";
  if (t.includes("crt") || t.includes("cert")) return "cert_for";
  if (t.includes("subdomain")) return "subdomain_of";
  return "linked";
}

// kweb-live-graph: best-effort entity type for the queried TARGET (the loop sends its value, not its type).
function liveTargetType(v: string): string {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
  if (/^@/.test(v) || /t\.me\//i.test(v)) return "handle";
  if (/^https?:\/\//i.test(v)) return "url";
  return "domain";
}

// kweb-live-graph (founder 2026-06-24): fold ONE tool's observed entities into the REAL case graph AS THE
// DIG HAPPENS, so nodes appear the moment they're found instead of only at the end. Reuses growCaseNetwork
// — the SAME projection the end-of-run fold uses — so a live LEAD node UPGRADES IN PLACE (same id, same
// position, no pop) when the gated result folds at completion. Admissible-only (the one isAdmissible gate
// — executable code in the model projection, not prose) so obvious junk never reaches the canvas. Un-corroborated
// observations stay as dimmed leads ("grow all, prune at end": survivors promote, the rest stay leads).
function liveGrowObserved(ev: ObservedEvent, objective: string): void {
  if (!vault) return;
  const g = ensureCyGraph();
  if (!g) return;
  // worthiness (PRD live-graph-quality, finding-1): drop non-admissible + self echoes, then collapse a
  // value emitted under multiple incompatible types in THIS observation to one node (precedence-typed) so
  // tooling-noise twins (an A-record IP echoed as nameserver/mailserver) never reach the graph.
  const admissible = ev.entities.filter((e) => !e.self && isAdmissible(e.type, e.value)[0]);
  const fresh = collapseObservedTwins(admissible);
  if (!fresh.length) return;
  const base: GraphModel | null = lastGraphModel ?? graphModelForCase(vault);
  const target = ev.target.trim();
  // a lead-shaped finding for each entity; the target is itself a lead so the edge has an anchor even when
  // the target is brand-new to the graph. Cast loosely — growCaseNetwork re-runs isAdmissible + the gate.
  const lead = (entity: string, entity_type: string) => ({
    finding: { entity, entity_type, confidence: "low" },
    verdict: { promote: false, grade: "D", reason: "live observation — not yet corroborated" },
  });
  const leads = fresh.map((e) => lead(e.value, e.type));
  if (target) leads.unshift(lead(target, liveTargetType(target)));
  const relationships = target
    ? fresh.map((e) => ({ src: target, dst: e.value, relType: relForLiveTool(ev.tool), confidence: "low" }))
    : [];
  const partial = { promoted: [], leads, relationships, steps: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", worked: true } as unknown as InvestigateResult;
  // Mirror renderRunGraph EXACTLY so the live build and the end fold are coherent: first paint via the
  // run-network builder (sets the redacted objective + lays out), then grow IN PLACE for every later
  // observation (positions + viewport untouched). Without the first-paint branch a fresh run's model lost
  // its redacted objective and never laid out.
  if (!base) {
    const model = graphModelForRunNetwork(vault, objective, partial);
    lastGraphModel = model;
    g.render(model);
  } else {
    const grown = growCaseNetwork(vault, base, partial, "osint");
    lastGraphModel = grown;
    g.grow(grown, base.nodes[0]?.id ?? "");
  }
  liveGrowAdds++;
  const empty = document.getElementById("cy-empty");
  if (empty) empty.hidden = (lastGraphModel?.nodes ?? []).some((n) => n.kind !== "objective");
  scheduleLiveRunPersist(); // hydra ISSUE-1/5: journal the just-grown model so an abort/reload rehydrates it
}

// hydra ISSUE-1 + ISSUE-5 (founder 2026-07-07): journal the live graph durably so the graph survives an abort
// or a reload before finalize. liveGrowObserved fires per tool observation and vault.put reseals the whole doc,
// so the write is THROTTLED (trailing debounce) — bursts of observations coalesce into ~1 durable write/sec;
// the terminal handlers flush the final state. A clean finalize clears the journal (the run: record supersedes).
const LIVE_RUN_PERSIST_MS = 1000;
let liveRunPersistTimer: ReturnType<typeof setTimeout> | null = null;
let liveRunPersistPending = false;

function scheduleLiveRunPersist(): void {
  if (!vault || !lastGraphModel) return;
  liveRunPersistPending = true;
  if (liveRunPersistTimer) return; // a write is already scheduled — this observation folds into it
  liveRunPersistTimer = setTimeout(() => {
    liveRunPersistTimer = null;
    void flushLiveRunPersist();
  }, LIVE_RUN_PERSIST_MS);
}

/** Write the current live model NOW (best-effort). Called by the throttle timer and flushed on run terminal. */
async function flushLiveRunPersist(): Promise<void> {
  if (!vault || !lastGraphModel || !liveRunPersistPending) return;
  liveRunPersistPending = false;
  try {
    await persistLiveRun(vault, lastGraphModel);
    // reload-survival: journal the step trail on the SAME write, so #trail replays after a reload as well as
    // the graph does (same durability guarantee — both ride this single throttled/flushed writer).
    await persistLiveRunSteps(vault, getRunStore().steps);
  } catch {
    /* best-effort durability; a locked vault mid-run must not crash the run */
  }
}

/** Cancel any pending journal write (used before a clean-finalize clear so a late timer can't re-write it). */
function cancelLiveRunPersist(): void {
  if (liveRunPersistTimer) {
    clearTimeout(liveRunPersistTimer);
    liveRunPersistTimer = null;
  }
  liveRunPersistPending = false;
}

function renderRunGraph(objective: string, result: InvestigateResult) {
  if (!vault) return;
  const g = ensureCyGraph();
  const base = lastGraphModel;
  if (!base) {
    // sp-77a52e2c: first paint is NETWORK-only (no objective hub), matching the 2nd-run grow + the
    // remount — the old graphModelForRun injected a transient hub that only vanished on reload. Key
    // redacted in the session layer; first paint = layout + fit.
    const model = graphModelForRunNetwork(vault, objective, result);
    lastGraphModel = model;
    if (g) g.render(model);
  } else {
    // cg-network (PRD prd-case-graph): the accumulated case graph is an entity↔entity web with no
    // objective hub, so base.nodes[0] is now an arbitrary ENTITY — never a valid spoke anchor. Fold
    // the run as a co-occurrence clique (growCaseNetwork) instead. The grow's fromId is placement-
    // only (cyGraph.anchorFor falls back to a connected neighbor), so passing an existing node id is
    // fine for layout; topology comes from the model's edges, never from this id.
    const grown = growCaseNetwork(vault, base, result);
    lastGraphModel = grown;
    if (g) g.grow(grown, base.nodes[0]?.id ?? ""); // grow in place: existing positions + viewport untouched (D5)
  }
  // D10: the hint shows iff there are no finding/lead nodes (an objective-only graph still hints).
  const empty = document.getElementById("cy-empty");
  if (empty) empty.hidden = lastGraphModel?.nodes.some((n) => n.kind !== "objective") ?? false; // clu-graph-topology
}

/**
 * Expand a node one hop and GROW the graph in place (no re-pop, D1). Fenced by graphGen (a
 * stale expand, or one whose parent vanished after a new run, is discarded — codex-2); a node
 * is dug at most once and never while in flight (codex-9). expandOpts injects the scripted
 * seam in the DOM proof; omitted = a live agent run on the user's key.
 */
async function doExpand(target: { id: string; label: string; kind: string }, expandOpts?: { fetchImpl?: FetchLike; toolOpts?: { fetchImpl?: FetchLike; retries?: number } }): Promise<boolean> {
  if (!vault || !lastGraphModel) return false;
  if (target.kind === "objective") return false; // the seed is not a dig target
  if (expandedNodeIds.has(target.id) || inFlightNodeIds.has(target.id)) return false;

  const gen = graphGen;
  inFlightNodeIds.add(target.id);
  try {
    const merged = await expandFromNode(vault, target.label, lastGraphModel, target.id, expandOpts);
    if (gen !== graphGen) return false; // superseded by a newer top-level run
    if (!lastGraphModel.nodes.some((n) => n.id === target.id)) return false; // parent gone
    // clu-error-output: surface the outcome — a dig is never a silent no-op. "grew" compares the merged
    // model to the pre-expand one (computed BEFORE the reassignment below).
    const grew = merged.nodes.length > lastGraphModel.nodes.length || merged.edges.length > lastGraphModel.edges.length;
    lastGraphModel = merged;
    expandedNodeIds.add(target.id);
    cyGraph?.grow(merged, target.id); // GROW in place — existing positions + viewport preserved
    window.__kipiChat?.pushAside(expandResultLine(target.label, { ok: true, grew }));
    return true;
  } catch (e) {
    // clu-error-output: surface WHY the dig failed (401 / network / provider) — not a silent false.
    window.__kipiChat?.pushAgent(expandResultLine(target.label, { ok: false, error: e }));
    return false;
  } finally {
    inFlightNodeIds.delete(target.id);
  }
}

// ---- nd-drawer: per-node deterministic OSINT transforms (no LLM; grow the graph in place) ----

// Transform state is keyed by the CANONICAL (type,value,transformId), NOT the volatile node.id (codex
// D6 — ids change across re-render/hydration). `transformDone` survives a drawer re-render; the in-flight
// lock additionally uses inFlightNodeIds so a transform and a "Dig one hop" cannot run on the same node
// at once (codex D7). The last result line per node is shown back in the drawer.
const transformDone = new Set<string>();
const transformInFlight = new Set<string>();
const lastTransformResult = new Map<string, string>();
const normValue = (s: string): string => s.trim().toLowerCase();
function transformKey(type: string, value: string, transformId: string): string {
  return `${type} ${normValue(value)} ${transformId}`;
}

async function runTransform(node: CyNodeData, transformId: string): Promise<void> {
  if (!vault || !lastGraphModel) return;
  if (node.kind === "objective") return;
  const key = transformKey(node.type, node.full_name, transformId);
  if (transformInFlight.has(key) || transformDone.has(key) || inFlightNodeIds.has(node.id)) return; // D6/D7
  const gen = graphGen;
  const cgen = caseGen; // sf-cases: fence the post-await done/result writes if the case changes mid-transform
  transformInFlight.add(key);
  inFlightNodeIds.add(node.id); // D7: shared lock — also blocks the Dig button + another transform on this node
  let line = "";
  try {
    // production = real fetch; the smoke injects the canned OSINT fetch via the existing chat-wire seam.
    const result = await transformNode(vault, node.type, node.full_name, transformId, { fetchImpl: chatWire?.toolOpts?.fetchImpl });
    // codex D1: read lastGraphModel AFTER the await and merge into THAT (never a stale base); growCaseGraph
    // (D9) is the session redaction+merge chokepoint, then grow in place (no re-pop).
    if (gen === graphGen && lastGraphModel?.nodes.some((n) => n.id === node.id)) {
      const merged = growCaseGraph(vault, lastGraphModel, node.id, result);
      lastGraphModel = merged;
      cyGraph?.grow(merged, node.id);
    }
    const added = result.promoted.length + result.leads.length;
    line = added ? `${result.promoted.length} promoted, ${result.leads.length} lead(s) added.` : "No gated entities returned."; // D14
    if (cgen === caseGen) transformDone.add(key); // sf-cases: skip if the case switched mid-transform (A→B bleed)
  } catch (e) {
    line = msg(e); // sanitized SessionError only — never a raw adapter error / key-bearing URL (D8)
  } finally {
    transformInFlight.delete(key);
    inFlightNodeIds.delete(node.id);
    if (cgen === caseGen) lastTransformResult.set(node.id, line); // sf-cases: don't surface A's result in B
  }
}

// The per-node OSINT transform menu: availableTransforms is value- and key-aware (codex D2). An empty
// list is honest, not a silent gap (codex D14). Every label/result reaches the DOM via textContent.
function renderTransformMenu(box: HTMLElement, node: CyNodeData): void {
  if (!vault || node.kind === "objective") return;
  const sec = section();
  const label = document.createElement("div");
  label.className = "dlabel";
  label.textContent = "OSINT transforms";
  sec.appendChild(label);

  const options = availableTransforms(vault, node.type, node.full_name);
  if (!options.length) {
    const none = document.createElement("div");
    none.className = "portpending";
    none.textContent =
      node.type === "ip" || node.type === "domain" || node.type === "wallet"
        ? `No transforms available for this value. Add a provider key (Enrich) to enable ${node.type} transforms.`
        : "No OSINT transforms for this node type.";
    sec.appendChild(none);
    box.appendChild(sec);
    return;
  }

  const row = document.createElement("div");
  row.className = "nd-transforms";
  const nodeBusy = inFlightNodeIds.has(node.id);
  for (const opt of options) {
    const key = transformKey(node.type, node.full_name, opt.id);
    const running = transformInFlight.has(key);
    const done = transformDone.has(key);
    const b = document.createElement("button");
    b.textContent = running ? "Running…" : done ? `${opt.label} ✓` : opt.keyed ? `${opt.label} (key)` : opt.label;
    b.disabled = running || done || nodeBusy; // D6 done · D7 node busy
    if (!b.disabled) b.addEventListener("click", () => void runTransform(node, opt.id));
    row.appendChild(b);
  }
  sec.appendChild(row);

  const last = lastTransformResult.get(node.id);
  if (last) {
    const rl = document.createElement("div");
    rl.className = "nd-transform-result";
    rl.textContent = last; // textContent — a result line is never markup
    sec.appendChild(rl);
  }
  box.appendChild(sec);
}

// ---- kk-search: the global ⌘K search over the client entity DB ----

// A pending entity to focus on the next /entities render (codex D11): set by a search-result click,
// consumed once by renderEntitiesPage (which finds the row by data-entity-key and expands + scrolls it).
let pendingFocusKey: string | null = null;
function takePendingFocus(): string | null {
  const k = pendingFocusKey;
  pendingFocusKey = null;
  return k;
}

// ux-rowmenu (item 4): the /entities row ⋯ menu "Open in graph" sets this, then navigates home; once the
// graph has hydrated, applyPendingGraphFocus() finds the matching node BY LABEL (GraphNode carries no ref;
// its label is the redacted entity value, which matches the row's value/label) and centers + selects it.
let pendingGraphFocus: { value: string; label: string } | null = null;
// ux-rowmenu: "Enrich" sets the target, then navigates to /enrich; renderEntityEnrich consumes it to
// prefill the entity-first input. Mirrors pendingFocusKey.
let pendingEnrichTarget: string | null = null;
function takePendingEnrich(): string | null {
  const t = pendingEnrichTarget;
  pendingEnrichTarget = null;
  return t;
}

// ux-rowmenu: focus the home graph node for a pending "Open in graph" request. Best-effort: matches the
// node whose label equals the entity's value or display label; if none (the entity isn't graphed yet),
// it simply leaves the user on the full-case graph. Runs after hydrateCaseGraph so the nodes exist.
function applyPendingGraphFocus(): void {
  const want = pendingGraphFocus;
  pendingGraphFocus = null;
  if (!want || !lastGraphModel) return;
  const node = lastGraphModel.nodes.find((n) => n.label === want.value || n.label === want.label);
  if (!node) return;
  cyGraph?.selectById(node.id);
  cyGraph?.centerOn(node.id);
}

// ob-keyprompt (kf-fix): a keyless run routes to /account and asks renderAccountView to highlight +
// focus the key card THERE. A deferred flag (not an inline focus) because the keycard moved off the
// graph home (ac-ui) AND focusing must wait for the async hashchange render() to mount /account — an
// inline focus on home no-ops (no #keycard) and racing render() would steal it. Mirrors pendingFocusKey.
let pendingKeyFocus = false;
function takePendingKeyFocus(): boolean {
  const v = pendingKeyFocus;
  pendingKeyFocus = false;
  return v;
}

// hist-reopen (kf-fix): History moved to /account (ac-ui) but a brief renders in the home dock
// (#brief, dock.ts). Reopening a brief from History therefore routes HOME and shows it in the dock —
// otherwise viewBrief would target a #brief that does not exist on /account and throw. Set on
// /account, consumed by renderSplitView once the dock exists. Mirrors pendingKeyFocus / pendingFocusKey.
let pendingBriefObjective: string | null = null;
/** The canonical entity key (matches entity/db entityKey + the /entities row data-entity-key). */
function entityKeyOf(e: EntityRecord): string {
  return JSON.stringify([e.ref.type, e.ref.value]);
}

// Search the SAVED entity DB (entityDbFor(vault, null)) — the SAME scope /entities shows (codex D10) —
// so a clicked result always exists on the page it navigates to. Case-insensitive on label/value/type.
function searchEntities(query: string): EntityRecord[] {
  if (!vault) return [];
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const store = entityDbFor(vault, null);
  return allEntities(store)
    .filter((e) => e.label.toLowerCase().includes(q) || e.ref.value.includes(q) || (e.type || "").toLowerCase().includes(q))
    .slice(0, 25);
}

function renderSearchResults(query: string): void {
  const box = document.getElementById("cmdk-results");
  if (!box) return;
  box.replaceChildren();
  if (!query.trim()) return; // empty input: no list, and never echo the raw query (codex D12)
  const results = searchEntities(query);
  if (!results.length) {
    const none = document.createElement("div");
    none.className = "cmdk-none";
    none.textContent = "No matches."; // D12: no raw-query echo
    box.appendChild(none);
    return;
  }
  for (const e of results) {
    const row = document.createElement("button");
    row.className = "cmdk-result";
    row.textContent = `${e.label} · ${e.type || e.role} · ${e.promoted ? "promoted" : "lead"}`; // textContent (XSS-safe)
    const key = entityKeyOf(e);
    row.addEventListener("click", () => {
      pendingFocusKey = key;
      navigate("/entities");
      window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); // close the Alpine modal
    });
    box.appendChild(row);
  }
}

function wireCmdkSearch(): void {
  const input = document.getElementById("cmdk-input") as HTMLInputElement | null;
  if (!input) return;
  input.addEventListener("input", () => renderSearchResults(input.value));
}

// back-fix (restore-osint-tool-belt 2026-06-24): wire the chrome Back button. An inline onclick is DEAD
// under our CSP (script-src 'self', no unsafe-inline) — it silently did nothing. The #chrome-back shell is
// static in index.html, so attach once. Guarded on history depth so it never navigates off our origin.
function wireChromeBack(): void {
  const btn = document.getElementById("chrome-back");
  if (!btn) return;
  // ch-buttons-audit (controls-honesty): Back used to silently NO-OP when history.length <= 1, and
  // history.back() can't prove there is IN-APP history — on a deep link opened in a fresh tab it would
  // leave Hydra entirely (codex). The app's nav model is hub-and-spoke (home = graph+chat; detail routes
  // surface OVER it, returning via "← graph"/"close → graph"), so Back's honest contract is simply "up to
  // home, always inside Hydra". navigate("/") guarantees that deterministically. Back is hidden on home +
  // the auth screens (highlightNav), so this only fires where a return-home is meaningful.
  btn.addEventListener("click", () => {
    if (currentRoute() !== "/") navigate("/");
  });
}

// ---- ed-wire: the client entity DB views (key-redacted by the session layer) ----

// Build the entity DB over the vault's runs + the CURRENT graph model (so in-session
// expansions show up). entityDbFor redacts the live key out of every input, so the
// store, the views, and the __kipi hooks never carry it.
function entityStore(): EntityStore | null {
  if (!vault) return null;
  return entityDbFor(vault, lastGraphModel);
}

const EMPTY_ENTITY_VIEW: EntityView = { found: false, dossier: null, connections: [], coOccurrences: [], score: null, typedRels: [], appearances: [] };

function entityViewFor(kind: string, type: string, value: string): EntityView {
  const store = entityStore();
  if (!store || kind === "objective") return EMPTY_ENTITY_VIEW; // the seed is not an entity (D4)
  const rec = getEntity(store, type, value);
  // sf-entity-detail: the drawer mirrors the /entities-fold depth (§1+2 score+breakdown, §7 typed rels,
  // §8 appears-in) so BOTH folds reach the same depth (the built-not-wired scar). The score needs the
  // entity's role+promoted from the store; null/[] when the node isn't a stored entity / un-Processed.
  return {
    found: !!rec,
    dossier: buildDossier(store, type, value),
    connections: connectionsFor(store, type, value),
    coOccurrences: coOccurrencesFor(store, type, value),
    // codex impl-review: all three key off the REDACTED store record (rec.ref), gated on rec — never build
    // a raw canonKey from the node's (possibly secret-tainted) value. A non-entity node has no typed rels.
    score: rec && vault ? entityScoreBreakdownFor(vault, rec.ref, rec.role, rec.promoted) : null,
    typedRels: rec && vault ? typedRelationshipsFor(vault, canonKey(rec.ref.type, rec.ref.value)) : [],
    appearances: rec && vault ? entityAppearancesFor(vault, rec.ref) : [],
  };
}

function edgeViewFor(srcId: string | undefined, dstId: string | undefined): EdgeView {
  const store = entityStore();
  if (!store || !lastGraphModel || !srcId || !dstId) return { found: false, evidence: null };
  const a = lastGraphModel.nodes.find((n) => n.id === srcId);
  const b = lastGraphModel.nodes.find((n) => n.id === dstId);
  if (!a || !b) return { found: false, evidence: null };
  // The objective node maps to the synthetic seed ref (type 'objective') so a
  // surfaced_in edge resolves; an entity node uses its entityType (D1/D4/D5).
  const ref = (n: typeof a) => ({ type: n.kind === "objective" ? "objective" : n.entityType ?? "", value: n.label });
  const ev = edgeEvidence(store, ref(a), ref(b));
  return { found: !!ev, evidence: ev };
}

function connArrow(dir: Connection["direction"]): string {
  return dir === "in" ? "←" : dir === "out" ? "→" : "↔";
}
function relText(rel: Connection["relType"]): string {
  return rel === "surfaced_in" ? "surfaced in" : rel === "co_occurs" ? "co-occurs" : "linked";
}

// Render the REAL dossier + typed-connections + co-occurrence sections into the drawer
// (createElement + textContent — a hostile entity is literal text).
function renderEntitySections(box: HTMLElement, view: EntityView) {
  if (!view.found) {
    const s = section();
    const t = document.createElement("div");
    t.className = "portpending";
    t.textContent = "Not yet in the case entity DB (no saved run mentions this entity).";
    s.appendChild(t);
    box.appendChild(s);
    return;
  }
  if (view.dossier) {
    const s = section();
    const label = document.createElement("div");
    label.className = "dlabel";
    label.textContent = "Dossier";
    s.appendChild(label);
    const head = document.createElement("div");
    head.className = "nd-dossier-head";
    head.textContent = view.dossier.headline;
    s.appendChild(head);
    for (const line of view.dossier.lines) {
      const li = document.createElement("div");
      li.className = "nd-dossier-line";
      li.textContent = line;
      s.appendChild(li);
    }
    box.appendChild(s);
  }
  const cs = section();
  const cl = document.createElement("div");
  cl.className = "dlabel";
  // adr-wire D9: "Derived connections" (deterministic) so they are never confused with the
  // model-typed semantic relations rendered separately by the AI affordances below.
  cl.textContent = `Derived connections (${view.connections.length})`;
  cs.appendChild(cl);
  if (!view.connections.length) {
    const none = document.createElement("div");
    none.className = "nd-conn-none";
    none.textContent = "No connections recorded yet.";
    cs.appendChild(none);
  } else {
    for (const c of view.connections.slice(0, 30)) {
      const row = document.createElement("div");
      row.className = "nd-conn";
      row.textContent =
        `${connArrow(c.direction)} ${relText(c.relType)}: ${c.otherLabel} · ${c.otherType || c.otherRole} · ${c.confidence}` +
        (c.count > 1 ? ` ×${c.count}` : "");
      cs.appendChild(row);
    }
  }
  box.appendChild(cs);
  if (view.coOccurrences.length) {
    const os = section();
    const ol = document.createElement("div");
    ol.className = "dlabel";
    ol.textContent = `Co-occurrence (${view.coOccurrences.length})`;
    os.appendChild(ol);
    for (const c of view.coOccurrences.slice(0, 20)) {
      const row = document.createElement("div");
      row.className = "nd-cooccur";
      row.textContent = `↔ ${c.otherLabel} · ${c.otherType || c.otherRole}`;
      os.appendChild(row);
    }
    box.appendChild(os);
  }
}

// ---- cl-wire: the entity's cluster membership in the drawer ----

// The selected entity's CLUSTER (label + size + co-members), when connected-components places it in
// one. Built via the read-only, key-redacted clustersFor; every value reaches the DOM via textContent.
function renderClusterSection(box: HTMLElement, node: CyNodeData): void {
  if (!vault) return;
  const cluster = clusterFor(clustersFor(vault, lastGraphModel), node.type || "", node.full_name);
  if (!cluster) return;
  const sec = section();
  const label = document.createElement("div");
  label.className = "dlabel";
  label.textContent = "Cluster";
  sec.appendChild(label);
  const head = document.createElement("div");
  head.className = "nd-cluster-head";
  head.textContent = `${cluster.label} · ${cluster.size} members`;
  sec.appendChild(head);
  const self = node.full_name.trim().toLowerCase();
  const others = cluster.members.filter((m) => m.value !== self);
  for (const m of others.slice(0, 20)) {
    const row = document.createElement("div");
    row.className = "nd-cluster-member";
    row.textContent = `· ${m.value} (${m.type})`;
    sec.appendChild(row);
  }
  box.appendChild(sec);
}

// ---- adr-wire: on-demand AI passes (model-written dossier + semantic typed relations) ----

// A model-written dossier (rendered markdown, escape-first XSS-safe) BESIDE the derived one, and
// "Type relations" overlaying the gate-faithful semantic rel_type as a SEPARATE "Model-typed"
// panel (D9 — never conflated with the derived rows). Buttons disable while a call is in flight
// (D8 — no double-spend). The session layer redacts the key in+out (executable belt + leakgate test);
// nothing here ever sees it.
function renderAiAffordances(box: HTMLElement, node: CyNodeData): void {
  const sec = section();
  const label = document.createElement("div");
  label.className = "dlabel";
  label.textContent = "AI analysis (model-written · uses your key)";
  sec.appendChild(label);

  const row = document.createElement("div");
  row.className = "nd-ai-actions";
  const dossierBtn = document.createElement("button");
  dossierBtn.className = "nd-ai-dossier-btn";
  dossierBtn.textContent = "AI dossier";
  const relsBtn = document.createElement("button");
  relsBtn.className = "nd-ai-relations-btn";
  relsBtn.textContent = "Type relations";
  row.appendChild(dossierBtn);
  row.appendChild(relsBtn);
  sec.appendChild(row);

  const out = document.createElement("div");
  out.className = "nd-ai-out";
  sec.appendChild(out);
  box.appendChild(sec);

  dossierBtn.addEventListener("click", async () => {
    if (dossierBtn.disabled) return;
    dossierBtn.disabled = true; // D8: no double-spend
    dossierBtn.textContent = "Writing…";
    try {
      renderAiDossier(out, await runAiDossier(node.type || "", node.full_name));
    } catch (e) {
      renderAiError(out, msg(e));
    } finally {
      dossierBtn.textContent = "AI dossier";
      dossierBtn.disabled = false;
    }
  });

  relsBtn.addEventListener("click", async () => {
    if (relsBtn.disabled) return;
    relsBtn.disabled = true;
    relsBtn.textContent = "Typing…";
    try {
      renderModelTyped(out, node, await runSemanticRelations(node.type || "", node.full_name));
    } catch (e) {
      renderAiError(out, msg(e));
    } finally {
      relsBtn.textContent = "Type relations";
      relsBtn.disabled = false;
    }
  });
}

function renderAiDossier(out: HTMLElement, md: string | null): void {
  out.querySelector(".nd-ai-dossier")?.remove();
  const wrap = document.createElement("div");
  wrap.className = "nd-ai-dossier";
  const tag = document.createElement("div");
  tag.className = "nd-ai-tag";
  tag.textContent = "AI dossier · model-written";
  wrap.appendChild(tag);
  const body = document.createElement("div");
  body.className = "markdown nd-ai-body";
  body.innerHTML = renderMarkdown(md ?? "No AI dossier — not enough grounded evidence for this entity."); // escape-first XSS-safe
  wrap.appendChild(body);
  out.appendChild(wrap);
}

function renderModelTyped(out: HTMLElement, node: CyNodeData, rels: SemanticRelation[]): void {
  out.querySelector(".nd-model-typed")?.remove();
  const store = entityStore();
  const rec = store ? getEntity(store, node.type || "", node.full_name) : null;
  const cidToConn = new Map<string, Connection>();
  if (store && rec) {
    for (const c of connectionsFor(store, node.type || "", node.full_name)) cidToConn.set(connId(rec.ref, c), c);
  }
  const wrap = document.createElement("div");
  wrap.className = "nd-model-typed";
  const tag = document.createElement("div");
  tag.className = "nd-ai-tag";
  tag.textContent = `Model-typed relations (${rels.length})`;
  wrap.appendChild(tag);
  if (!rels.length) {
    const none = document.createElement("div");
    none.className = "nd-conn-none";
    none.textContent = "No semantic relations typed (none survived the gate).";
    wrap.appendChild(none);
  }
  for (const r of rels) {
    const conn = cidToConn.get(r.cid);
    const li = document.createElement("div");
    li.className = "nd-model-rel";
    const other = conn ? `${conn.otherLabel} · ${conn.otherType || conn.otherRole}` : "(connection)";
    li.textContent = `⇒ ${r.relType}: ${other} · ${r.confidence}${r.evidence ? ` — ${r.evidence}` : ""}`; // textContent (XSS-safe)
    wrap.appendChild(li);
  }
  out.appendChild(wrap);
}

function renderAiError(out: HTMLElement, message: string): void {
  const e = document.createElement("div");
  e.className = "nd-ai-err err";
  e.textContent = message;
  out.appendChild(e);
}

// ---- the right slide-in node drawer (graph.html node-drawer), built with textContent (D9) ----

function clearDrawer() {
  // ccc-workspace-shell: node detail is the chat node card now (the floating #cy-drawer is gone).
  // Clearing selection (background tap) removes the current card from the chat stream.
  document.querySelector("#chat-host .node-card")?.remove();
}
function clearGraphChrome() {
  clearDrawer();
  closeMenu();
  document.getElementById("cy-setchip")?.replaceChildren();
  const stats = document.getElementById("cy-stats");
  if (stats) stats.replaceChildren();
}

// nd-origin (UX 2026-06-24, sp-8943beb4): the founder must be able to tell, at a glance, where a node
// came from — especially a node that is NOT from intake (it may warrant an OSINT call). The graph encodes
// this as the border style (intake=solid / osint=dashed / manual=dotted), which is unreadable at zoom, so
// the drawer states it in plain words. The OLD chip collapsed every non-osint origin to "from intake",
// which mislabels a `manual` node — fixed here to the honest taxonomy.
function originLabel(origin: string | undefined): string {
  switch (origin) {
    case "osint": return "OSINT — agent-discovered";
    case "manual": return "manual — analyst-added";
    case "seed": return "seed — your starting point";
    case "intake": return "from intake — an uploaded report";
    default: return origin ? `${origin}` : "from intake — an uploaded report";
  }
}

// ccc-workspace-shell: the floating node drawer (#cy-drawer) is gone; its FULL content now renders into
// the chat node card. This builds that rich body into ANY host (the card the dock hands us). No floating
// close button — the chat card has its own lifecycle (replaced in place / scrolled by the dock).
function buildNodeCard(box: HTMLElement, node: CyNodeData) {
  box.replaceChildren();

  // header: role pill + name
  const head = section();
  const pill = document.createElement("div");
  pill.className = `role-pill role-${node.role || ""}`;
  pill.textContent = node.role || node.type || "node";
  head.appendChild(pill);
  const title = document.createElement("div");
  title.className = "dtitle";
  title.textContent = node.full_name; // textContent: an entity value is never markup (D9)
  head.appendChild(title);
  const chips = document.createElement("div");
  chips.className = "dchips";
  if (node.type) chips.appendChild(chip(node.type));
  chips.appendChild(chip(node.origin === "osint" ? "OSINT" : node.origin === "manual" ? "manual" : node.origin === "seed" ? "seed" : "intake", node.origin === "osint" || node.origin === "manual"));
  head.appendChild(chips);
  box.appendChild(head);

  // node-removal (founder 2026-06-25): a manual "Remove from case" — reversible exclude (node + its edges
  // drop from the graph + /entities; an Undo toast restores it). The seed objective is never removable.
  if (node.kind !== "objective") {
    const rm = document.createElement("button");
    rm.className = "ghost nd-remove";
    rm.textContent = "Remove from case";
    rm.title = "Remove this node and its edges from the graph + entities (reversible — Undo restores it)";
    rm.style.cssText = "margin:2px 0 4px;color:#c2553f;border:1px solid #c2553f33";
    rm.addEventListener("click", () => void excludeNodeFromCase(node.type ?? "", node.full_name, node.full_name));
    box.appendChild(rm);
  }

  // facts: the client node fields (status / grade / sources / why-held)
  const facts = section();
  const dl = document.createElement("dl");
  dl.className = "nd-meta";
  const status = node.kind === "objective" ? "seed objective" : node.promoted ? "promoted (on graph)" : "lead (held)";
  if (node.type) addDetailRow(dl, "type", node.type); // complete properties table (nd-drawer)
  if (node.role) addDetailRow(dl, "role", node.role);
  if (node.sub_role) addDetailRow(dl, "sub-role", node.sub_role); // A1: the operator's network function
  addDetailRow(dl, "status", status);
  if (node.kind !== "objective") addDetailRow(dl, "origin", originLabel(node.origin)); // nd-origin: honest provenance in plain words
  if (typeof node.report_count === "number") addDetailRow(dl, "sources", String(node.report_count));
  if (typeof node.infraSourceCount === "number") addDetailRow(dl, "infra sources", String(node.infraSourceCount));
  if (node.grade) addDetailRow(dl, "grade", node.grade);
  // INC-4a: the real Process analytics — present only after the score + graph_metrics steps run.
  if (typeof node.threat_score === "number") addDetailRow(dl, "threat score", String(Math.round(node.threat_score)));
  if (typeof node.degree_centrality === "number") addDetailRow(dl, "degree centrality", node.degree_centrality.toFixed(2));
  if (typeof node.betweenness === "number") addDetailRow(dl, "betweenness", node.betweenness.toFixed(2));
  if (typeof node.eigenvector === "number") addDetailRow(dl, "eigenvector", node.eigenvector.toFixed(2));
  if (typeof node.community === "number") addDetailRow(dl, "community", String(node.community));
  if (node.kind !== "objective") {
    const store = entityStore();
    const rec = store ? getEntity(store, node.type, node.full_name) : null;
    if (rec) addDetailRow(dl, "runs", String(rec.runs.length)); // runs-count from the entity DB
  }
  if (node.reason) addDetailRow(dl, "why held", node.reason);
  facts.appendChild(dl);

  // A5 (analyze.py:526 PIVOT_TEMPLATES): the per-entity external OSINT pivot LINKS an analyst clicks to
  // research this entity off-platform (Shodan / VirusTotal / Etherscan / urlscan / PublicWWW …). Links,
  // not fetches — no key, no CORS. Opened in a new tab; rel=noopener so the target can't reach us back.
  if (node.kind !== "objective") {
    const links = pivotLinks(node.full_name, node.type);
    if (links.length) {
      const piv = document.createElement("div");
      piv.className = "nd-pivots";
      const plabel = document.createElement("div");
      plabel.className = "dlabel";
      plabel.textContent = "OSINT pivots — research this entity off-platform";
      piv.appendChild(plabel);
      for (const { label, url } of links) {
        const a = document.createElement("a");
        a.className = "nd-pivot-link";
        a.href = url; // already URL-encoded in pivots.ts
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = label; // textContent (XSS-safe)
        piv.appendChild(a);
      }
      facts.appendChild(piv);
    }
  }

  // Dig one hop (the agent loop on this entity → grow in place)
  if (node.kind !== "objective") {
    const inFlight = inFlightNodeIds.has(node.id);
    const expanded = expandedNodeIds.has(node.id);
    const btn = document.createElement("button");
    btn.className = "dig";
    btn.textContent = inFlight ? "Digging…" : expanded ? "Expanded" : "Dig one hop";
    btn.disabled = inFlight || expanded; // codex-9: no repeat spend on the same node
    if (!btn.disabled) btn.addEventListener("click", () => void doExpand({ id: node.id, label: node.full_name, kind: node.kind }));
    facts.appendChild(btn);
  }
  box.appendChild(facts);

  // nd-drawer: the per-node OSINT transform menu (deterministic, no LLM, grows the graph in place)
  renderTransformMenu(box, node);

  // Neighbors — focus this node's directed links (computed from cytoscape topology, D5)
  const neigh = section();
  const nlabel = document.createElement("div");
  nlabel.className = "dlabel";
  nlabel.textContent = "Neighbors";
  neigh.appendChild(nlabel);
  const nrow = document.createElement("div");
  nrow.className = "neighbors";
  (["in", "out", "all"] as const).forEach((dir) => {
    const b = document.createElement("button");
    b.textContent = dir === "in" ? "← in" : dir === "out" ? "out →" : "both";
    b.addEventListener("click", () => cyGraph?.showDirection(dir));
    nrow.appendChild(b);
  });
  const focus = document.createElement("button");
  focus.textContent = "◎ focus web";
  focus.addEventListener("click", () => cyGraph?.spotlightNode(node.id));
  nrow.appendChild(focus);
  // ccc-workspace-shell: the old "💬 discuss in chat" button is dropped — this card already LIVES in the
  // chat, so the node is here to be discussed/dug directly.
  neigh.appendChild(nrow);
  box.appendChild(neigh);

  // ed-wire: REAL dossier + typed connections + co-occurrence from the client entity DB
  // (key-redacted). The objective/seed has no entity record (D4), so this is skipped for it.
  if (node.kind !== "objective") renderEntitySections(box, entityViewFor(node.kind, node.type || "", node.full_name));

  // cl-wire: the entity's CLUSTER membership (label + size + co-members), when it is in one.
  if (node.kind !== "objective") renderClusterSection(box, node);

  // adr-wire: the AI dossier + semantic typed relations (on-demand LLM passes, spends the key).
  if (node.kind !== "objective") renderAiAffordances(box, node);

  // The properties table + the OSINT transform menu are now real above. Only two surfaces are out of
  // scope by decision (nd-drawer): the style-rules editor (cosmetic graph styling, not evidence) and the
  // manual-node form (authoring a node is an analyst WRITE — the analyst-authority surface, item 5).
  const pp = section();
  const pl = document.createElement("div");
  pl.className = "dlabel";
  pl.textContent = "Out of scope (by decision)"; // spillover-skip — UI label for the nd-drawer decision above, not a code deferral
  pp.appendChild(pl);
  const ppt = document.createElement("div");
  ppt.className = "portpending";
  ppt.textContent =
    "The style-rules editor (cosmetic) and the manual-node form (an analyst write — the analyst-authority surface) are intentionally out of this client.";
  pp.appendChild(ppt);
  box.appendChild(pp);
}

function section(): HTMLElement {
  const d = document.createElement("div");
  d.className = "dsec";
  return d;
}
function chip(text: string, osint = false): HTMLElement {
  const c = document.createElement("span");
  c.className = osint ? "dchip osint" : "dchip";
  c.textContent = text;
  return c;
}
function addDetailRow(dl: HTMLElement, label: string, value: string) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value;
  dl.appendChild(dt);
  dl.appendChild(dd);
}

// ---- controls strip (layout switcher / fit / re-layout / path mode / search) ----

// A4: ONE shared filter + visibility state so the chat path (kipiGraphApi.applyFilter) and the facet UI
// COMPOSE instead of clobbering each other (codex), and a graph regrow re-applies the active view.
// co-occurrence defaults SHOWN — in the web those edges ARE the entity↔entity network backbone (the
// home-graph keystone), unlike the original's server-side co_mentioned which defaulted off.
const graphFilterState: { etype?: string; minScore?: number; role?: string; origin?: string; cluster?: string } = {};
const graphVisState = { meaningfulOnly: false, inClusterOnly: false, coOccurrence: true, showAll: false };
// G2a (video-review 2026-06-25): "Focus threats" defaults ON — the case graph reads as the promoted
// threat spine, not a 200-node hairball (founder Option 1: tame the view, keep all data). Reset clears it.
let graphFocusThreats = true;
function graphFilterActive(): boolean {
  const f = graphFilterState;
  return !!(f.etype || f.minScore != null || f.role || f.origin || f.cluster);
}
function applyGraphFilter(): void {
  if (graphFilterActive()) cyGraph?.applyFilter(graphFilterState);
  else cyGraph?.clearFilter();
}

function buildControls() {
  const bar = document.getElementById("cy-controls");
  if (!bar || !cyGraph) return;
  bar.replaceChildren();

  const sel = document.createElement("select");
  sel.title = "Layout";
  const layouts: [string, string][] = [["cose", "Force (cose)"]];
  if (cyGraph.fcoseOk) layouts.push(["fcose", "Physics (fcose)"]);
  if (cyGraph.dagreOk) layouts.push(["dagre", "Hierarchy (dagre)"]);
  layouts.push(["concentric", "Ego rings"], ["circle", "Circle"]);
  for (const [v, label] of layouts) {
    const o = document.createElement("option");
    o.value = v;
    o.textContent = label;
    sel.appendChild(o);
  }
  sel.addEventListener("change", () => cyGraph?.setLayout(sel.value));
  bar.appendChild(sel);

  bar.appendChild(ctlBtn("Fit", () => cyGraph?.fit()));
  bar.appendChild(ctlBtn("Re-layout", () => cyGraph?.reLayout()));

  const msg = document.createElement("span");
  msg.className = "cy-msg";
  msg.id = "cy-msg";

  const pathBtn = ctlBtn("Path", () => {
    const on = cyGraph?.togglePathMode();
    pathBtn.classList.toggle("on", !!on);
    msg.textContent = on ? "pick the source node…" : "";
  });
  pathBtn.title = "Shortest path: pick two nodes";
  bar.appendChild(pathBtn);

  const search = document.createElement("input");
  search.className = "cy-search";
  search.placeholder = "search node…";
  const runSearch = () => { const r = cyGraph?.searchNode(search.value); msg.textContent = r?.msg ?? ""; };
  search.addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });
  search.addEventListener("input", () => { if (!search.value) { cyGraph?.clearSearch(); msg.textContent = ""; } });
  bar.appendChild(search);
  bar.appendChild(ctlBtn("Go", runSearch));
  bar.appendChild(msg);

  const facets = document.createElement("span"); // A4: rebuilt from the live graph on every render/grow
  facets.id = "cy-facets";
  facets.className = "cy-facets";
  bar.appendChild(facets);
  refreshFacetControls();
}

// A4 (graph.html:67-131): the facet filters, visibility toggles, and the Legend toggle. REBUILT from the
// live graph (cyGraph.getFacets) on every render/grow (wired via onStats — codex: a one-shot build mounts
// empty + goes stale). Selected values are restored from the shared graphFilterState/graphVisState so a
// regrow re-applies the active view instead of resetting it.
function refreshFacetControls(): void {
  const host = document.getElementById("cy-facets");
  if (!host || !cyGraph) return;
  host.replaceChildren();
  const facets = cyGraph.getFacets();

  const mkSelect = (label: string, field: "role" | "origin" | "cluster", options: { key: string; n: number }[]): void => {
    if (!options.length) return; // only show a facet that has values
    const s = document.createElement("select");
    s.className = "cy-facet";
    s.title = label;
    const all = document.createElement("option");
    all.value = "";
    all.textContent = `all ${label}`;
    s.appendChild(all);
    for (const o of options) {
      const opt = document.createElement("option");
      opt.value = o.key;
      opt.textContent = `${o.key} (${o.n})`;
      s.appendChild(opt);
    }
    s.value = graphFilterState[field] ?? ""; // restore the active selection across a regrow
    s.addEventListener("change", () => {
      graphFilterState[field] = s.value || undefined;
      applyGraphFilter();
    });
    host.appendChild(s);
  };
  mkSelect("roles", "role", facets.roles);
  mkSelect("origins", "origin", facets.origins);
  mkSelect("clusters", "cluster", facets.clusters);

  // visibility toggles (graph.html:112-131) — a real hide, combined into one setVisibility call.
  const mkToggle = (label: string, key: keyof typeof graphVisState): void => {
    const wrap = document.createElement("label");
    wrap.className = "cy-toggle";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = graphVisState[key]; // restore state across a regrow
    cb.addEventListener("change", () => {
      graphVisState[key] = cb.checked;
      cyGraph?.setVisibility({ ...graphVisState });
    });
    wrap.appendChild(cb);
    wrap.appendChild(document.createTextNode(" " + label));
    host.appendChild(wrap);
  };
  // G2a: "Focus threats" — dim non-promoted nodes so the spine pops (default ON). Its own handler (drives
  // setSpineFocus, not setVisibility) so the spine dim composes with, but is independent of, the hide toggles.
  const focusWrap = document.createElement("label");
  focusWrap.className = "cy-toggle";
  focusWrap.title = "Lead with the promoted threat spine; uncheck (or Reset view) to show every node";
  const focusCb = document.createElement("input");
  focusCb.type = "checkbox";
  focusCb.checked = graphFocusThreats; // restore across a regrow
  focusCb.addEventListener("change", () => {
    graphFocusThreats = focusCb.checked;
    cyGraph?.setSpineFocus(graphFocusThreats);
  });
  focusWrap.appendChild(focusCb);
  focusWrap.appendChild(document.createTextNode(" Focus threats"));
  host.appendChild(focusWrap);

  mkToggle("meaningful only", "meaningfulOnly");
  mkToggle("in a cluster", "inClusterOnly");
  mkToggle("co-occurrence links", "coOccurrence");

  // Reset view (graph.html "show all"): clear every facet + visibility hide back to the full graph.
  const reset = ctlBtn("Reset view", () => {
    for (const k of Object.keys(graphFilterState) as (keyof typeof graphFilterState)[]) delete graphFilterState[k];
    graphVisState.meaningfulOnly = graphVisState.inClusterOnly = false;
    graphVisState.coOccurrence = true;
    graphFocusThreats = false; // G2a: "show every node" means dropping the spine dim too
    cyGraph?.setVisibility({ showAll: true });
    cyGraph?.setSpineFocus(false);
    cyGraph?.clearFilter();
    refreshFacetControls();
  });
  reset.title = "Clear all filters + show every node";
  host.appendChild(reset);

  // Legend toggle (graph.html:134-161): build the panel once, show/hide on click.
  const legendBtn = ctlBtn("Legend", () => {
    const panel = document.getElementById("cy-legend") ?? buildLegendPanel();
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  });
  legendBtn.title = "What the shapes, colors, and lines mean";
  host.appendChild(legendBtn);

  // sp-8943beb4: provenance (node border-style = origin: solid=intake / dashed=osint / dotted=manual) was
  // real but unreadable — the key was locked behind the Legend toggle, so an analyst couldn't tell an
  // intake node from an osint-discovered one without a click. Surface an ALWAYS-ON origin key (the item's
  // accepted "always-on mini-legend" option), each swatch drawn in its REAL border style so it is
  // self-explanatory. Built from legendSpec().origins so it can never drift from the node render.
  host.appendChild(buildOriginKeyStrip());
}

// sp-8943beb4: a compact, always-visible provenance key (origin → border style). Drawn from legendSpec()
// so it never drifts from the render; each swatch uses the actual border style. Inline-styled (no CSS-file
// dependency, so it renders on any route the graph controls mount). textContent only (XSS-safe, D9).
function buildOriginKeyStrip(): HTMLElement {
  const strip = document.createElement("div");
  strip.className = "cy-origin-key";
  strip.title = "Node border style shows where each entity came from (chain of custody)";
  // hydra ISSUE-4 family (founder 2026-07-07): color was #57534E (light-theme muted) — invisible on the dark
  // canvas. Route to the themed --muted token so the legend text flips with the graph it labels.
  strip.style.cssText = "display:flex;gap:12px;align-items:center;flex-wrap:wrap;font-size:11px;color:var(--muted);padding:2px 0";
  for (const o of legendSpec().origins) {
    const item = document.createElement("span");
    item.style.cssText = "display:inline-flex;gap:5px;align-items:center";
    const sw = document.createElement("span");
    sw.className = "cy-legend-swatch";
    sw.style.cssText = `display:inline-block;width:13px;height:13px;border-radius:50%;background:transparent;border:2px ${o.borderStyle} var(--ink)`; // hydra ISSUE-4: was #1A1A19 (near-black) → invisible in dark; --ink flips
    item.appendChild(sw);
    const label = document.createElement("span");
    label.textContent = o.origin; // intake / osint / manual
    item.appendChild(label);
    strip.appendChild(item);
  }
  return strip;
}

// A4 (graph.html:134-161): the node/edge encoding legend, rendered FROM legendSpec() so it can never
// drift from the actual render. textContent only (XSS-safe, D9). Hidden until the Legend button toggles it.
function buildLegendPanel(): HTMLElement {
  const spec = legendSpec();
  const panel = document.createElement("div");
  panel.id = "cy-legend";
  panel.className = "cy-legend";
  panel.style.display = "none";

  const section = (title: string): HTMLElement => {
    const h = document.createElement("div");
    h.className = "cy-legend-h";
    h.textContent = title;
    panel.appendChild(h);
    return panel;
  };
  const row = (swatch: HTMLElement, text: string): void => {
    const r = document.createElement("div");
    r.className = "cy-legend-row";
    r.appendChild(swatch);
    const t = document.createElement("span");
    t.textContent = text;
    r.appendChild(t);
    panel.appendChild(r);
  };
  const dot = (color: string, shape: string): HTMLElement => {
    const s = document.createElement("span");
    s.className = "cy-legend-swatch";
    s.style.border = `2px solid ${color}`;
    s.style.background = "#A7CFCB";
    if (shape === "ellipse") s.style.borderRadius = "50%";
    else if (shape === "diamond") s.style.transform = "rotate(45deg)";
    else if (shape === "octagon") s.style.clipPath = "polygon(30% 0,70% 0,100% 30%,100% 70%,70% 100%,30% 100%,0 70%,0 30%)";
    else if (shape === "round-rectangle") s.style.borderRadius = "3px";
    return s;
  };
  const line = (color: string, style: string): HTMLElement => {
    const s = document.createElement("span");
    s.className = "cy-legend-line";
    s.style.borderTop = `2px ${style} ${color}`;
    return s;
  };

  section("Role / shape");
  for (const r of spec.roles) row(dot(r.color, r.shape), `${r.role} (${r.shape})`);
  section("Origin (border style)");
  for (const o of spec.origins) row(dot("var(--ink)", "ellipse"), `${o.origin} — ${o.borderStyle} border`); // hydra ISSUE-4: was #1A1A19 → invisible in dark
  section("Edge confidence");
  for (const c of spec.confidences) row(line(c.color, "solid"), c.confidence);
  section("Lines");
  row(line("#78716C", "solid"), "a known link (hosts / registered-by / pays) — arrow shows direction");
  row(line("#A8A29E", "dotted"), "appeared together (co-occurrence), not yet a confirmed link");

  const host = document.getElementById("cy-controls")?.parentElement ?? document.body;
  host.appendChild(panel);
  return panel;
}

function ctlBtn(label: string, handler: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.className = "ghost";
  b.textContent = label;
  b.addEventListener("click", handler);
  return b;
}

function renderStats(stats: { nodes: number; edges: number }) {
  const box = document.getElementById("cy-stats");
  if (!box) return;
  box.replaceChildren();
  // ux: an analyst reads "entities · links". The dead "faces:0" stat (a favicon-thumbnail count that was
  // always 0 after the F3 favicon drop) was removed from GraphStats entirely (node-graph-prd-audit 2026-06-24).
  const parts = [`${stats.nodes} entit${stats.nodes === 1 ? "y" : "ies"}`, `${stats.edges} link${stats.edges === 1 ? "" : "s"}`];
  for (const text of parts) {
    const s = document.createElement("span");
    s.textContent = text;
    box.appendChild(s);
  }
}

// ---- selection chip (Maltego set): the box-/shift-selected nodes, copy / clear ----

// draggable set chip: remembered position (module state) reapplied on every re-render so it stays put.
let setchipPos: { left: number; top: number } | null = null;
function makeSetChipDraggable(box: HTMLElement, handle: HTMLElement): void {
  handle.style.cursor = "move";
  if (setchipPos) { box.style.left = `${setchipPos.left}px`; box.style.top = `${setchipPos.top}px`; box.style.right = "auto"; box.style.bottom = "auto"; }
  handle.addEventListener("pointerdown", (e) => {
    if ((e.target as HTMLElement).tagName === "BUTTON") return; // copy/clear buttons aren't drag handles
    e.preventDefault();
    const rect = box.getBoundingClientRect();
    const dx = e.clientX - rect.left, dy = e.clientY - rect.top;
    const onMove = (ev: PointerEvent) => {
      const left = Math.max(4, Math.min(ev.clientX - dx, window.innerWidth - rect.width - 4));
      const top = Math.max(4, Math.min(ev.clientY - dy, window.innerHeight - rect.height - 4));
      setchipPos = { left, top };
      box.style.left = `${left}px`; box.style.top = `${top}px`; box.style.right = "auto"; box.style.bottom = "auto";
    };
    const onUp = () => { window.removeEventListener("pointermove", onMove); window.removeEventListener("pointerup", onUp); };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  });
}

function renderSetChip(set: SetMember[]) {
  const box = document.getElementById("cy-setchip");
  if (!box) return;
  box.replaceChildren();
  if (!set.length) return;
  box.className = "cy-setchip";
  const head = document.createElement("div");
  head.className = "cy-setchip-head";
  const count = document.createElement("span");
  count.textContent = `${set.length} selected`;
  head.appendChild(count);
  // draggable (founder 2026-07-03): drag the header to move the chip out of the way. Pointer events +
  // absolute left/top; positions persist across re-renders via setchipPos (module state).
  makeSetChipDraggable(box, head);
  const actions = document.createElement("span");
  const copy = document.createElement("button");
  copy.className = "link";
  copy.textContent = "copy";
  copy.addEventListener("click", () => { if (navigator.clipboard) void navigator.clipboard.writeText(set.map((s) => s.name).join("\n")); });
  const clear = document.createElement("button");
  clear.className = "link";
  clear.textContent = "clear";
  clear.addEventListener("click", () => cyGraph?.clearSelection());
  actions.appendChild(copy);
  actions.appendChild(clear);
  head.appendChild(actions);
  box.appendChild(head);
  const ul = document.createElement("ul");
  for (const s of set) {
    const li = document.createElement("li");
    li.textContent = s.name; // textContent (D9)
    ul.appendChild(li);
  }
  box.appendChild(ul);

  // multi-select group actions (founder 2026-07-03): act on the WHOLE selection. Each routes into the chat
  // (askInChat → dispatch) so the run/answer shows in the conversation, exactly like the single-node menu.
  const names = set.map((s) => s.name);
  const row = document.createElement("div");
  row.className = "cy-setchip-actions";
  const act = (label: string, onClick: () => void) => {
    const b = document.createElement("button");
    b.textContent = label;
    b.addEventListener("click", onClick);
    row.appendChild(b);
  };
  act("Investigate all", () => window.__kipiChat?.askInChat(`investigate ${names.join(", ")}`));
  act("Dig each one hop", () => {
    for (const s of set) {
      const n = lastGraphModel?.nodes.find((x) => x.id === s.id);
      if (n && n.kind !== "objective") void doExpand({ id: n.id, label: n.label, kind: n.kind });
    }
  });
  act("What connects these?", () => window.__kipiChat?.askInChat(`what connects ${names.join(", ")}?`));
  act("Remove from graph", () => {
    for (const s of set) removeNodeByTarget(s.name); // node-removal: reversible via the undo toast
    cyGraph?.clearSelection();
    window.__kipiChat?.pushAside(`removed ${set.length} node${set.length === 1 ? "" : "s"} from the graph (undo available)`);
  });
  box.appendChild(row);
}

// ---- right-click context menu (focus a node's web) ----

function closeMenu() {
  document.getElementById("cy-menu")?.replaceChildren();
}
function renderMenu(node: CyNodeData, clientX: number, clientY: number) {
  const box = document.getElementById("cy-menu");
  if (!box) return;
  box.replaceChildren();
  box.className = "cy-menu";
  box.style.left = `${Math.max(8, Math.min(clientX, window.innerWidth - 232))}px`;
  box.style.top = `${Math.max(8, Math.min(clientY, window.innerHeight - 160))}px`;
  const head = document.createElement("div");
  head.className = "mhead";
  head.textContent = node.full_name; // textContent (D9)
  box.appendChild(head);
  // remove-cards (founder 2026-07-03): the right-click menu is now the way to pull a node's detail — every
  // item ROUTES A QUESTION/COMMAND INTO THE CHAT (askInChat → the same dispatch the analyst types into), so
  // the answer arrives as a normal chat turn. No node card is injected. `ask` is a small helper that fires
  // one menu item's chat text and closes the menu.
  const ask = (text: string) => { window.__kipiChat?.askInChat(text); closeMenu(); };
  const addItem = (label: string, onClick: () => void, disabled = false) => {
    const b = document.createElement("button");
    b.textContent = label;
    b.disabled = disabled;
    if (!disabled) b.addEventListener("click", onClick);
    box.appendChild(b);
  };
  addItem("What is this?", () => ask(`what is ${node.full_name}?`));
  if (node.kind !== "objective") {
    // Show full details = the DETERMINISTIC entity panel (score/rels/appears-in/dossier) as a chat message,
    // NO LLM call (founder 2026-07-03). Distinct from "What is this?" which is the conversational LLM answer.
    addItem("Show full details", () => { window.__kipiChat?.showNodeDetails(node); closeMenu(); });
    addItem("Show its connections", () => ask(`what are the connections of ${node.full_name}?`));
    const inFlight = inFlightNodeIds.has(node.id);
    const expanded = expandedNodeIds.has(node.id);
    // Dig one hop = the client one-hop expand (streams into the chat trail + grows the graph). Guarded so the
    // same node isn't dug twice (codex-9: no repeat spend).
    addItem(
      inFlight ? "Digging…" : expanded ? "Expanded" : "Dig one hop",
      () => { void doExpand({ id: node.id, label: node.full_name, kind: node.kind }); closeMenu(); },
      inFlight || expanded,
    );
    addItem("Investigate fully", () => ask(`investigate ${node.full_name}`));
  }
  addItem("◎ Focus this node's web", () => { cyGraph?.spotlightNode(node.id); closeMenu(); });
  if (node.kind !== "objective") {
    // Open entity page — the same pendingFocus seam ⌘K / the gap-chip use (navigate to /entities focused here).
    addItem("📄 Open entity page", () => { pendingFocusKey = canonKey(node.type || "", node.full_name); navigate("/entities"); closeMenu(); });
  }
  const onElsewhere = (e: MouseEvent) => {
    if (!box.contains(e.target as Node)) { closeMenu(); document.removeEventListener("click", onElsewhere, true); }
  };
  setTimeout(() => document.addEventListener("click", onElsewhere, true), 0);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]!);
}
function msg(e: unknown): string {
  return e instanceof VaultError || e instanceof Error ? e.message : String(e);
}

async function createVaultFlow(password: string) {
  const r = await Vault.create(storage, password);
  applyVault(r.vault);
  return r;
}

// ---- Debug API for the Playwright smoke (deterministic, JSON-serializable) ----
declare global {
  interface Window {
    __kipi: {
      reset(): Promise<void>;
      hasVault(): Promise<boolean>;
      createVault(pw: string, opts?: { onboarded?: boolean; cases?: boolean }): Promise<{ recoveryPhrase: string }>;
      unlock(pw: string): Promise<{ ok: true }>;
      lock(): { ok: true };
      putCase(k: string, v: unknown): Promise<{ ok: true }>;
      getCase(k: string): { value: unknown };
      runPivot(domain: string): Promise<{ succeeded: number; providers: string[]; sample: string[] }>;
      tryBlockedFetch(url: string): Promise<{ blocked: boolean; detail: string }>;
      storageMode(): { mode: string; folderName?: string; conflict?: boolean; needsRegrant?: boolean };
      keyStatus(): { configured: boolean };
      runScriptedInvestigation(
        objective: string,
        turns: unknown[],
      ): Promise<{ stopReason: string; promoted: string[]; leads: string[]; steps: number }>;
      runScriptedBrief(objective: string, briefText: string): Promise<{ brief: string }>;
      listRuns(): { objective: string; stopReason: string; promoted: number; leads: number }[];
      getBrief(objective: string): { brief: string | null };
      graphModel(): GraphModel | null;
      // rsn-run-store: a SAFE summary of the run store — status + COUNTS only, never any entity strings
      // or raw step text (either could carry a secret embedded by a model response; the in-memory result
      // is not secret-redacted, only the persisted record is). Enough for the wipe/reattach/chip smokes.
      runStore(): { status: string; steps: number; findings: number; leads: number };
      runEvents(): RunEventSummary;
      expandNode(nodeId: string, turns: unknown[]): Promise<{ ok: boolean; nodes: number; edges: number }>;
      graphPositions(): Record<string, { x: number; y: number }>;
      cyCounts(): { nodes: number; edges: number };
      graphSelectedSet(): { id: string; name: string }[];
      graphToggleGroupNode(id: string): boolean;
      liveGrowAdds(): number;
      cyViewport(): { zoom: number; pan: { x: number; y: number } } | null;
      cyRenderedPos(id: string): { x: number; y: number } | null;
      cyCenterOn(id: string): void;
      selectNode(id: string): boolean;
      installChatWire(spec: { turns?: unknown[]; qaText?: string; qaTexts?: string[]; dossierText?: string; relationsSmart?: boolean; consolidateText?: string; typeText?: string; schemaText?: string; analyzeText?: string; synthesizeText?: string; groupBriefText?: string }): void;
      qaRequests(): string[];
      cyDimmed(): number;
      analysisRecord(): AnalysisRecord | null;
      entityDb(): EntityStore | null;
      entityView(nodeId: string): EntityView;
      edgeView(srcId: string, dstId: string): EdgeView;
      aiDossier(nodeId: string): Promise<{ dossier: string | null }>;
      semanticRelations(nodeId: string): Promise<{ relations: SemanticRelation[] }>;
      consolidate(): Promise<ConsolidateSuggestion[]>;
      typeEntities(): Promise<TypingSuggestion[]>;
      applyCorrection(type: string, value: string, predicate: string, newValue: string): Promise<{ ok: true }>;
      corrections(): CorrectionRow[];
      runScriptedProxyEnrich(id: string, target: string, response: unknown): Promise<{ count: number; objective: string; requestUrl: string }>;
      clusters(): Cluster[];
      bridges(): Bridge[];
      focus(): Focus;
      crossDomain(): CrossDomainEntity[];
      ingestText(name: string, text: string): Promise<{ count: number; objective: string }>;
      // ocr-smoke (cap-ocr): a debug hook (ships with the __kipi harness, like the rest) that returns
      // the recognized text for an image's bytes via the multilingual OCR path. The smoke needs the raw
      // glyphs because ingestText discards the source text by design. Reads no vault state for input;
      // the saved key is scrubbed from the OUTPUT (the OCR path bypasses ingestText's redaction).
      ocrText(bytes: number[]): Promise<{ text: string }>;
      // en-wire/en-smoke: provider status is read-only (no secret). runScriptedEnrich injects ONLY a
      // canned provider fetch (NO key arg — D4): the smoke saves the key through the real DOM first.
      providerStatus(): ProvidersView;
      runScriptedEnrich(id: string, target: string, response: unknown): Promise<EnrichResult>;
      // a6-smoke: inject a scripted Supabase wire (URL-routed canned responses) so the auth UI drives the
      // REAL identity flow with no network. NO credential args — the smoke types into the real DOM.
      installAuthWire(routes: Record<string, { status?: number; body?: unknown }>): void;
      authMode(): string;
      authRequests(): { endpoint: string; bodyKeys: string[]; hasAuthHeader: boolean }[];
    };
  }
}

const SECRET_DENIED = "secrets are not readable/writable via this hook";
// ca-ui D6: the secret namespace AND the correction/analyst namespaces are never raw-readable/writable via
// the debug hooks (a correction must go through the validated, redacted session path).
function isProtectedKey(k: string): boolean {
  // pf-process: the analysis: record is not raw-forgeable via the debug hooks — it must go through the
  // typed, redacted putAnalysis chokepoint, exactly like a correction.
  return k.startsWith(SECRET_PREFIX) || k.startsWith("correction:") || k.startsWith("setting:") || k.startsWith("report:") || k.startsWith("analysis:"); // rb-ui D2
}

// sec (FAANG): the privileged debug bridge is gated behind a build flag. The smoke build sets
// VITE_KIPI_DEBUG=1 (playwright.config); a stripped prod build omits it, so window.__kipi is ABSENT in
// production — a compromised bundled parser on a hostile upload then has no privileged surface to drive.
if (import.meta.env.VITE_KIPI_DEBUG)
window.__kipi = {
  async reset() {
    await ready;
    vault?.lock();
    applyVault(null);
    await forgetDataKey().catch(() => {}); // stay-signed-in: drop the persisted session key too
    await storage.remove(VAULT_FILE);
    await opfsStorage.remove(VAULT_FILE).catch(() => {});
    await clearHandle();
    backend = opfsBackend();
    storage = backend.storage;
    await render();
  },
  async hasVault() {
    await ready;
    return Vault.exists(storage);
  },
  async createVault(pw, opts) {
    await ready;
    const r = await createVaultFlow(pw);
    // ob-tour: a bridge-created vault represents a PROVISIONED test vault — past first-run onboarding —
    // so the overlay never covers the content for the many smokes that interact with home right after.
    // The onboarding smoke opts into the fresh state with { onboarded: false } to exercise the overlay.
    if (rawVault && opts?.onboarded !== false) await setOnboarded(rawVault);
    // sf-cases: a provisioned test vault also gets a STARTER case, so the many putCase smokes have an active
    // case to write into. The REAL new-user flow (no case → the create-first-case empty state) is opted into
    // with { cases: false }, exercised by its own smoke.
    if (rawVault && opts?.cases !== false) {
      const id = await createCase(rawVault, "Test case");
      await switchCase(id); // activates + re-renders
      return { recoveryPhrase: r.recoveryPhrase };
    }
    await render();
    return { recoveryPhrase: r.recoveryPhrase };
  },
  async unlock(pw) {
    await ready;
    applyVault(await Vault.unlock(storage, pw));
    await render();
    return { ok: true };
  },
  lock() {
    vault?.lock();
    applyVault(null); // sec: clear case-derived state via the chokepoint (codex: lock must route through applyVault)
    void render();
    return { ok: true };
  },
  async putCase(k, v) {
    if (!vault) throw new Error("locked");
    if (isProtectedKey(k)) throw new Error(SECRET_DENIED); // ca-ui D6: corrections/analyst are not raw-forgeable
    await vault.put(k, v);
    return { ok: true };
  },
  getCase(k) {
    if (!vault) throw new Error("locked");
    if (isProtectedKey(k)) throw new Error(SECRET_DENIED); // never expose the key / a correction record raw
    return { value: vault.get(k) };
  },
  // ca-ui: validated correction hooks for the smoke (apply/list go through the session, key-safe).
  async applyCorrection(type, value, predicate, newValue) {
    if (!vault) throw new Error("locked");
    await applyCorrection(vault, type, value, predicate, newValue);
    await afterCorrection();
    return { ok: true };
  },
  // pb-csp-ui: drive a proxied (blocked-provider) enrich with a CANNED worker response (the smoke proves
  // the request goes to the worker ?u= target with no provider key, and the parsed entity gates).
  async runScriptedProxyEnrich(id, target, response) {
    if (!vault) throw new Error("locked");
    const log: string[] = [];
    const fetchImpl = (async (url: string) => {
      log.push(String(url));
      return { ok: true, status: 200, json: async () => response } as Response;
    }) as unknown as FetchLike;
    const r = await enrichViaProxy(vault, id, target, { fetchImpl });
    return { count: r.count, objective: r.objective, requestUrl: log[0] ?? "" };
  },
  corrections() {
    return vault ? listCorrections(vault) : [];
  },
  async runPivot(domain) {
    // wiring-audit (sp-759690a7): the pivot results are returned inline (consumed by the caller +
    // the drawer); they are NOT persisted. The old `vault.put(`pivot:${domain}`, results)` write was
    // dead — grounding reads only run: keys (it EXCLUDES pivot:), the entity DB excludes pivot:, and
    // nothing else read the namespace. Removed the write (and its now-unused case-switch fence).
    const { results, succeeded } = await runPivot(domain);
    return {
      succeeded,
      providers: results.map((r) => r.provider),
      sample: results.flatMap((r) => r.entities.slice(0, 3).map((e) => `${r.provider}:${e.type}:${e.value}`)),
    };
  },
  async tryBlockedFetch(url) {
    // The CSP connect-src allowlist must block this. A block surfaces as a thrown
    // TypeError ("Failed to fetch"); a success means the wall has a hole.
    try {
      await fetch(url, { mode: "no-cors" });
      return { blocked: false, detail: "fetch resolved (CSP did NOT block)" };
    } catch (e) {
      return { blocked: true, detail: msg(e) };
    }
  },
  storageMode() {
    return { mode: backend.mode, folderName: backend.folderName, conflict: backend.conflict, needsRegrant: backend.needsRegrant };
  },
  keyStatus() {
    return { configured: !!vault && hasApiKey(vault) };
  },
  async runScriptedInvestigation(objective, turns) {
    if (!vault) throw new Error("locked");
    if (!hasApiKey(vault)) await setApiKey(vault, "sk-ant-scripted-test"); // dummy only if no real key set
    const result = await startInvestigation(objective, {
      fetchImpl: scriptedFetch(turns),
      toolOpts: { fetchImpl: cannedOsintFetch(), retries: 0 },
    });
    return {
      stopReason: result?.stopReason ?? "none",
      promoted: result?.promoted.map((f) => f.entity) ?? [],
      leads: result?.leads.map((l) => l.finding.entity) ?? [],
      steps: result?.steps.length ?? 0,
    };
  },
  async runScriptedBrief(objective, briefText) {
    if (!vault) throw new Error("locked");
    if (!hasApiKey(vault)) await setApiKey(vault, "sk-ant-scripted-test"); // dummy only if no real key set
    // seed a run with a promoted finding so the brief is not the no-evidence path
    await vault.put(`run:${objective}`, {
      objective,
      steps: [],
      promoted: [{ entity: "live.example.com", entity_type: "domain", grade: "A", infra_source_count: 2, source_count: 2 }],
      leads: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    });
    const brief = await startBrief(objective, scriptedBriefFetch(briefText));
    return { brief: brief ?? "" };
  },
  listRuns() {
    return vault ? listRuns(vault) : [];
  },
  getBrief(objective) {
    return { brief: vault ? getBrief(vault, objective) : null };
  },
  graphModel() {
    return lastGraphModel; // already key-redacted by renderRunGraph -> graphModelForRunNetwork / growCaseNetwork
  },
  runStore() {
    // rsn-run-store: COUNTS only — never entity strings or raw step text. The in-memory run result is not
    // secret-redacted (only the persisted vault record is), so a model-embedded key in an entity value
    // must not egress through this debug hook. Counts are enough for the wipe/reattach/chip smokes.
    const s = getRunStore();
    return { status: s.status, steps: s.steps.length, findings: s.findings.length, leads: s.leads.length };
  },
  runEvents() {
    return runEvents.summary();
  },
  async expandNode(nodeId, turns) {
    if (!vault || !lastGraphModel) throw new Error("no graph");
    const node = lastGraphModel.nodes.find((n) => n.id === nodeId);
    if (!node) return { ok: false, nodes: lastGraphModel.nodes.length, edges: lastGraphModel.edges.length };
    if (!hasApiKey(vault)) await setApiKey(vault, "sk-ant-scripted-test"); // dummy only if no real key
    const ok = await doExpand({ id: node.id, label: node.label, kind: node.kind }, { fetchImpl: scriptedFetch(turns), toolOpts: { fetchImpl: cannedOsintFetch(), retries: 0 } });
    return { ok, nodes: lastGraphModel.nodes.length, edges: lastGraphModel.edges.length };
  },
  graphPositions() {
    return cyGraph ? cyGraph.positions() : {};
  },
  cyCounts() {
    return cyGraph ? cyGraph.counts() : { nodes: 0, edges: 0 };
  },
  graphSelectedSet() {
    return cyGraph ? cyGraph.selectedSet.slice() : []; // multi-select smoke: the current group members
  },
  graphToggleGroupNode(id) {
    return cyGraph ? cyGraph.toggleGroupNode(id) : false; // multi-select smoke: toggle a node in the group by id
  },
  liveGrowAdds() {
    return liveGrowAdds; // kweb-live-graph: live observations that grew the graph during the last run
  },
  cyViewport() {
    return cyGraph ? cyGraph.viewport() : null;
  },
  cyRenderedPos(id) {
    return cyGraph ? cyGraph.renderedPos(id) : null;
  },
  cyCenterOn(id) {
    if (cyGraph) cyGraph.centerOn(id);
  },
  selectNode(id) {
    return cyGraph ? cyGraph.selectById(id) : false;
  },
  // cd-smoke (D1): install a scripted Anthropic wire so the live-streaming proof drives the REAL
  // chat send() -> runInvestigation / answerQuestion loop WITHOUT a key/network. `turns` scripts
  // the tool-use run; `qaText` scripts the no-tools grounded answer.
  installChatWire(spec) {
    qaRequestLog.length = 0; // a fresh wire starts a fresh capture
    chatWire = {
      runFetch: spec.turns ? scriptedFetch(spec.turns) : undefined,
      toolOpts: spec.turns ? { fetchImpl: cannedOsintFetch(), retries: 0 } : undefined,
      // conclusions/follow-up smoke: `qaTexts` scripts SEQUENTIAL grounded answers (first question →
      // texts[0], follow-up → texts[1], …) and every QA request body is captured (qaRequests) so the
      // smoke can assert what actually reached the wire (the synthesis voice, the prior answer).
      qaFetch: Array.isArray(spec.qaTexts)
        ? scriptedSeqQaFetch(spec.qaTexts, qaRequestLog)
        : typeof spec.qaText === "string" ? scriptedBriefFetch(spec.qaText) : undefined,
      // adr-wire: a fixed-text dossier wire + the smart relations wire (reads the prompt cids).
      dossierFetch: typeof spec.dossierText === "string" ? scriptedBriefFetch(spec.dossierText) : undefined,
      relationsFetch: spec.relationsSmart ? scriptedRelationsFetch() : undefined,
      // ct-wire: scripted classify wires for the case-level consolidate/typing passes (same text shape)
      consolidateFetch: typeof spec.consolidateText === "string" ? scriptedBriefFetch(spec.consolidateText) : undefined,
      typeFetch: typeof spec.typeText === "string" ? scriptedBriefFetch(spec.typeText) : undefined,
      // pf-process: scripted understand-pass wire for the Process schema step.
      schemaFetch: typeof spec.schemaText === "string" ? scriptedBriefFetch(spec.schemaText) : undefined,
      // ca-analyze (INC-3): scripted analyze-pass wire for the Process analyze step (clusters + rels).
      analyzeFetch: typeof spec.analyzeText === "string" ? scriptedBriefFetch(spec.analyzeText) : undefined,
      // INC-4b: scripted case-brief wire for the Process synthesize step (dossierFetch above is reused
      // by the dossiers step).
      synthesizeFetch: typeof spec.synthesizeText === "string" ? scriptedBriefFetch(spec.synthesizeText) : undefined,
      // sf-briefs: scripted per-group/standalone summary wire for the Group-related-reports button.
      groupBriefFetch: typeof spec.groupBriefText === "string" ? scriptedBriefFetch(spec.groupBriefText) : undefined,
    };
    consolidateCache.clear();
    typeCache.clear(); // a fresh wire must not read a prior run's cached suggestions
  },
  cyDimmed() {
    return cyGraph ? cyGraph.dimmedCount() : 0;
  },
  // conclusions/follow-up smoke: the captured QA request bodies (see installChatWire.qaTexts).
  qaRequests() {
    return [...qaRequestLog];
  },
  // adr-wire (D5): the AI hooks resolve via the redacted lastGraphModel + REJECT objective/unknown
  // nodes (null/[]); the output is the session-redacted dossier/relations (never the key).
  async aiDossier(nodeId) {
    const n = lastGraphModel?.nodes.find((x) => x.id === nodeId);
    if (!n || n.kind === "objective") return { dossier: null };
    return { dossier: await runAiDossier(n.entityType ?? "", n.label) };
  },
  async semanticRelations(nodeId) {
    const n = lastGraphModel?.nodes.find((x) => x.id === nodeId);
    if (!n || n.kind === "objective") return { relations: [] };
    return { relations: await runSemanticRelations(n.entityType ?? "", n.label) };
  },
  // ct-wire: the case-level consolidate/typing suggestions, read-only + key-redacted (the session hooks
  // redact in + out). They route through the cached runConsolidate/runTypeEntities, so they share the
  // chat-wire seam and never accept an arbitrary fetch from the caller (codex D12).
  async consolidate() {
    return runConsolidate();
  },
  async typeEntities() {
    return runTypeEntities();
  },
  // pf-process: the redacted, validated analysis record (schema + AI role/type overlays) for the live
  // proof — the smoke asserts no key landed in it. Read-only (the record is written only via putAnalysis).
  analysisRecord() {
    return vault ? analysisFor(vault) : null;
  },
  // cl-wire: the serializable, key-redacted clusters (clustersFor reads the redacted entity DB).
  clusters() {
    return vault ? clustersFor(vault, lastGraphModel) : [];
  },
  // sf-bridges: the serializable, key-redacted cross-cluster bridge entities (read-only, no LLM).
  bridges() {
    return vault ? bridgesFor(vault, lastGraphModel) : [];
  },
  // sf-focus: the serializable, key-redacted focus brief (top-N ranked items + deterministic gaps).
  focus() {
    return vault ? focusFor(vault, lastGraphModel) : { items: [], gaps: [] };
  },
  // td-wire: the serializable, key-redacted cross-domain entities (read-only, no LLM).
  crossDomain() {
    return vault ? crossDomainEntities(vault) : [];
  },
  // ig-wire: returns only the redacted {count, objective} (ingestText sanitizes the record) — D13.
  async ingestText(name, text) {
    if (!vault) throw new Error("locked");
    return ingestText(vault, name, text);
  },
  // ocr-smoke (cap-ocr): OCR caller-provided image bytes via fileToText (the multilingual engine), for
  // the smoke to assert non-Latin recognition. No persistence, never wired to the intake UI. It reads no
  // vault SECRET as input, but the OCR path bypasses ingestText's redaction, so the saved Anthropic key
  // is scrubbed from the OUTPUT (belt — matches the leak-safety of the sibling debug hooks).
  async ocrText(bytes) {
    const buf = new Uint8Array(bytes);
    const file = { name: "ocr-probe.png", type: "image/png", arrayBuffer: async () => buf.buffer };
    const { text } = await fileToText(file);
    const key = vault ? getApiKey(vault) : null;
    return { text: key ? text.split(key).join("[REDACTED]") : text };
  },
  // en-wire: read-only provider status (no secret value).
  providerStatus() {
    return vault ? providerStatus(vault) : { providers: [], blocked: [] };
  },
  // en-smoke (D4): inject ONLY a canned provider fetch (no key arg). The smoke saves the key via the
  // real DOM first; enrichTarget reads it from the vault and routes through the SAME gate + write path.
  async runScriptedEnrich(id, target, response) {
    if (!vault) throw new Error("locked");
    return enrichTarget(vault, id, target, { fetchImpl: cannedJsonFetch(response) });
  },
  // a6-smoke (D6): inject a URL-routed scripted Supabase wire (no credential args, retains nothing).
  installAuthWire(routes) {
    authWire = { authFetch: routedFetch(routes) };
  },
  authMode() {
    return authMode;
  },
  authRequests() {
    return authRequests;
  },
  // ed-wire: the entity DB + per-node/edge views for the live proof. All key-redacted
  // (entityDbFor redacts every input), serializable, read-only.
  entityDb() {
    return entityStore();
  },
  entityView(nodeId) {
    const n = lastGraphModel?.nodes.find((x) => x.id === nodeId);
    if (!n) return EMPTY_ENTITY_VIEW;
    return entityViewFor(n.kind, n.entityType ?? "", n.label);
  },
  edgeView(srcId, dstId) {
    return edgeViewFor(srcId, dstId);
  },
};

// conclusions/follow-up smoke: sequential QA answers + request-body capture (see installChatWire).
const qaRequestLog: string[] = [];
function scriptedSeqQaFetch(texts: string[], log: string[]): FetchLike {
  const q = [...texts];
  return (async (_url: string, init: RequestInit) => {
    log.push(String(init?.body ?? ""));
    const text = (q.length > 1 ? q.shift() : q[0]) ?? "";
    return {
      ok: true,
      status: 200,
      json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }),
    };
  }) as unknown as FetchLike;
}

function scriptedBriefFetch(briefText: string): FetchLike {
  return (async () => ({
    ok: true,
    status: 200,
    json: async () => ({ content: [{ type: "text", text: briefText }], stop_reason: "end_turn", usage: {} }),
  })) as unknown as FetchLike;
}

// en-smoke: a canned provider-response fetch (returns the same JSON for any request). The enrich
// adapter parses it exactly as it would a real provider body; no network, no key in the request.
function cannedJsonFetch(response: unknown): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => response })) as unknown as FetchLike;
}

// a6-smoke: a scripted Supabase fetch that routes a canned response by the /auth/v1/* endpoint in the
// URL. The smoke supplies one entry per endpoint it exercises; an entry's status<400 is a success body.
// It RECORDS each request's endpoint + body keys + auth-header presence (NOT values) so the smoke can
// prove the only bodies sent to Supabase are {email,password}/{email} — no case data (codex D7).
interface AuthReqRecord {
  endpoint: string;
  bodyKeys: string[];
  hasAuthHeader: boolean;
}
let authRequests: AuthReqRecord[] = [];

function routedFetch(routes: Record<string, { status?: number; body?: unknown }>): FetchLike {
  authRequests = [];
  return (async (url: string, init?: RequestInit) => {
    const u = String(url);
    const endpoint =
      u.includes("/signup") ? "signup"
      : u.includes("/token") ? "token"
      : u.includes("/user") ? "user"
      : u.includes("/recover") ? "recover"
      : u.includes("/logout") ? "logout"
      : "other";
    let bodyKeys: string[] = [];
    try {
      bodyKeys = init?.body ? Object.keys(JSON.parse(String(init.body))) : [];
    } catch {
      bodyKeys = ["<unparseable>"];
    }
    const headers = (init?.headers as Record<string, string>) ?? {};
    authRequests.push({ endpoint, bodyKeys, hasAuthHeader: !!headers.authorization });
    const r = routes[endpoint] ?? { status: 200, body: {} };
    const status = r.status ?? 200;
    return { ok: status < 400, status, json: async () => r.body ?? {} };
  }) as unknown as FetchLike;
}

// adr-smoke: a relations wire that READS the connection cids out of the prompt body and emits a
// canonical recipe — first cid → hosts/high (KEPT), second cid → same_operator/low (GATE-DROPPED),
// plus a bogus cid → owns/high (VALIDATION-DROPPED) — so the smoke proves the strong-attribution
// gate + the unknown-cid validation without hard-coding the dynamic cids.
function scriptedRelationsFetch(): FetchLike {
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse((init?.body as string) ?? "{}");
    const userMsg = String(body?.messages?.[0]?.content ?? "");
    const cids = [...userMsg.matchAll(/"cid":\s*("(?:[^"\\]|\\.)*")/g)].map((m) => JSON.parse(m[1]));
    const relations: unknown[] = [];
    if (cids[0]) relations.push({ cid: cids[0], rel_type: "hosts", confidence: "high", evidence: "ns record" });
    if (cids[1]) relations.push({ cid: cids[1], rel_type: "same_operator", confidence: "low", evidence: "weak" });
    relations.push({ cid: '["bogus","bogus","bogus","bogus","linked","out"]', rel_type: "owns", confidence: "high" });
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: JSON.stringify({ relations }) }], usage: {} }) };
  }) as unknown as FetchLike;
}

// Scripted wires for the Playwright DOM smoke test (no key, no network). A turn flagged
// `__waitForStop` hangs until the AbortSignal fires, so the Stop button has a deterministic smoke test
// (click Stop -> the in-flight model call rejects -> aborted; smoke test: prominent-stop.spec.ts).
function scriptedFetch(turns: unknown[]): FetchLike {
  const q = [...turns];
  return (async (_url: string, init: RequestInit) => {
    const next = (q.shift() ?? { content: [], stop_reason: "end_turn", usage: {} }) as Record<string, unknown>;
    if (next.__waitForStop) {
      const signal = init?.signal;
      await new Promise<void>((_resolve, reject) => {
        const abort = () => reject(new DOMException("aborted", "AbortError"));
        if (signal?.aborted) return abort();
        signal?.addEventListener("abort", abort, { once: true });
      });
    }
    // cd-smoke (D1): a real inter-turn delay reproduces STREAMING timing — earlier turns' steps
    // render into #trail BEFORE this turn resolves, so the proof can assert incremental arrival.
    if (typeof next.__delayMs === "number") {
      await new Promise<void>((r) => setTimeout(r, next.__delayMs as number));
    }
    return { ok: true, status: 200, json: async () => next };
  }) as unknown as FetchLike;
}
function cannedOsintFetch(): FetchLike {
  return (async (url: string) => {
    const u = String(url);
    if (u.includes("dns.google"))
      return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }) };
    // en-smoke (m3): a canned Shodan host body so a scripted agent run can exercise the enrich_shodan
    // tool with a SUCCESSFUL, gate-faithful result (the keyed tool is reachable in the loop). It
    // MALICIOUSLY echoes the smoke's saved Shodan key in a domain value AND the asn note (the literal
    // is shared with tests/smoke/agent-enrich.spec.ts) so the smoke proves the AGENT path redacts a
    // provider key both in-flight (the tool step / model message) and at rest (the persisted record +
    // the graph). api.shodan.io is already in the CSP connect-src — no new origin. The clean
    // good.example.com hostname is the gate-faithful entity that lands.
    if (u.includes("api.shodan.io"))
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ip_str: "8.8.8.8",
          hostnames: ["good.example.com"],
          domains: ["evil-shdnagentecho7777.com"],
          asn: "AS15169",
          org: "shdnagentecho7777",
        }),
      };
    // oc-smoke: a canned ENS resolution so a scripted agent run can exercise the keyless ens_name
    // on-chain tool — vitalik.eth resolves to its 0x wallet, the gate-faithful entity that lands.
    // api.ensideas.com is in the CSP connect-src (PRD-onchain) — no new origin.
    if (u.includes("api.ensideas.com"))
      return {
        ok: true,
        status: 200,
        json: async () => ({ address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", name: "vitalik.eth" }),
      };
    return { ok: false, status: 404, json: async () => ({}) };
  }) as unknown as FetchLike;
}

// Re-render on hash navigation (sidebar clicks). When locked, render() ignores the route
// and shows create/unlock, so a stray hash never bypasses the lock.
window.addEventListener("hashchange", () => void render());

// sec (FAANG MED): unload zeroing — drop the in-memory data key when the tab goes away (pagehide fires
// on close/navigate-away/bfcache, more reliable than beforeunload). Route through applyVault(null) so the
// chokepoint ALSO clears the decrypted graph/case state (codex: lock() alone leaves lastGraphModel + the
// DOM, which a bfcache restore would re-show without a re-unlock). Best-effort; the vault file persists.
window.addEventListener("pagehide", () => {
  vault?.lock();
  applyVault(null);
});
// sec (codex): on a bfcache RESTORE the frozen DOM could still show the prior decrypted graph — re-render
// so the restored page shows the (locked) login gate, never stale decrypted content.
window.addEventListener("pageshow", (e) => {
  if (!e.persisted) return;
  void render(); // sec: paint the LOCKED shell synchronously first (pagehide set vault=null) so the frozen
  void bootstrapSession().then(render); // bfcache DOM never flashes stale decrypted content while restore awaits
});

// sec (FAANG MED): idle auto-lock — after IDLE_LOCK_MS of no pointer/key activity, lock the vault so a
// decrypted vault does not live in memory unattended. Armed only while unlocked (via applyVault →
// armIdleLock); reset on activity. Generous default so it never interrupts active work.
// stay-signed-in (clu-auth): a generous idle window — usability over hardening on a single-user, own-
// machine tool (founder decision). The idle-lock only drops the in-memory key; the persisted session
// key means a reload restores seamlessly. Sign out is the real lock.
const IDLE_LOCK_MS = 8 * 60 * 60 * 1000;
let idleTimer: ReturnType<typeof setTimeout> | null = null;
function armIdleLock(): void {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
  if (vault) idleTimer = setTimeout(() => { if (vault) lockVault(); }, IDLE_LOCK_MS);
}
window.addEventListener("pointerdown", armIdleLock);
window.addEventListener("keydown", armIdleLock);

void ready.then(bootstrapSession).then(render); // stay-signed-in: restore a persisted session before first paint
wireBugReportLink(); // rel-bug: upgrade the static sidebar "Report a bug" mailto to the templated one
wireCmdkSearch(); // kk-search: attach the ⌘K input listener once (the #cmdk-input shell is static)
wireChromeBack(); // back-fix: attach the chrome Back listener once (inline onclick is dead under CSP)
void loadGithubStars(); // gh-stars: fill the top-strip star count from the public repo (fails silently)
registerServiceWorker(); // rel-pwa: install the network-first SW (PROD) + the opt-in update bar
