// The left-nav pages. The home route ("/") is the graph+chat split-view (app.ts);
// these are the OTHER nav destinations, so every sidebar item navigates to a REAL
// built page — never a dead href="#" (the built-not-wired scar). Pages that have
// client data (Entities, Runs & findings, Deliverables, Cross-case) render it live
// from the vault + the entity DB; pages that still need server/enrich infra
// (Reports & intake, Enrich, Inbox, Cross-domain) are HONEST built pages that explain
// what they need + point to the working path — not fake data, not dead buttons.
//
// All DOM is createElement + textContent (a hostile entity value is literal text).
// Key hygiene: pages read ONLY through the session accessors (entityDbFor / listRuns /
// listBriefs / getBrief / runEntities), which redact the live key before the data ever
// reaches here.

import type { Vault } from "./vault/vault.js";
import { entityDbFor, listRuns, listBriefs, getBrief, CASE_BRIEF_KEY, listGroupBriefs, runEntities, runDetail, listIngestedDocs, sourcesFor, reportDetailFor, type CrossDomainEntity, type Bridge, type Focus, type FocusItem, type FocusGap, type IngestResult, type ProvidersView, type EnrichResult, type EnrichStats, type EnrichRunRow, type EnrichRunDetail, type CorrectionRow, type ReportDetailEntity, type IngestedDoc, type SourceDoc, type Alert, type RunEntity, type ProcessStepStatus, type EntityScoreBreakdown, type EntityTypedRel, type EntityAppearance, type EntityDossierOverride, type ActivityItem, type ReportModel, type CaseInfo } from "./agent/session.js";
import type { ExportFiles } from "./export/intel.js";
import { mapOsintError } from "./chat/errors.js"; // clu-error-output: OSINT failures → guidance strings
import { CONSOLIDATE_ROLES, SURFACE_TYPES } from "./entity/consolidate.js";
import type { DisplayStep, AttributedEntity, DiscoveredAsset, Pivot } from "./agent/runtrail.js";
import {
  allEntities,
  crossRunEntities,
  connectionsFor,
  buildDossier,
  aliasLinksFor,
  entityKey,
  type EntityRecord,
  type Connection,
} from "./entity/db.js";
import { connId, type SemanticRelation } from "./entity/relations.js";
import type { ConsolidateSuggestion, TypingSuggestion } from "./entity/consolidate.js";
import type { Cluster } from "./entity/clusters.js";
import type { CaseSchema } from "./entity/analysis.js";
import { renderMarkdown, renderBriefMarkdown } from "./chat/markdown.js";
import { OSINT_CAPABILITIES, capabilityCounts, CAP_ACCESS_LABEL, CAP_ACCESS_HINT, CAP_BYO_NOTE, type CapAccess } from "./osint/catalog.js";
import { FULL_TOOL_CAPABILITIES, FULL_TOOL_NOTE, fullToolCount } from "./osint/fulltool-catalog.js";
import { toolInventory, toolInventoryCounts } from "./osint/tool-inventory.js";
import type { WorkerProbe } from "./osint/proxy.js";

export interface PageDeps {
  vault: Vault;
  navigate(route: string): void;
  download(name: string, bytes: Uint8Array): void;
  // adr-wire D6: the AI passes are async deps supplied by app.ts (which owns the vault + the
  // scripted-wire seam). pages.ts NEVER constructs an AnthropicClient or reads the key.
  aiDossier(type: string, value: string): Promise<string | null>;
  semanticRelations(type: string, value: string): Promise<SemanticRelation[]>;
  // ct-wire: case-level consolidate (merge + role) + typing (surface re-type) AI suggestions — READ
  // projections supplied by app.ts (current=lastGraphModel, key-redacted, cached). pages.ts only renders.
  consolidateEntities(): Promise<ConsolidateSuggestion[]>;
  typeEntities(): Promise<TypingSuggestion[]>;
  // kk-search D11: the entity (canonical key) a search result asked to focus; consumed once per render.
  takePendingFocus(): string | null;
  // ca-ui: analyst corrections (the top-authority write). The app applies + re-renders.
  applyCorrection(type: string, value: string, predicate: string, newValue: string): Promise<void>;
  listCorrections(): CorrectionRow[];
  revertCorrection(canonicalKey: string, predicate: string): Promise<void>;
  getAnalyst(): string;
  setAnalyst(name: string): Promise<void>;
  // sf-activity: the "who did what, when" feed — a key-redacted projection over the timestamped retained
  // records (corrections/dossier/notes/uploads/process/enrich/group-briefs), supplied by app.ts (key-safe).
  activity(): ActivityItem[];
  // sf-cases: the multi-case switcher — list/create/select cases (app.ts owns the GLOBAL setting: writes +
  // the in-memory clear + re-render on switch). Key-safe (case names redacted at the session layer).
  cases(): CaseInfo[];
  createCase(name: string): Promise<void>;
  switchCase(id: string): Promise<void>;
  // sf-cases delete: per-case data counts for the confirm dialog, then the irreversible delete (app.ts
  // auto-switches off the active case — to another case, or the empty state — first, drops the `case:<id>:`
  // namespace, re-renders). Every case is deletable (no implicit default).
  caseCounts(id: string): { runs: number; entities: number };
  deleteCase(id: string): Promise<void>;
  // sf-exports: the downstream-tool export files (STIX 2.1 / MISP / 3 CSVs), serialized from the redacted
  // model, supplied by app.ts (key-safe). The page downloads them in-browser via d.download.
  exports(): ExportFiles;
  // sf-report-builder: the branded-report data model (brief / actors / dossiers / iocs / sources),
  // key-redacted, supplied by app.ts. The /report page renders it into the print-ready deliverable.
  reportModel(): ReportModel;
  // clu-auto-report: persist the analyst's exec-summary edit (top authority) / re-render (drop the edit,
  // revert to current state). app.ts owns the vault + redaction; the page never touches the key.
  saveReportSummary(text: string): Promise<void>;
  clearReportSummary(): Promise<void>;
  // rb-ui: alerts (priority projection) + per-report notes — supplied by app.ts (key-safe).
  alerts(): Alert[];
  // sf-alerts: the acknowledge write-path (single-writer alert:<id>:ack), supplied by app.ts (key-safe).
  acknowledgeAlert(id: string): Promise<void>;
  acknowledgeAllAlerts(ids: string[]): Promise<void>;
  reportEntities(objective: string): RunEntity[];
  getReportNotes(objective: string): string;
  setReportNotes(objective: string, text: string): Promise<void>;
  // sf-entity-detail: the per-entity DETAIL fold projections (the entity.html depth) — supplied by app.ts
  // (which owns the vault); pages.ts only renders. All READ-ONLY + key-redacted at the session layer,
  // except the editable dossier override (the ONE same-class persisted key, mirroring setReportNotes).
  entityScore(e: EntityRecord): EntityScoreBreakdown | null; // §1+2 score header + breakdown (total == stored)
  typedRelationships(canonicalKey: string): EntityTypedRel[]; // §7 always-shown typed rels
  entityCorrections(canonicalKey: string): CorrectionRow[]; // §4 per-entity corrections-audit slice
  entityAppearances(e: EntityRecord): EntityAppearance[]; // §8 appears-in report list + gate counts
  getDossierOverride(e: EntityRecord): EntityDossierOverride | null; // §6 editable override (separate from AI)
  setDossierOverride(e: EntityRecord, text: string): Promise<void>; // §6 single-writer save (blank = revert)
  // cl-wire D2: clusters supplied by app.ts (so the page sees lastGraphModel's expansion entities).
  clusters(): Cluster[];
  // sf-bridges: cross-cluster bridge entities (spanning >= 2 analyze-clusters), supplied by app.ts.
  bridges(): Bridge[];
  // sf-focus: "where to look first" — the top-N threat-ranked items + the deterministic gaps, supplied
  // by app.ts (key-redacted at the session layer, no LLM). pages.ts only renders. focusEntity navigates
  // to /entities and focuses the entity (the ⌘K pendingFocus seam — the original's /entity/{id} link).
  focus(): Focus;
  focusEntity(ref: { type: string; value: string }): void;
  // ux-rowmenu (item 4): the /entities row ⋯ menu seams. openInGraph → home + focus the node;
  // enrichEntity → /enrich with the entity prefilled; takePendingEnrich is consumed by renderEntityEnrich.
  openInGraph(e: EntityRecord): void;
  enrichEntity(value: string): void;
  takePendingEnrich(): string | null;
  // td-wire: cross-domain entities (bridging >= 2 investigation types), supplied by app.ts.
  crossDomain(): CrossDomainEntity[];
  // sf-deliverables: regenerate the case brief (single-writer synthesizeCaseBrief, offline-seamed in app.ts)
  // + the stale-banner inputs (builtOn vs live run count). pages.ts never touches the vault/key.
  synthesize(): Promise<string>;
  briefStale(objective: string): { builtOn: number; live: number } | null;
  // sf-briefs: run the grouped-relatedness engine + per-group LLM summaries (app.ts owns the vault +
  // the offline fetch seam). The /briefs viewer reads the persisted records via listGroupBriefs(vault).
  groupBriefs(): Promise<{ groups: number; standalone: number }>;
  // ig-wire: file/text ingestion supplied by app.ts (which owns the vault + the file→text layer).
  ingest(name: string, text: string): Promise<IngestResult>;
  ingestFile(file: File): Promise<IngestResult>;
  // en-wire: enrich providers supplied by app.ts (which owns the vault + the secret: namespace).
  // pages.ts NEVER reads or writes a key directly — it only calls these.
  providers(): ProvidersView;
  saveProviderKey(id: string, key: string): Promise<void>;
  clearProviderKey(id: string): Promise<void>;
  testProvider(id: string): Promise<{ ok: boolean; detail: string }>;
  enrich(id: string, target: string): Promise<EnrichResult>;
  enrichStats(): EnrichStats;
  listEnrichRuns(): EnrichRunRow[];
  getEnrichRunDetail(objective: string): EnrichRunDetail | null;
  // pb-csp-ui: the user-proxy tier (the CORS-blocked providers via the user's own Cloudflare Worker).
  workerUrl(): string | null;
  saveWorkerUrl(url: string): Promise<void>;
  enrichViaProxy(id: string, target: string): Promise<EnrichResult>;
  // hydra-see-sites: probe the saved Worker for the "Test connection" button (reachable? Browser Rendering on?).
  testWorkerProxy(): Promise<WorkerProbe>;
  // pf-process (INC-1): the Process pipeline panel on /reports. app.ts owns the runner + the app-level
  // job state (the source of truth, PRD D8); pages.ts only renders it + subscribes to live updates.
  processState(): ProcessUiState;
  subscribeProcess(fn: (s: ProcessUiState) => void): void;
  startProcess(): Promise<void>;
  abortProcess(): void;
  schemaSummary(): string | null; // the auto-modeled schema, one-line ("<domain> · N roles") or null
  schemaDetail(): CaseSchema | null; // the FULL modeled schema (roles, entity types, sub-roles, noise)
}

// pf-process: the Process panel's view model — app.ts aggregates runProcess's onStep/onLog callbacks
// into this state and pushes it to the subscribed panel; the panel paints from it (no DOM-local truth).
export interface ProcessUiStep {
  key: string;
  label: string;
  status: ProcessStepStatus;
}
export interface ProcessUiState {
  status: "idle" | "running" | "done" | "error";
  steps: ProcessUiStep[];
  log: string[];
  error?: string;
}

const BRIEF_CAP = 256 * 1024;

// ---- small DOM helpers ----

function elt(tag: string, cls?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
function chip(text: string, kind = ""): HTMLElement {
  return elt("span", `pg-chip ${kind}`.trim(), text);
}
function pageShell(title: string, subtitle: string): { page: HTMLElement; body: HTMLElement } {
  const page = elt("section", "pg");
  const head = elt("div", "pg-head");
  head.appendChild(elt("h1", "pg-title", title));
  head.appendChild(elt("p", "pg-sub", subtitle));
  page.appendChild(head);
  const body = elt("div", "pg-body");
  page.appendChild(body);
  return { page, body };
}
function emptyNote(body: HTMLElement, text: string): void {
  body.appendChild(elt("p", "pg-empty", text));
}

// ---- Entities page ----

export function renderEntitiesPage(d: PageDeps): HTMLElement {
  const store = entityDbFor(d.vault, null);
  const entities = allEntities(store);
  const { page, body } = pageShell("Entities", `${entities.length} entit${entities.length === 1 ? "y" : "ies"} across all runs`);
  if (!entities.length) {
    emptyNote(body, "No entities yet. Run an investigation in the Workspace to populate the entity DB.");
    return page;
  }
  renderConsolidateAffordance(d, body);
  // ux (brief §Entities #4): a one-line legend so the row chips aren't unexplained scoring vocab.
  body.appendChild(elt("p", "ent-legend", "promoted = passed the evidence gate · lead = held for corroboration · grade A→D = corroboration strength"));
  const rows: HTMLElement[] = [];
  for (const e of entities) {
    const row = entityRow(d, store, e);
    row.dataset.entityKey = JSON.stringify([e.ref.type, e.ref.value]); // kk-search D11: stable focus key
    rows.push(row);
    body.appendChild(row);
  }
  // kk-search D11: a search-result click left a pending entity to focus — find its row by data-entity-key
  // (NO querySelector, so a value with quotes/special chars never breaks) and expand + scroll it AFTER the
  // router has appended the page (requestAnimationFrame).
  const focusKey = d.takePendingFocus();
  if (focusKey) {
    requestAnimationFrame(() => {
      const target = rows.find((r) => r.dataset.entityKey === focusKey);
      if (target) {
        (target.querySelector(".ent-top") as HTMLElement | null)?.click();
        target.scrollIntoView({ block: "center" });
      }
    });
  }
  return page;
}

// ct-wire: the case-level AI passes (consolidate merge+role / typing surface re-type). They are
// SUGGESTIONS, NOT applied (codex D11) — the apply path is the analyst-authority surface (item 5).
// Every value reaches the DOM via elt() (textContent), so a model-controlled reason/label is literal
// text, never markup (codex D7). Buttons disable while a call is in flight (codex D9); the cache lives
// in app.ts (keyed by an entity-DB digest) so a repeat click on an unchanged case does not re-spend.
function renderConsolidateAffordance(d: PageDeps, body: HTMLElement): void {
  const sec = elt("div", "ent-consolidate");
  sec.appendChild(elt("div", "ent-ai-label", "AI suggestions — not applied (model-written · uses your key)"));
  const consBtn = elt("button", "pg-btn", "Consolidate (AI)") as HTMLButtonElement;
  const typeBtn = elt("button", "pg-btn", "Refine types (AI)") as HTMLButtonElement;
  sec.appendChild(consBtn);
  sec.appendChild(typeBtn);
  const out = elt("div", "ent-consolidate-out");
  sec.appendChild(out);
  body.appendChild(sec);

  consBtn.addEventListener("click", async () => {
    if (consBtn.disabled) return;
    consBtn.disabled = true; // D9
    consBtn.textContent = "Consolidating…";
    try {
      const sugs = await d.consolidateEntities();
      out.querySelector(".cons-merges")?.remove();
      out.appendChild(renderMergeSuggestions(sugs, d));
    } catch (err) {
      out.appendChild(elt("div", "ent-ai-err", err instanceof Error ? err.message : String(err)));
    } finally {
      consBtn.textContent = "Consolidate (AI)";
      consBtn.disabled = false;
    }
  });

  typeBtn.addEventListener("click", async () => {
    if (typeBtn.disabled) return;
    typeBtn.disabled = true;
    typeBtn.textContent = "Refining…";
    try {
      const sugs = await d.typeEntities();
      out.querySelector(".cons-types")?.remove();
      out.appendChild(renderTypeSuggestions(sugs, d));
    } catch (err) {
      out.appendChild(elt("div", "ent-ai-err", err instanceof Error ? err.message : String(err)));
    } finally {
      typeBtn.textContent = "Refine types (AI)";
      typeBtn.disabled = false;
    }
  });
}

function applyBtn(label: string, fn: () => Promise<void>): HTMLButtonElement {
  const b = elt("button", "pg-btn cons-apply", label) as HTMLButtonElement;
  b.addEventListener("click", async () => {
    if (b.disabled) return;
    b.disabled = true;
    b.textContent = "Applying…";
    try {
      await fn(); // ca-ui: the app applies the correction + re-renders the page (D11)
    } catch (err) {
      b.textContent = err instanceof Error ? err.message : "failed";
      b.disabled = false;
    }
  });
  return b;
}

function renderMergeSuggestions(sugs: ConsolidateSuggestion[], d: PageDeps): HTMLElement {
  const wrap = elt("div", "cons-merges");
  wrap.appendChild(elt("div", "ent-ai-tag", `Merge suggestions (${sugs.length}) — AI, not applied`));
  if (!sugs.length) {
    wrap.appendChild(elt("div", "ent-conn", "No merge suggestions for this case."));
    return wrap;
  }
  for (const s of sugs) {
    const card = elt("div", "cons-card");
    card.appendChild(elt("div", "cons-role", `suggested equivalence · role ${s.role} · ${s.confidence}`)); // D3/D7 textContent
    for (const m of s.members) card.appendChild(elt("div", "cons-member", `${m.label} · ${m.promoted ? "promoted" : "lead"}`));
    if (s.reason) card.appendChild(elt("div", "cons-reason", s.reason)); // D7: model reason is literal text
    // ca-ui: applying a group's ROLE writes a role correction for EACH member (analyst authority).
    card.appendChild(
      applyBtn(`Apply role ${s.role}`, async () => {
        for (const m of s.members) await d.applyCorrection(m.ref.type, m.ref.value, "role", s.role);
      }),
    );
    wrap.appendChild(card);
  }
  return wrap;
}

function renderTypeSuggestions(sugs: TypingSuggestion[], d: PageDeps): HTMLElement {
  const wrap = elt("div", "cons-types");
  wrap.appendChild(elt("div", "ent-ai-tag", `Type suggestions (${sugs.length}) — AI, not applied`));
  if (!sugs.length) {
    wrap.appendChild(elt("div", "ent-conn", "No type suggestions for this case."));
    return wrap;
  }
  for (const s of sugs) {
    const card = elt("div", "cons-card");
    card.appendChild(elt("div", "cons-type", `${s.label}: ${s.fromType} → ${s.toType} · ${s.confidence}`)); // D7 textContent
    if (s.reason) card.appendChild(elt("div", "cons-reason", s.reason));
    card.appendChild(applyBtn(`Apply type ${s.toType}`, () => d.applyCorrection(s.ref.type, s.ref.value, "type", s.toType)));
    wrap.appendChild(card);
  }
  return wrap;
}

function entityRow(d: PageDeps, store: ReturnType<typeof entityDbFor>, e: EntityRecord): HTMLElement {
  const row = elt("div", "ent-row");
  const head = elt("div", "ent-rowhead"); // ux-rowmenu: holds the expand button + the ⋯ actions menu
  const top = elt("button", "ent-top");
  top.appendChild(elt("span", "ent-name", e.label));
  const meta = elt("span", "ent-meta");
  meta.appendChild(chip(e.type || e.role));
  meta.appendChild(chip(e.promoted ? "promoted" : "lead", e.promoted ? "ok" : "warn"));
  if (e.grade) meta.appendChild(chip(`grade ${e.grade}`));
  meta.appendChild(chip(`${e.runs.length} run(s)`));
  top.appendChild(meta);

  const detail = elt("div", "ent-detail");
  detail.hidden = true;
  let built = false;
  const ensureBuilt = (): void => {
    if (!built) { buildEntityDetail(d, detail, store, e); built = true; }
  };
  top.addEventListener("click", () => { ensureBuilt(); detail.hidden = !detail.hidden; });

  head.appendChild(top);
  head.appendChild(entityRowMenu(d, e, () => {
    // "Override role": expand the fold + scroll to its assert/override form (.ent-assert).
    ensureBuilt();
    detail.hidden = false;
    requestAnimationFrame(() => detail.querySelector(".ent-assert")?.scrollIntoView({ behavior: "smooth", block: "center" }));
  }));
  row.appendChild(head);
  row.appendChild(detail);
  return row;
}

// ux-rowmenu (item 4): registry of every OPEN row menu's close()-er, so opening one menu cleanly closes
// the others — and EVERY close path (item click, toggle-off, outside-click, Escape, another menu opening)
// runs the same close() that removes the document listeners (codex: no leaked listeners retaining
// torn-down row DOM after a re-render/navigation).
const openEntityMenus = new Set<() => void>();
// Exported so app.ts render() can close any open row menu BEFORE it tears down the page DOM
// (root().innerHTML=""). The in-component close paths cover click/Escape/outside-click/other-menu, but a
// non-click teardown (back/forward, idle auto-lock, bfcache) would otherwise leak the document listeners.
export function closeAllEntityMenus(): void {
  for (const closeOne of [...openEntityMenus]) closeOne();
}

// The per-row ⋯ actions menu — Open in graph / Enrich / Override role. A small DOM popover (no Alpine).
// stopPropagation keeps a menu click from toggling the row's expand button (its sibling).
function entityRowMenu(d: PageDeps, e: EntityRecord, onOverrideRole: () => void): HTMLElement {
  const wrap = elt("div", "ent-menu-wrap");
  const btn = elt("button", "ent-menu-btn") as HTMLButtonElement;
  btn.type = "button";
  btn.setAttribute("aria-label", "Entity actions");
  btn.setAttribute("aria-haspopup", "true");
  btn.textContent = "⋯";
  const pop = elt("div", "ent-menu-pop");
  pop.hidden = true;

  let onDoc: ((e2: Event) => void) | null = null;
  let onEsc: ((e2: KeyboardEvent) => void) | null = null;
  // close() is the SINGLE teardown: it removes both document listeners + deregisters, so no path leaks them.
  const close = (): void => {
    pop.hidden = true;
    btn.setAttribute("aria-expanded", "false");
    if (onDoc) { document.removeEventListener("click", onDoc); onDoc = null; }
    if (onEsc) { document.removeEventListener("keydown", onEsc); onEsc = null; }
    openEntityMenus.delete(close);
  };
  const item = (label: string, fn: () => void): HTMLButtonElement => {
    const b = elt("button", "ent-menu-item") as HTMLButtonElement;
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", (ev) => { ev.stopPropagation(); close(); fn(); });
    return b;
  };
  pop.appendChild(item("Open in graph", () => d.openInGraph(e)));
  pop.appendChild(item("Enrich", () => d.enrichEntity(e.ref.value)));
  pop.appendChild(item("Override role", onOverrideRole));

  btn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const willOpen = pop.hidden;
    closeAllEntityMenus(); // close every open menu (each via its own close() → listeners removed)
    if (!willOpen) return; // it was open; closeAll already closed it
    pop.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    onDoc = (e2: Event): void => { if (!wrap.contains(e2.target as Node)) close(); };
    onEsc = (e2: KeyboardEvent): void => { if (e2.key === "Escape") close(); };
    setTimeout(() => { document.addEventListener("click", onDoc!); document.addEventListener("keydown", onEsc!); }, 0);
    openEntityMenus.add(close);
  });
  wrap.appendChild(btn);
  wrap.appendChild(pop);
  return wrap;
}

// sf-entity-detail: the per-entity DETAIL fold — rendered to the SAME depth as the original
// /entity/{id} (entity.html) across SIX sections (§1+2 score header + breakdown, §3 assert form, §4
// corrections-audit slice, §7 typed relationships, §8 appears-in list, §6 editable dossier override),
// PLUS the derived dossier/connections/aliases that were already here. The drawer mirrors §1+2/§7/§8
// (dock.ts) so both folds reach the same depth (the built-not-wired scar).
function buildEntityDetail(d: PageDeps, detail: HTMLElement, store: ReturnType<typeof entityDbFor>, e: EntityRecord): void {
  renderScoreHeader(d, detail, e); // §1+2 attention score + collapsible breakdown
  const dossier = buildDossier(store, e.type, e.ref.value);
  if (dossier) {
    detail.appendChild(elt("div", "ent-dossier-head", `${dossier.headline} · Derived`));
    for (const line of dossier.lines) detail.appendChild(elt("div", "ent-dossier-line", line));
  }
  renderEntityDossierOverride(d, detail, e); // §6 editable analyst dossier (separate from the AI dossier)
  renderAssertForm(d, detail, e); // §3 assert {role,type} — the analyst top authority
  renderEntityCorrections(d, detail, e); // §4 per-entity corrections-audit slice + revert
  const conns = connectionsFor(store, e.type, e.ref.value);
  renderTypedRelationships(d, detail, e); // §7 always-shown typed relationships (clickable)
  detail.appendChild(elt("div", "ent-conns-head", `Derived connections (${conns.length})`)); // D9
  for (const c of conns.slice(0, 40)) detail.appendChild(connectionRow(c));
  // ca-correlate (INC-2): alias "also known as" links from the correlate pass (auto_link_aliases
  // port — person/person_candidate names with >= 0.8 token overlap). aliasLinksFor memoizes per
  // store, so this is free after the first entity expanded on the page.
  const aliases = aliasLinksFor(store)[entityKey(e.ref)] ?? [];
  if (aliases.length) {
    detail.appendChild(elt("div", "ent-aka-head", `Also known as (${aliases.length})`));
    const list = elt("div", "ent-aka-list");
    for (const name of aliases) list.appendChild(elt("span", "ent-aka", name)); // textContent — literal
    detail.appendChild(list);
  }
  renderEntityAppearances(d, detail, e); // §8 appears-in report list + gate counts
  renderEntityAiAffordances(d, detail, e, conns);
}

// §1+2: the attention score header + a collapsible breakdown whose total ALWAYS equals the stored
// threatScore (prop = the exact residual). All values reach the DOM via textContent (elt). No score yet
// (un-Processed) → a quiet hint, never a fake zero.
function renderScoreHeader(d: PageDeps, detail: HTMLElement, e: EntityRecord): void {
  const b = d.entityScore(e);
  const sec = elt("div", "ent-score");
  if (!b) {
    sec.appendChild(elt("div", "ent-score-none", "No attention score yet — run Process to score the case."));
    detail.appendChild(sec);
    return;
  }
  const head = elt("div", "ent-score-head");
  head.appendChild(elt("span", "ent-score-label", "attention score"));
  head.appendChild(elt("span", "ent-score-value", String(b.total)));
  head.appendChild(elt("span", "ent-score-sub", `degree ${b.degree} · ${b.reportCount} reports`));
  sec.appendChild(head);

  const det = elt("details", "ent-score-breakdown") as HTMLDetailsElement;
  const sum = elt("summary", "ent-score-summary", "Score breakdown");
  det.appendChild(sum);
  const table = elt("div", "ent-score-table");
  const row = (label: string, detail: string, pts: number): void => {
    const r = elt("div", "ent-score-row");
    r.appendChild(elt("span", "ent-score-rowlabel", label));
    r.appendChild(elt("span", "ent-score-rowdetail", detail));
    r.appendChild(elt("span", "ent-score-rowpts", pts >= 0 ? `+${pts}` : String(pts)));
    table.appendChild(r);
  };
  row("role × 10", `${b.role || "—"} (weight ${b.roleWeight})`, b.rolePts);
  row("reports × 5", `${b.reportCount} distinct reports`, b.reportPts);
  row("degree × 1", `${b.degree} typed relationships`, b.degreePts);
  if (b.priorPts) row("seed × 30", "promoted (prior weight 1.0)", b.priorPts);
  if (b.propPts) row("propagation", "neighbor-of-seed (residual)", b.propPts);
  const total = elt("div", "ent-score-row ent-score-total");
  total.appendChild(elt("span", "ent-score-rowlabel", "total"));
  total.appendChild(elt("span", "ent-score-rowdetail", ""));
  total.appendChild(elt("span", "ent-score-rowpts", String(b.total)));
  table.appendChild(total);
  det.appendChild(table);

  // §1+2 centrality metrics (INC-4a graph_metrics) — shown inside the breakdown when present.
  if (b.metrics) {
    const m = b.metrics;
    const metrics = elt("div", "ent-score-metrics");
    metrics.appendChild(elt("span", "ent-metric", `degree centrality ${m.degreeCentrality.toFixed(3)}`));
    metrics.appendChild(elt("span", "ent-metric", `betweenness ${m.betweenness.toFixed(3)}`));
    metrics.appendChild(elt("span", "ent-metric", `eigenvector ${m.eigenvector.toFixed(3)}`));
    metrics.appendChild(elt("span", "ent-metric", `community ${m.community}`));
    // PRD-B graph-path-confidence: the strength of this node's attribution chain back to a case seed (shown
    // only when it has a path — an unreachable node is unscored, not 0).
    if (typeof m.pathConfidence === "number") {
      metrics.appendChild(elt("span", "ent-metric", `path confidence ${m.pathConfidence.toFixed(3)}`));
    }
    det.appendChild(metrics);
  }
  det.appendChild(
    elt("div", "ent-score-formula", "role×10 + reports×5 + degree×1 + seed×30 + propagation — a rank-by-attention signal, not a maliciousness rating."),
  );
  sec.appendChild(det);
  detail.appendChild(sec);
}

// §3: the analyst ASSERT form — the analyst is the top authority, not just an approver. A field select
// {role,type} + a value-select bound to the predicate's allowlist (CONSOLIDATE_ROLES / SURFACE_TYPES) +
// Set → applyCorrection. Extends the old role-only override with the `type` predicate.
function renderAssertForm(d: PageDeps, detail: HTMLElement, e: EntityRecord): void {
  const sec = elt("div", "ent-assert");
  sec.appendChild(elt("div", "ent-assert-head", "Your call — assert a value (overrides the report everywhere)"));
  sec.appendChild(elt("span", "ent-assert-current", `role: ${e.role} · type: ${e.type}`));

  const fieldSel = elt("select", "ent-assert-field") as HTMLSelectElement;
  for (const f of ["role", "type"]) {
    const opt = document.createElement("option");
    opt.value = f;
    opt.textContent = f;
    fieldSel.appendChild(opt);
  }
  sec.appendChild(fieldSel);

  const valueSel = elt("select", "ent-assert-value") as HTMLSelectElement;
  const fillValues = (predicate: string): void => {
    valueSel.replaceChildren();
    const allow: readonly string[] = predicate === "role" ? CONSOLIDATE_ROLES : SURFACE_TYPES;
    const current = predicate === "role" ? e.role : e.type;
    for (const v of allow) {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      if (v === current) opt.selected = true;
      valueSel.appendChild(opt);
    }
  };
  fillValues("role");
  fieldSel.addEventListener("change", () => fillValues(fieldSel.value));
  sec.appendChild(valueSel);

  sec.appendChild(
    applyBtn("Set", () => d.applyCorrection(e.ref.type, e.ref.value, fieldSel.value, valueSel.value)),
  );
  detail.appendChild(sec);
}

// §4: the per-entity corrections-audit slice — the ACTIVE analyst overrides on THIS entity (predicate →
// value, by author) + a revert affordance. Mirrors the Corrections-page rows, filtered to this entity.
function renderEntityCorrections(d: PageDeps, detail: HTMLElement, e: EntityRecord): void {
  const rows = d.entityCorrections(entityKey(e.ref));
  if (!rows.length) return; // no overrides → nothing to audit (the assert form is the entry point)
  const sec = elt("div", "ent-corr");
  sec.appendChild(elt("div", "ent-corr-head", `Active overrides (${rows.length})`));
  for (const r of rows) {
    const row = elt("div", "ent-corr-row");
    row.appendChild(elt("span", "ent-corr-pred", `${r.predicate} → ${r.value}`)); // textContent
    row.appendChild(elt("span", "ent-corr-author", `by ${r.author}`));
    row.appendChild(applyBtn("Revert", () => d.revertCorrection(r.canonicalKey, r.predicate)));
    sec.appendChild(row);
  }
  detail.appendChild(sec);
}

// §7: typed relationships ALWAYS shown (promoted from the on-demand AI block) — rel_type + conf +
// evidence rows, each other-entity clickable → /entities (the report-entity-row nav precedent). All
// values reach the DOM via textContent; the click navigates, never injects markup.
function renderTypedRelationships(d: PageDeps, detail: HTMLElement, e: EntityRecord): void {
  const rels = d.typedRelationships(entityKey(e.ref));
  if (!rels.length) return; // no persisted typed rels (un-Processed / none gated) → omit, never a fake empty
  const sec = elt("div", "ent-typedrel");
  sec.appendChild(elt("div", "ent-typedrel-head", `Typed relationships (${rels.length})`));
  for (const r of rels) {
    const row = elt("div", "ent-typedrel-row");
    row.appendChild(elt("span", "ent-typedrel-conf", `[${r.confidence}]`));
    row.appendChild(elt("span", "ent-typedrel-type", r.direction === "out" ? `${r.relType} →` : `← ${r.relType}`));
    const link = elt("button", "ent-typedrel-other", r.otherLabel) as HTMLButtonElement; // clickable other-entity
    link.addEventListener("click", () => d.navigate("/entities"));
    row.appendChild(link);
    if (r.evidence) row.appendChild(elt("span", "ent-typedrel-ev", `— ${r.evidence}`));
    sec.appendChild(row);
  }
  detail.appendChild(sec);
}

// §8: the "Appears in N report(s)" list from EntityRecord.runs + the gate evidentiary weight (grade /
// promoted / sourceCount / infraSourceCount) + the surfaced_in confidence. The raw snippet TEXT is the
// SIGNED zero-retention divergence (not shown). All values via textContent.
function renderEntityAppearances(d: PageDeps, detail: HTMLElement, e: EntityRecord): void {
  const apps = d.entityAppearances(e);
  const sec = elt("div", "ent-appears");
  sec.appendChild(elt("div", "ent-appears-head", `Appears in ${apps.length} report(s)`));
  for (const a of apps) {
    const row = elt("div", "ent-appears-row");
    row.appendChild(elt("span", "ent-appears-obj", a.objective)); // already-redacted objective
    const weight = [
      a.promoted ? "promoted" : "lead",
      a.grade ? `grade ${a.grade}` : null,
      `${a.sourceCount} src`,
      a.infraSourceCount ? `${a.infraSourceCount} infra` : null,
      a.surfacedConfidence ? `conf ${a.surfacedConfidence}` : null,
    ].filter(Boolean).join(" · ");
    row.appendChild(elt("span", "ent-appears-weight", weight));
    sec.appendChild(row);
  }
  detail.appendChild(sec);
}

// §6: the EDITABLE analyst-dossier override — Edit/Save/Revert-to-AI, kept SEPARATE from the AI dossier
// (a different vault key) + an "analyst-edited" badge. The saved override renders via the escape-first
// renderMarkdown (the AI-dossier precedent — NEVER raw innerHTML of untrusted text); the editor uses a
// textarea (textContent input). The save goes through the single-writer setEntityDossierOverride.
function renderEntityDossierOverride(d: PageDeps, detail: HTMLElement, e: EntityRecord): void {
  const sec = elt("div", "ent-override");
  const head = elt("div", "ent-override-head");
  head.appendChild(elt("span", "ent-override-title", "Analyst dossier"));
  const badge = elt("span", "ent-override-badge", "analyst-edited");
  head.appendChild(badge);
  sec.appendChild(head);

  const body = elt("div", "markdown ent-override-body");
  const editor = elt("div", "ent-override-editor");
  editor.hidden = true;
  const ta = elt("textarea", "ent-override-ta") as HTMLTextAreaElement;
  ta.rows = 10;
  ta.placeholder = "Write your dossier. Kept separate from the AI dossier — regenerating it won't overwrite this.";
  const saveBtn = elt("button", "pg-btn", "Save") as HTMLButtonElement;
  const cancelBtn = elt("button", "pg-btn ghost", "Cancel") as HTMLButtonElement;
  editor.appendChild(ta);
  const editorRow = elt("div", "ent-override-row");
  editorRow.appendChild(saveBtn);
  editorRow.appendChild(cancelBtn);
  editor.appendChild(editorRow);

  const actions = elt("div", "ent-override-actions");
  const editBtn = elt("button", "pg-btn", "Edit dossier") as HTMLButtonElement;
  const revertBtn = elt("button", "pg-btn ghost", "Revert to AI") as HTMLButtonElement;
  actions.appendChild(editBtn);
  actions.appendChild(revertBtn);

  const paint = (): void => {
    const ov = d.getDossierOverride(e);
    const has = !!ov;
    badge.hidden = !has;
    revertBtn.hidden = !has;
    if (has) {
      body.innerHTML = renderMarkdown(ov!.text); // escape-first XSS-safe (the AI-dossier precedent)
      body.hidden = false;
    } else {
      body.textContent = "No analyst dossier yet. Click Edit to write one (separate from the AI dossier).";
      body.hidden = false;
    }
  };

  editBtn.addEventListener("click", () => {
    const ov = d.getDossierOverride(e);
    ta.value = ov?.text ?? "";
    body.hidden = true;
    actions.hidden = true;
    editor.hidden = false;
  });
  cancelBtn.addEventListener("click", () => {
    editor.hidden = true;
    body.hidden = false;
    actions.hidden = false;
  });
  saveBtn.addEventListener("click", async () => {
    if (saveBtn.disabled) return;
    saveBtn.disabled = true;
    saveBtn.textContent = "Saving…";
    try {
      await d.setDossierOverride(e, ta.value);
      editor.hidden = true;
      actions.hidden = false;
      paint(); // optimistic re-read from the vault (the single source of truth)
    } catch (err) {
      saveBtn.textContent = err instanceof Error ? err.message : "failed";
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = "Save";
    }
  });
  revertBtn.addEventListener("click", async () => {
    if (revertBtn.disabled) return;
    revertBtn.disabled = true;
    try {
      await d.setDossierOverride(e, ""); // blank = revert-to-AI (the setReportNotes/clearProviderKey discipline)
      paint();
    } finally {
      revertBtn.disabled = false;
    }
  });

  sec.appendChild(body);
  sec.appendChild(editor);
  sec.appendChild(actions);
  paint();
  detail.appendChild(sec);
}

// adr-wire: the on-demand AI passes on the Entities page (model-written dossier BESIDE the derived
// one + a separate "Model-typed relations" block — D9). The async deps route through app.ts (D6);
// buttons disable while a call is in flight (D8). Every value reaches the DOM via textContent /
// the escape-first markdown renderer.
function renderEntityAiAffordances(d: PageDeps, detail: HTMLElement, e: EntityRecord, conns: Connection[]): void {
  const sec = elt("div", "ent-ai");
  sec.appendChild(elt("div", "ent-ai-label", "AI analysis (model-written · uses your key)"));
  const dossierBtn = elt("button", "pg-btn", "AI dossier") as HTMLButtonElement;
  const relsBtn = elt("button", "pg-btn", "Type relations") as HTMLButtonElement;
  sec.appendChild(dossierBtn);
  sec.appendChild(relsBtn);
  const out = elt("div", "ent-ai-out");
  sec.appendChild(out);
  detail.appendChild(sec);

  dossierBtn.addEventListener("click", async () => {
    if (dossierBtn.disabled) return;
    dossierBtn.disabled = true; // D8
    dossierBtn.textContent = "Writing…";
    try {
      const md = await d.aiDossier(e.type, e.ref.value);
      out.querySelector(".ent-ai-dossier")?.remove();
      const wrap = elt("div", "ent-ai-dossier");
      wrap.appendChild(elt("div", "ent-ai-tag", "AI dossier · model-written"));
      const body = elt("div", "markdown ent-ai-body");
      body.innerHTML = renderMarkdown(md ?? "No AI dossier — not enough grounded evidence for this entity."); // escape-first XSS-safe
      wrap.appendChild(body);
      out.appendChild(wrap);
    } catch (err) {
      out.appendChild(elt("div", "ent-ai-err", err instanceof Error ? err.message : String(err)));
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
      const rels = await d.semanticRelations(e.type, e.ref.value);
      const cidToConn = new Map<string, Connection>();
      for (const c of conns) cidToConn.set(connId(e.ref, c), c);
      out.querySelector(".ent-model-typed")?.remove();
      const wrap = elt("div", "ent-model-typed");
      wrap.appendChild(elt("div", "ent-ai-tag", `Model-typed relations (${rels.length})`));
      if (!rels.length) wrap.appendChild(elt("div", "ent-conn", "No semantic relations typed (none survived the gate)."));
      for (const r of rels) {
        const conn = cidToConn.get(r.cid);
        const other = conn ? `${conn.otherLabel} · ${conn.otherType || conn.otherRole}` : "(connection)";
        wrap.appendChild(elt("div", "ent-model-rel", `⇒ ${r.relType}: ${other} · ${r.confidence}${r.evidence ? ` — ${r.evidence}` : ""}`));
      }
      out.appendChild(wrap);
    } catch (err) {
      out.appendChild(elt("div", "ent-ai-err", err instanceof Error ? err.message : String(err)));
    } finally {
      relsBtn.textContent = "Type relations";
      relsBtn.disabled = false;
    }
  });
}

function connectionRow(c: Connection): HTMLElement {
  const arrow = c.direction === "in" ? "←" : c.direction === "out" ? "→" : "↔";
  const rel = c.relType === "surfaced_in" ? "surfaced in" : c.relType === "co_occurs" ? "co-occurs" : "linked";
  return elt(
    "div",
    "ent-conn",
    `${arrow} ${rel}: ${c.otherLabel} · ${c.otherType || c.otherRole} · ${c.confidence}${c.count > 1 ? ` ×${c.count}` : ""}`,
  );
}

// ---- Corrections page (ca-ui: the analyst-authority audit + the "You" name) ----

const MAX_CORR_ROWS = 200;

export function renderCorrectionsPage(d: PageDeps): HTMLElement {
  const { page, body } = pageShell("Corrections", "Analyst overrides — the top authority, applied to entities, the graph, and briefs");

  // the analyst "You" name (local attribution)
  const nameSec = elt("div", "corr-analyst");
  nameSec.appendChild(elt("span", "corr-label", "You (analyst):"));
  const input = elt("input", "corr-name-input") as HTMLInputElement;
  input.type = "text";
  input.value = d.getAnalyst();
  nameSec.appendChild(input);
  const saveName = elt("button", "pg-btn", "Save name") as HTMLButtonElement;
  saveName.addEventListener("click", async () => {
    saveName.disabled = true;
    try {
      await d.setAnalyst(input.value);
      saveName.textContent = "Saved";
    } finally {
      window.setTimeout(() => {
        saveName.textContent = "Save name";
        saveName.disabled = false;
      }, 800);
    }
  });
  nameSec.appendChild(saveName);
  body.appendChild(nameSec);

  const rows = d.listCorrections();
  const active = rows.filter((r) => r.active);
  const orphan = rows.length - active.length;
  body.appendChild(
    elt("div", "corr-count", `${active.length} active correction(s)${orphan ? ` · ${orphan} orphaned (entity no longer exists)` : ""}`),
  );
  if (!active.length) {
    emptyNote(body, "No corrections yet. Override an entity's role on the Entities page, or apply an AI suggestion.");
    return page;
  }
  for (const r of active.slice(0, MAX_CORR_ROWS)) {
    const card = elt("div", "corr-card");
    card.appendChild(elt("div", "corr-row", `${r.label} · ${r.predicate} → ${r.value} · by ${r.author}`)); // textContent
    const revert = elt("button", "pg-btn", "Revert") as HTMLButtonElement;
    revert.addEventListener("click", async () => {
      revert.disabled = true;
      revert.textContent = "Reverting…";
      try {
        await d.revertCorrection(r.canonicalKey, r.predicate);
      } catch {
        revert.textContent = "Revert";
        revert.disabled = false;
      }
    });
    card.appendChild(revert);
    body.appendChild(card);
  }
  return page;
}

// ---- sf-activity: the /activity feed ("who did what, when") — a reverse-chron projection over the
// timestamped retained records (activityFor). Mirrors the original activity.html: analyst · action ·
// entity/report · detail · time, with the original's honest empty-state copy. All textContent (a hostile
// entity/objective is literal text); the projection is key-redacted at the session layer. ----
function activityWhen(at: string): string {
  // a stable, locale-independent "YYYY-MM-DD HH:MM" (the original shows the SQLite created_at) — no Date
  // parsing, so the smoke is deterministic and a malformed `at` degrades to its literal text.
  const m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(at);
  return m ? `${m[1]} ${m[2]}` : at;
}

export function renderActivityPage(d: PageDeps): HTMLElement {
  const { page, body } = pageShell("Activity", `Who did what, when. You're acting as ${d.getAnalyst()}.`);
  const items = d.activity();
  body.appendChild(elt("div", "act-count", `${items.length} action(s)`));
  if (!items.length) {
    emptyNote(body, "No activity yet. Notes, corrections, dossier edits, uploads, processing, and enrichment runs show up here, stamped with who did them and when.");
    return page;
  }
  const list = elt("div", "act-list");
  for (const a of items) {
    const row = elt("div", "act-row");
    if (a.analyst) row.appendChild(elt("span", "act-analyst", a.analyst)); // analyst chip (when the record stamped one)
    row.appendChild(elt("span", "act-action", a.action));
    if (a.entityLabel) row.appendChild(elt("span", "act-entity", a.entityLabel));
    if (a.report) row.appendChild(elt("span", "act-report", a.report));
    if (a.detail) row.appendChild(elt("span", "act-detail", a.detail));
    row.appendChild(elt("span", "act-when", activityWhen(a.at)));
    list.appendChild(row);
  }
  body.appendChild(list);
  return page;
}

// ---- sf-exports: the /exports page — STIX 2.1 / MISP / CSV downloads, generated in-browser (intel.ts)
// from the redacted export model. One card per format with a Download button → d.download (the existing
// Blob primitive). Faithful to exports.html (the server file-paths are an artifact — the bytes download
// directly, nothing leaves the browser). ----
function downloadCard(d: PageDeps, title: string, desc: string, files: { name: string; text: string }[], disabled = false): HTMLElement {
  const card = elt("div", "exp-card");
  card.appendChild(elt("div", "exp-title", title));
  card.appendChild(elt("div", "exp-desc", desc));
  const row = elt("div", "exp-actions");
  for (const f of files) {
    const btn = elt("button", "pg-btn", `Download ${f.name}`) as HTMLButtonElement;
    if (disabled) {
      // ux (brief §Exports #15): an empty case produces empty files — disable + explain, don't hand the
      // analyst a 0-entity download.
      btn.disabled = true;
      btn.title = "Run Process to populate the case first.";
    } else {
      btn.addEventListener("click", () => d.download(f.name, new TextEncoder().encode(f.text)));
    }
    row.appendChild(btn);
  }
  card.appendChild(row);
  return card;
}

export function renderExportsPage(d: PageDeps): HTMLElement {
  const { page, body } = pageShell("Exports", "STIX 2.1, MISP, and CSV for downstream tools — generated in your browser, nothing leaves the page");
  const f = d.exports();
  // ux (brief §Exports #15): an empty case (no processed entities) yields empty files — disable the
  // downloads + explain, rather than hand the analyst a 0-entity export. entitiesCsv = header only when empty.
  const hasData = f.entitiesCsv.trim().split("\n").length > 1;
  body.appendChild(elt("p", "exp-hint", hasData
    ? "STIX 2.1, MISP, and CSV for downstream tools. The downloads reflect the current case."
    : "Run Process first to populate entities, scores, relationships, and clusters — then these downloads fill in."));
  body.appendChild(downloadCard(d, "STIX 2.1 bundle", "Identity + per-entity observables/SDOs + typed-relationship SROs, for a TIP / threat-sharing platform.", [{ name: "stix_bundle.json", text: f.stix }], !hasData));
  body.appendChild(downloadCard(d, "MISP event", "An event with one attribute per high-value entity (operator / channel / IOC), to_ids set on IOCs + operators.", [{ name: "misp_event.json", text: f.misp }], !hasData));
  body.appendChild(downloadCard(d, "CSV (entities, relationships, clusters)", "Flat CSVs for spreadsheets / Notion / pivot analysis.", [
    { name: "entities.csv", text: f.entitiesCsv },
    { name: "typed_relationships.csv", text: f.relationshipsCsv },
    { name: "clusters.csv", text: f.clustersCsv },
  ], !hasData));
  return page;
}

// ---- sf-cases: the /cases multi-case switcher — list the cases (active highlighted) + a New-case form +
// click-to-select. One vault per user; cases are a key-namespace dimension (the active case scopes every
// projection). Per-user keys (the Anthropic/provider keys, the analyst name) are SHARED across cases.
// Case names reach the DOM via textContent (a hostile name is literal text); they're redacted at the session
// layer. Original /cases + /select-case/{} → this one route (the click-to-select fold). ----
export function renderCasesPage(d: PageDeps): HTMLElement {
  const { page, body } = pageShell("Cases", "One vault, multiple cases. Switch the active case — entities, runs, briefs, and findings scope to it. Your keys + analyst name are shared across cases.");

  // the New-case form
  const form = elt("div", "case-new");
  const input = elt("input", "case-name-input") as HTMLInputElement;
  input.type = "text";
  input.placeholder = "New case name (e.g. Acme breach)";
  const createBtn = elt("button", "pg-btn primary", "Create case") as HTMLButtonElement;
  createBtn.addEventListener("click", async () => {
    const name = input.value.trim();
    if (!name) return;
    createBtn.disabled = true;
    createBtn.textContent = "Creating…";
    try {
      await d.createCase(name); // creates + switches + re-renders the whole app
    } catch (err) {
      createBtn.textContent = err instanceof Error ? err.message : "failed";
      createBtn.disabled = false;
    }
  });
  form.appendChild(input);
  form.appendChild(createBtn);
  body.appendChild(form);

  const cases = d.cases();
  body.appendChild(elt("div", "case-count", cases.length ? `${cases.length} case(s)` : "No cases yet. Create your first case above to start."));
  const list = elt("div", "case-list");
  for (const c of cases) {
    const row = elt("div", `case-row${c.active ? " case-active" : ""}`);
    const main = elt("div", "case-main");
    main.appendChild(elt("span", "case-name", c.name)); // textContent — literal
    if (c.active) main.appendChild(chip("active", "ok"));
    if (c.createdAt) main.appendChild(elt("span", "case-date", c.createdAt.slice(0, 10)));
    row.appendChild(main);
    if (!c.active) {
      const sw = elt("button", "pg-btn", "Switch to") as HTMLButtonElement;
      sw.addEventListener("click", async () => {
        sw.disabled = true;
        sw.textContent = "Switching…";
        try {
          await d.switchCase(c.id); // sets active + clears in-memory state + re-renders
        } catch {
          sw.textContent = "Switch to";
          sw.disabled = false;
        }
      });
      row.appendChild(sw);
    }
    // sf-cases delete: every case gets a Delete (no implicit case is special anymore). One confirm shows the
    // stakes (run + entity counts); deleting the active case auto-switches to another case, or to the empty
    // state when it was the last one (app.ts). The case name is interpolated as a literal string in confirm().
    const del = elt("button", "pg-btn danger", "Delete") as HTMLButtonElement;
    del.addEventListener("click", async () => {
      const { runs, entities } = d.caseCounts(c.id);
      const ok = window.confirm(
        `Delete "${c.name}"?\n\nThis permanently removes the case and all its data: ${runs} run(s), ${entities} entit${entities === 1 ? "y" : "ies"}, plus its briefs and findings.\n\nThis can't be undone.`,
      );
      if (!ok) return;
      del.disabled = true;
      del.textContent = "Deleting…";
      try {
        await d.deleteCase(c.id); // drops the namespace + re-renders the whole app
      } catch (err) {
        del.textContent = err instanceof Error ? err.message : "Delete";
        del.disabled = false;
      }
    });
    row.appendChild(del);
    list.appendChild(row);
  }
  body.appendChild(list);
  return page;
}

// ---- sf-report-builder: the /report page — a builder FORM + an inline BRANDED render + window.print(),
// a 1:1 of report-builder.html + report.html folded into one SPA route. The form is print-hidden (CSS
// @media print); the .report-doc is the deliverable. All values via textContent / escape-first markdown;
// accent hex-validated before a CSS var; logo a data:image/ upload (the CSP img-src blocks remote URLs). ----

const REPORT_SECTIONS: [string, string][] = [
  ["summary", "Executive summary"],
  ["actors", "Priority actors"],
  ["dossiers", "Actor dossiers"],
  ["iocs", "Indicators of compromise"],
  ["crosscase", "Cross-case links"],
  ["methodology", "Methodology & provenance"],
];

function sanitizeAccent(v: string): string {
  return /^#[0-9a-fA-F]{3,8}$/.test(v) ? v : "#1e3a5f"; // report.html accent regex
}

function labeledInput(label: string, input: HTMLElement): HTMLElement {
  const wrap = elt("label", "rf-field");
  wrap.appendChild(elt("span", "rf-label", label));
  wrap.appendChild(input);
  return wrap;
}

export function renderReportPage(d: PageDeps): HTMLElement {
  const m = d.reportModel();
  const page = elt("section", "pg report-page");
  page.appendChild(elt("h1", "pg-title", "Build a client report"));
  page.appendChild(elt("p", "pg-sub", "Tune branding + sections, then Print / Save as PDF. The report below is the client deliverable."));

  const branding = { title: `Intelligence Report — ${m.caseName}`, client: "", preparedBy: d.getAnalyst(), accent: "#1e3a5f", logo: "" };
  const selected = new Set(REPORT_SECTIONS.map(([k]) => k));

  // ---- the builder FORM (print-hidden via .report-form) ----
  const form = elt("div", "report-form");
  const titleIn = elt("input", "rf-input") as HTMLInputElement;
  titleIn.value = branding.title;
  titleIn.addEventListener("input", () => { branding.title = titleIn.value; paint(); });
  const clientIn = elt("input", "rf-input") as HTMLInputElement;
  clientIn.placeholder = "e.g. Acme Corp";
  clientIn.addEventListener("input", () => { branding.client = clientIn.value; paint(); });
  const byIn = elt("input", "rf-input") as HTMLInputElement;
  byIn.value = branding.preparedBy;
  byIn.addEventListener("input", () => { branding.preparedBy = byIn.value; paint(); });
  const accentIn = elt("input", "rf-color") as HTMLInputElement;
  accentIn.type = "color";
  accentIn.value = branding.accent;
  accentIn.addEventListener("input", () => { branding.accent = sanitizeAccent(accentIn.value); paint(); });
  const logoIn = elt("input", "rf-input") as HTMLInputElement;
  logoIn.type = "file";
  logoIn.accept = "image/*";
  logoIn.addEventListener("change", () => {
    const file = logoIn.files?.[0];
    if (!file) { branding.logo = ""; paint(); return; }
    const reader = new FileReader();
    reader.onload = () => {
      const url = String(reader.result || "");
      branding.logo = url.startsWith("data:image/") ? url : ""; // data:image/ only (CSP + no remote fetch)
      paint();
    };
    reader.readAsDataURL(file);
  });
  form.appendChild(labeledInput("Report title", titleIn));
  form.appendChild(labeledInput("Client (prepared for)", clientIn));
  form.appendChild(labeledInput("Prepared by", byIn));
  form.appendChild(labeledInput("Accent color", accentIn));
  form.appendChild(labeledInput("Logo (image upload)", logoIn));

  const secWrap = elt("div", "rf-sections");
  secWrap.appendChild(elt("span", "rf-label", "Sections"));
  for (const [key, label] of REPORT_SECTIONS) {
    const lab = elt("label", "rf-check");
    const cb = elt("input", "rf-sec") as HTMLInputElement;
    cb.type = "checkbox";
    cb.checked = true;
    cb.dataset.section = key;
    cb.addEventListener("change", () => { cb.checked ? selected.add(key) : selected.delete(key); paint(); });
    lab.appendChild(cb);
    lab.appendChild(elt("span", "", label));
    secWrap.appendChild(lab);
  }
  form.appendChild(secWrap);

  // clu-auto-report: the exec summary AUTO-EXISTS (live, current-state) — editable + re-renderable, NO
  // Generate button. Edits persist to the vault (analyst is top authority); "Re-render from current
  // state" drops the edit so the summary reverts to the LLM brief (if any) else the deterministic live
  // summary. The textarea seeds from the resolved execSummary (m.execSummary always non-empty).
  const sumWrap = elt("div", "rf-field rf-summary");
  sumWrap.appendChild(elt("span", "rf-label", "Executive summary — auto-updates with the case; edit to override"));
  const sumArea = elt("textarea", "rf-input rf-summary-area") as HTMLTextAreaElement;
  sumArea.rows = 8;
  sumArea.value = m.execSummary;
  sumWrap.appendChild(sumArea);
  const sumStatus = elt("div", "rf-summary-status");
  const sumRow = elt("div", "rf-summary-row");
  const saveSum = elt("button", "pg-btn", "Save summary") as HTMLButtonElement;
  const rerenderSum = elt("button", "pg-btn", "Re-render from current state") as HTMLButtonElement;
  saveSum.addEventListener("click", async () => {
    saveSum.disabled = true;
    try {
      await d.saveReportSummary(sumArea.value);
      d.navigate("/report"); // re-render so the deliverable reflects the saved (redacted) edit
    } catch (e) {
      sumStatus.textContent = e instanceof Error ? e.message : "Save failed";
      saveSum.disabled = false;
    }
  });
  rerenderSum.addEventListener("click", async () => {
    rerenderSum.disabled = true;
    try {
      await d.clearReportSummary();
      d.navigate("/report"); // re-derive from current state (brief or live) + re-render
    } catch (e) {
      sumStatus.textContent = e instanceof Error ? e.message : "Re-render failed";
      rerenderSum.disabled = false;
    }
  });
  sumRow.appendChild(saveSum);
  sumRow.appendChild(rerenderSum);
  sumWrap.appendChild(sumRow);
  sumWrap.appendChild(sumStatus);
  form.appendChild(sumWrap);

  const printBtn = elt("button", "pg-btn primary report-print", "Print / Save as PDF") as HTMLButtonElement;
  printBtn.addEventListener("click", () => window.print());
  form.appendChild(printBtn);
  page.appendChild(form);

  // ---- the branded RENDER (.report-doc) ----
  const doc = elt("div", "report-doc");
  page.appendChild(doc);

  const paint = (): void => {
    doc.replaceChildren();
    doc.style.setProperty("--report-accent", sanitizeAccent(branding.accent)); // sanitized → no CSS injection

    // COVER
    const cover = elt("div", "rep-cover");
    if (branding.logo) {
      const img = elt("img", "rep-logo") as HTMLImageElement;
      img.src = branding.logo; // a validated data:image/ URL
      img.alt = "";
      cover.appendChild(img);
    }
    cover.appendChild(elt("div", "rep-eyebrow", "Confidential Intelligence Report"));
    cover.appendChild(elt("h1", "rep-cover-title", branding.title || `Intelligence Report — ${m.caseName}`));
    if (branding.client) cover.appendChild(elt("div", "rep-client", `Prepared for ${branding.client}`));
    cover.appendChild(elt("div", "rep-rule"));
    const meta = elt("div", "rep-meta");
    meta.appendChild(elt("div", "", `Case: ${m.caseName}`));
    meta.appendChild(elt("div", "", `Prepared by: ${branding.preparedBy || "analyst"}`));
    meta.appendChild(elt("div", "", `Scope: ${m.stats.reports} report${m.stats.reports === 1 ? "" : "s"}, ${m.stats.entities} entities`));
    cover.appendChild(meta);
    cover.appendChild(elt("div", "rep-confidential", "Confidential — for the named recipient only. Do not redistribute."));
    doc.appendChild(cover);

    // EXECUTIVE SUMMARY
    if (selected.has("summary")) {
      const sec = repSection("Executive Summary");
      const kpis = elt("div", "rep-kpis");
      for (const [n, l] of [[m.stats.reports, "Reports"], [m.stats.entities, "Entities"], [m.topActors.length, "Priority actors"], [m.iocs.length, "Indicators"]] as [number, string][]) {
        const kpi = elt("div", "rep-kpi");
        kpi.appendChild(elt("div", "rep-kpi-n", String(n)));
        kpi.appendChild(elt("div", "rep-kpi-l", l));
        kpis.appendChild(kpi);
      }
      sec.appendChild(kpis);
      if (m.execSummary.trim()) {
        const md = elt("div", "rep-md");
        md.innerHTML = renderBriefMarkdown(m.execSummary); // escape-first XSS-safe
        sec.appendChild(md);
      } else {
        sec.appendChild(elt("div", "rep-empty", "No synthesis brief generated for this case yet."));
      }
      doc.appendChild(sec);
    }

    // PRIORITY ACTORS
    if (selected.has("actors")) {
      const sec = repSection("Priority Actors");
      sec.appendChild(elt("div", "rep-lead", "Ranked by attention score across this case's reporting."));
      if (m.topActors.length) {
        for (const a of m.topActors) {
          const card = elt("div", "rep-actor");
          const h = elt("div", "rep-actor-head");
          h.appendChild(elt("span", "rep-actor-name", a.name));
          h.appendChild(chip(a.role || a.type || "entity"));
          card.appendChild(h);
          if (a.why) card.appendChild(elt("div", "rep-actor-why", a.why));
          sec.appendChild(card);
        }
      } else {
        sec.appendChild(elt("div", "rep-empty", "No priority actors scored yet — run Process."));
      }
      doc.appendChild(sec);
    }

    // ACTOR DOSSIERS
    if (selected.has("dossiers")) {
      const sec = repSection("Actor Dossiers");
      if (m.dossiers.length) {
        for (const x of m.dossiers) {
          const card = elt("div", "rep-dossier");
          card.appendChild(elt("h3", "rep-dossier-name", x.name));
          card.appendChild(elt("div", "rep-dossier-src", x.source === "analyst" ? "Analyst-authored" : "AI-generated, analyst-reviewed"));
          const md = elt("div", "rep-md");
          md.innerHTML = renderMarkdown(x.body); // escape-first XSS-safe
          card.appendChild(md);
          sec.appendChild(card);
        }
      } else {
        sec.appendChild(elt("div", "rep-empty", "No dossiers or analyst notes recorded for the top actors."));
      }
      doc.appendChild(sec);
    }

    // IOCs
    if (selected.has("iocs")) {
      const sec = repSection("Indicators of Compromise");
      if (m.iocs.length) {
        sec.appendChild(repTable(["Indicator", "Type", "Reports"], m.iocs.map((i) => [i.name, i.type, String(i.reports)]), [false, false, true]));
      } else {
        sec.appendChild(elt("div", "rep-empty", "No indicators extracted for this case."));
      }
      doc.appendChild(sec);
    }

    // CROSS-CASE
    if (selected.has("crosscase")) {
      const sec = repSection("Cross-Case Links");
      sec.appendChild(elt("div", "rep-lead", "Actors and indicators in this case that also appear in other investigations."));
      if (m.crossCase.length) {
        sec.appendChild(repTable(["Entity", "Type", "Also appears in"], m.crossCase.map((c) => [c.name, c.type, c.alsoIn.join(", ")]), [false, false, false]));
      } else {
        // codex impl-review: honest single-vault copy — the client holds ONE case, so it did not (cannot)
        // check other investigations; this populates once sf-cases adds multi-case (not "checked + found none").
        sec.appendChild(elt("div", "rep-empty", "Cross-case links populate once this vault holds more than one case (single-case today)."));
      }
      doc.appendChild(sec);
    }

    // METHODOLOGY
    if (selected.has("methodology")) {
      const sec = repSection("Methodology & Provenance");
      sec.appendChild(elt("p", "rep-p", `Findings are derived from ${m.stats.reports} source report${m.stats.reports === 1 ? "" : "s"} ingested into this case. Entities and relationships are extracted automatically, then reviewed by an analyst. Attention scoring is a rank-by-priority signal (role, cross-report presence, network centrality, and analyst-flagged priors), not a maliciousness rating.`));
      sec.appendChild(elt("p", "rep-p", "Where a newer report contradicted an earlier one, the conflicting claim was superseded by analyst decision and the prior assertion retained in the audit trail. Analyst notes and edited dossiers reflect knowledge beyond the source reporting."));
      if (m.sources.length) {
        sec.appendChild(repTable(["Source report", "Type", "Ingested"], m.sources.map((s) => [s.title || "(untitled)", s.sourceType, s.ingestedAt.slice(0, 10)]), [false, false, false]));
      }
      doc.appendChild(sec);
    }

    // FOOTER
    const footer = elt("div", "rep-footer");
    footer.appendChild(elt("span", "", branding.title || m.caseName));
    footer.appendChild(elt("span", "", `Confidential · prepared by ${branding.preparedBy || "analyst"}`));
    doc.appendChild(footer);
  };

  paint();
  return page;
}

function repSection(title: string): HTMLElement {
  const sec = elt("div", "rep-section");
  sec.appendChild(elt("h2", "rep-section-title", title));
  return sec;
}

function repTable(headers: string[], rows: string[][], numeric: boolean[]): HTMLElement {
  const table = elt("table", "rep-table");
  const thead = elt("thead");
  const htr = elt("tr");
  headers.forEach((h, i) => {
    const th = elt("th", numeric[i] ? "rep-num" : "", h);
    htr.appendChild(th);
  });
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = elt("tbody");
  for (const row of rows) {
    const tr = elt("tr");
    row.forEach((cell, i) => tr.appendChild(elt("td", numeric[i] ? "rep-num" : "", cell))); // textContent — XSS-safe
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  return table;
}

// ---- Clusters page (cl-wire: entities grouped by connected components) ----

export function renderClustersPage(d: PageDeps): HTMLElement {
  const clusters = d.clusters();
  const { page, body } = pageShell("Clusters", `${clusters.length} cluster(s) — entities grouped by shared connections`);
  if (!clusters.length) {
    emptyNote(body, "No clusters yet. A cluster forms when two or more entities are connected (co-occur or linked) across your runs.");
    return page;
  }
  for (const c of clusters) {
    const card = elt("div", "cl-card");
    const head = elt("div", "cl-head");
    head.appendChild(elt("span", "cl-name", c.label));
    const meta = elt("span", "cl-meta");
    meta.appendChild(chip(c.kind));
    meta.appendChild(chip(`${c.size} members`, "ok"));
    head.appendChild(meta);
    card.appendChild(head);
    const members = elt("div", "cl-members");
    for (const m of c.members) members.appendChild(elt("div", "cl-member", `${m.value} · ${m.type}`)); // textContent
    card.appendChild(members);
    body.appendChild(card);
  }
  return page;
}

// ---- Cross-cluster bridges page (sf-bridges) ----
//
// Faithful to the original /bridges (bridges.html): the network-structure connectors — entities that
// span >= 2 analyze-clusters. One card per bridge entity: name + SEED badge, role / function, the
// bridged-cluster chips, the # of clusters it spans, and its threat score. Sorted by cluster span then
// score (the original's ORDER BY cluster_count DESC, threat_score DESC). All values reach the DOM via
// the textContent-only `elt` helper, so a hostile entity value is literal text. Bridges are read via the
// key-redacted projection (d.bridges() → bridgesFor), so no raw key reaches here.
export function renderBridgesPage(d: PageDeps): HTMLElement {
  const bridges = d.bridges();
  const { page, body } = pageShell(
    "Connectors",
    `${bridges.length} connector entit${bridges.length === 1 ? "y" : "ies"} — entities spanning multiple clusters (network-structure connectors)`,
  );
  if (!bridges.length) {
    emptyNote(
      body,
      "No entities span this many clusters. A bridge appears once the case has 2+ analytic clusters with an entity in (or tied across) more than one — run Process to model the clusters.",
    );
    return page;
  }
  for (const b of bridges) {
    const card = elt("div", "br-card");
    const head = elt("div", "br-head");
    const name = elt("span", "br-name", b.label);
    head.appendChild(name);
    if (b.promoted) head.appendChild(chip("SEED", "warn"));
    const meta = elt("span", "br-meta");
    meta.appendChild(chip(b.role || b.type || "entity"));
    meta.appendChild(chip(`${b.clusterCount} clusters`, "ok"));
    meta.appendChild(chip(`score ${Math.round(b.threatScore)}`));
    head.appendChild(meta);
    card.appendChild(head);
    // the bridged-cluster chips (the "Clusters" column in the original) + the cross-cluster rel count.
    const clusters = elt("div", "br-clusters");
    for (const c of b.clusters) clusters.appendChild(chip(c.name)); // textContent (already redacted)
    if (b.crossRelCount > 0) clusters.appendChild(chip(`${b.crossRelCount} cross-cluster edge${b.crossRelCount === 1 ? "" : "s"}`, "warn"));
    card.appendChild(clusters);
    body.appendChild(card);
  }
  return page;
}

// ---- Focus page (sf-focus) ----
//
// Faithful to the original /focus (focus.html): "where to look first, ranked by attention". The
// score-ranked TOP targets (rank · name · role · SEED · score, + the deterministic why-sentence + cluster
// chips + top typed-rel chips), the Gaps "what to look for next" section, and the VERBATIM
// score-methodology block (focus.html:172-191 — "How to read these scores"). All values reach the DOM via
// the textContent-only `elt` helper, so a hostile entity value / cluster name is literal text. Focus is
// read via the key-redacted projection (d.focus() → focusFor), so no raw key reaches here. Honest empty
// state pre-Process. SIGNED divergences (in the manifest note): the elevated/cooling score-DELTA strip
// (no client focus-run-history store) and the optional LLM Analyst summary (the gap list is the analog).
export function renderFocusPage(d: PageDeps): HTMLElement {
  const focus = d.focus();
  const { page, body } = pageShell("Focus", "Where to look first, ranked by attention.");

  // Gaps & what to look for next — the amber callout (focus.html:41-61). Rendered above the items, like
  // the original, so the analyst sees the missing-corroboration / not-investigated prompts first.
  if (focus.gaps.length) renderFocusGaps(d, body, focus.gaps);

  if (!focus.items.length) {
    // Honest empty state — faithful to focus.html:73-85 (the flow that sharpens the picture).
    const empty = elt("div", "fc-empty");
    empty.appendChild(elt("div", "fc-empty-title", "No focus brief yet"));
    empty.appendChild(elt("div", "fc-empty-sub", "The picture sharpens with more data. The flow:"));
    const ol = elt("ol", "fc-empty-flow");
    for (const step of [
      "Add reports — Reports tab → Files or Paste.",
      "Process the case — dedupes, types, builds typed links + clusters, scores targets.",
      "Investigate the top targets — the detective enriches them + builds connections.",
    ]) {
      ol.appendChild(elt("li", undefined, step));
    }
    empty.appendChild(ol);
    empty.appendChild(elt("div", "fc-empty-note", "Each pass: more data + more investigation → sharper picture."));
    body.appendChild(empty);
    return page;
  }

  // Top targets — the score-ranked list (focus.html:97-140).
  const list = elt("div", "fc-list");
  list.appendChild(elt("div", "fc-list-head", `Top targets (${focus.items.length})`));
  for (const it of focus.items) list.appendChild(focusItemRow(it));
  body.appendChild(list);

  // Methodology — the VERBATIM "How to read these scores" block (focus.html:172-191), collapsed by default.
  body.appendChild(focusMethodology());
  return page;
}

// The amber "Gaps & what to look for next" callout (focus.html:41-61): a severity pill + title + the →
// action + a named-entity chip sample (click → /entities, focusing the entity via ⌘K's focus seam).
function renderFocusGaps(d: PageDeps, body: HTMLElement, gaps: FocusGap[]): void {
  const box = elt("div", "fc-gaps");
  box.appendChild(elt("div", "fc-gaps-head", "Gaps & what to look for next"));
  const ul = elt("ul", "fc-gaps-list");
  for (const g of gaps) {
    const li = elt("li", "fc-gap");
    li.appendChild(elt("span", `fc-gap-sev fc-gap-${g.severity}`, g.severity));
    const main = elt("div", "fc-gap-main");
    main.appendChild(elt("div", "fc-gap-title", g.title));
    main.appendChild(elt("div", "fc-gap-action", `→ ${g.action}`));
    if (g.entities.length) {
      const ents = elt("div", "fc-gap-ents");
      for (const e of g.entities) {
        const chipEl = elt("button", "fc-gap-ent", e.name); // textContent — a hostile value is literal text
        chipEl.addEventListener("click", () => d.focusEntity(e.ref)); // → /entities, focus the entity (⌘K seam)
        ents.appendChild(chipEl);
      }
      main.appendChild(ents);
    }
    li.appendChild(main);
    ul.appendChild(li);
  }
  box.appendChild(ul);
  body.appendChild(box);
}

// One ranked focus item (focus.html:103-137): rank · name · role · SEED · score, then the why-sentence,
// the cluster chips, and the top typed-rel chips.
function focusItemRow(it: FocusItem): HTMLElement {
  const row = elt("div", "fc-item");
  const head = elt("div", "fc-item-head");
  head.appendChild(elt("span", "fc-rank", `#${it.rank}`));
  head.appendChild(elt("span", "fc-name", it.name)); // textContent — literal
  head.appendChild(chip(it.role || it.type || "entity"));
  if (it.promoted) head.appendChild(chip("SEED", "warn"));
  head.appendChild(elt("span", "fc-score", `score ${Math.round(it.score)}`));
  row.appendChild(head);

  if (it.why) row.appendChild(elt("div", "fc-why", it.why)); // textContent (deterministic, already redacted)

  if (it.clusters.length) {
    const cls = elt("div", "fc-clusters");
    for (const c of it.clusters) cls.appendChild(chip(c.name)); // textContent (already redacted)
    row.appendChild(cls);
  }

  if (it.topRelationships.length) {
    const rels = elt("div", "fc-rels");
    for (const r of it.topRelationships) {
      const rel = elt("span", "fc-rel");
      rel.appendChild(elt("span", "fc-rel-type", r.relType));
      rel.appendChild(elt("span", "fc-rel-dir", r.direction === "out" ? "→" : "←"));
      rel.appendChild(elt("span", "fc-rel-other", r.otherLabel)); // textContent — literal
      rels.appendChild(rel);
    }
    row.appendChild(rels);
  }
  return row;
}

// The VERBATIM score-methodology block (focus.html:172-191) — a <details> "How to read these scores".
function focusMethodology(): HTMLElement {
  const det = elt("details", "fc-method") as HTMLDetailsElement;
  det.appendChild(elt("summary", "fc-method-sum", "How to read these scores"));
  const bodyEl = elt("div", "fc-method-body");
  bodyEl.appendChild(
    elt(
      "p",
      undefined,
      "Score is a rank-by-attention signal, not a maliciousness rating. Same data produces the same scores. Higher score = look here first.",
    ),
  );
  bodyEl.appendChild(elt("div", "fc-method-formula", "score = role×10 + reports×5 + degree×1 + seed×30 + propagation"));
  const ul = elt("ul", "fc-method-list");
  for (const [label, text] of [
    ["role × 10", "operator=5, ioc=4, channel=3, infra=1, source=0. Operators carry the most analyst-relevant signal."],
    ["reports × 5", "distinct reports where the entity appears. Cross-report presence = persistent, not one-off."],
    ["degree × 1", "typed relationships the entity is part of. Network-central entities score higher."],
    ["seed × 30", "entities you've flagged as known-bad priors get a heavy boost."],
    ["propagation", "direct neighbors of a seed get +seed × 10, two-hop neighbors get +seed × 4. Associates of known-bad light up."],
  ]) {
    const li = elt("li", undefined);
    li.appendChild(elt("strong", undefined, label));
    li.appendChild(document.createTextNode(` — ${text}`));
    ul.appendChild(li);
  }
  bodyEl.appendChild(ul);
  const seedNote = elt("p", "fc-method-seed");
  seedNote.appendChild(elt("strong", undefined, "[SEED]"));
  seedNote.appendChild(
    document.createTextNode(" = entity matched a name in your case-file priors. Not auto-discovered — you told the system this one matters."),
  );
  bodyEl.appendChild(seedNote);
  det.appendChild(bodyEl);
  return det;
}

// ---- Runs & findings page ----

export function renderRunsPage(d: PageDeps): HTMLElement {
  // D6: head counts are GATE-FAITHFUL (re-gated runEntities), not the raw listRuns counts — so the
  // collapsed head and the expanded detail always agree (a forged-promoted shows as a lead in both).
  // This is cheap (re-gates findings only, never touches steps); the expensive step trail stays lazy.
  const summaries = listRuns(d.vault).map((r) => {
    const ents = runEntities(d.vault, r.objective);
    const promoted = ents.filter((e) => e.promoted).length;
    return { objective: r.objective, stopReason: r.stopReason, promoted, leads: ents.length - promoted };
  });
  const total = summaries.reduce((a, s) => a + s.promoted, 0);
  const { page, body } = pageShell("Runs & findings", `${summaries.length} run(s) · ${total} promoted finding(s)`);
  if (!summaries.length) {
    emptyNote(body, "No runs yet. Investigate something in the Workspace.");
    return page;
  }
  for (const r of summaries) {
    const card = elt("div", "run-card");
    const head = elt("button", "run-head");
    head.appendChild(elt("span", "run-obj", r.objective));
    const meta = elt("span", "run-meta");
    meta.appendChild(chip(`${r.promoted} promoted`, "ok"));
    meta.appendChild(chip(`${r.leads} leads`, "warn"));
    // ux (brief §Runs #3): the raw `end_turn` stop-reason is internal LLM jargon — show "complete".
    meta.appendChild(chip(r.stopReason === "end_turn" ? "complete" : r.stopReason));
    // ux (brief §Runs #3): a visible affordance so the analyst knows the card expands into the step trail.
    const trailHint = elt("span", "run-trail-hint", "View step trail ›");
    meta.appendChild(trailHint);
    head.appendChild(meta);
    card.appendChild(head);

    const detail = elt("div", "run-detail");
    detail.hidden = true;
    let built = false;
    head.addEventListener("click", () => {
      // D8: runDetail (steps redaction + attribution) runs ONLY on first expand, cached per card.
      if (!built) {
        buildRunDetail(d, detail, r.objective);
        built = true;
      }
      detail.hidden = !detail.hidden;
      trailHint.textContent = detail.hidden ? "View step trail ›" : "Hide step trail ▾";
    });
    card.appendChild(detail);
    body.appendChild(card);
  }
  return page;
}

// r1-page: build the expandable run detail — the real step trail (what it did) + findings attributed
// to the step that produced them (what it found) + a deterministic bottom line. All text via the
// textContent-only elt helper, so a hostile entity/result value is literal text (D10).
function buildRunDetail(d: PageDeps, detail: HTMLElement, objective: string): void {
  const rd = runDetail(d.vault, objective);
  if (!rd) {
    detail.appendChild(elt("p", "run-muted", "Run detail unavailable."));
    return;
  }

  // sf-findings: the Trail|Findings view toggle (mirrors runs.html:120-127). One stage, two emphases of
  // the SAME data — Trail reads the narrative; Findings is the flat promotable list. Default TRAIL — the
  // client's route is /runs, whose original default IS the trail (runs.html:387 default_view='trail');
  // the original /findings 302-redirects to /runs?view=findings, which here is the Findings toggle. So a
  // plain /runs visit shows the trail (faithful to /runs); the Findings view is one click away. The
  // findings list itself renders in BOTH views (only the trail toggles). CSP-safe: DOM .hidden +
  // addEventListener, no inline handler.
  const toggle = elt("div", "run-view-toggle");
  const trailBtn = elt("button", "run-view-btn active", "Trail");
  const findBtn = elt("button", "run-view-btn", "Findings");
  toggle.appendChild(trailBtn);
  toggle.appendChild(findBtn);
  detail.appendChild(toggle);

  // What it did — the agent's real step trail (shown by default; the Findings toggle hides it).
  const trailSection = elt("div", "run-trail-section");
  trailSection.hidden = false; // default Trail → trail shown (faithful to the original /runs default)
  trailSection.appendChild(elt("div", "run-section-head", `What it did · ${rd.steps.length} step${rd.steps.length === 1 ? "" : "s"}`));
  if (!rd.steps.length) {
    trailSection.appendChild(elt("p", "run-muted", "No step-by-step trail recorded for this run."));
  } else {
    const trail = elt("div", "run-trail");
    for (const s of rd.steps) trail.appendChild(trailStepRow(s));
    trailSection.appendChild(trail);
  }
  detail.appendChild(trailSection);

  const setView = (view: "trail" | "findings"): void => {
    trailSection.hidden = view === "findings";
    trailBtn.className = view === "trail" ? "run-view-btn active" : "run-view-btn";
    findBtn.className = view === "findings" ? "run-view-btn active" : "run-view-btn";
  };
  trailBtn.addEventListener("click", () => setView("trail"));
  findBtn.addEventListener("click", () => setView("findings"));

  // What it found — the rich findings list (always shown).
  detail.appendChild(elt("div", "run-section-head", `What it found · ${rd.findings.length}`));
  if (!rd.findings.length) {
    detail.appendChild(elt("p", "run-muted", "This run surfaced no findings."));
  } else {
    const list = elt("div", "run-finding-list");
    for (const f of rd.findings) list.appendChild(findingRow(f));
    detail.appendChild(list);
  }

  // Discovered assets — a projection over the step trail (always shown).
  if (rd.assets.length) {
    detail.appendChild(elt("div", "run-section-head", `Discovered assets · ${rd.assets.length}`));
    const box = elt("div", "run-asset-list");
    for (const a of rd.assets) box.appendChild(assetRow(a));
    detail.appendChild(box);
  }

  // Next moves — deterministic next-moves over the run's leads (only when there are leads to chase).
  if (rd.pivots.length) detail.appendChild(pivotsBlock(rd.pivots));

  // Bottom line — deterministic, no model call.
  const bl = elt("div", "run-bottomline");
  bl.appendChild(elt("div", "run-bottomline-label", "Bottom line"));
  bl.appendChild(elt("div", "run-bottomline-text", rd.bottomLine));
  detail.appendChild(bl);
}

// sf-findings: the confidence pill class — EXACT color map per runs.html:267-268:
//   high → role-infra (green), low → role-source (slate), medium (and any other) → role-operator (amber).
function confidenceClass(confidence?: string): string {
  const c = (confidence ?? "medium").toLowerCase();
  if (c === "high") return "role-infra";
  if (c === "low") return "role-source";
  return "role-operator"; // medium + any unexpected value (matches the runs.html else branch)
}

// sf-findings: strip a SINGLE leading block-marker (- / * / # / > / |) from the claim's first line so the
// INLINE renderMarkdown does not promote a one-sentence claim into a list/heading/table — while inline
// marks (**bold**, `code`) still render. renderMarkdown escapes first regardless, so this is XSS-safe.
function claimForInline(claim: string): string {
  return claim.replace(/^\s*(?:[-*>]\s+|#{1,6}\s+|\|\s*)/, "");
}

function trailStepRow(s: DisplayStep): HTMLElement {
  const row = elt("div", `trail-step ${s.kind}`);
  row.appendChild(elt("span", "trail-dot"));
  if (s.kind === "tool") {
    const headRow = elt("div", "trail-tool-head");
    headRow.appendChild(elt("span", "trail-n", `#${s.n}`));
    headRow.appendChild(elt("span", `trail-tool${s.isError ? " err" : ""}`, s.tool ?? ""));
    if (s.inputText) headRow.appendChild(elt("span", "trail-input", s.inputText));
    row.appendChild(headRow);
    if (s.resultText) row.appendChild(elt("div", "trail-result", `→ ${s.resultText}`));
  } else {
    const reason = elt("div", "trail-reason");
    reason.appendChild(elt("span", "trail-n", `#${s.n}`));
    reason.appendChild(elt("span", "trail-text", s.text ?? ""));
    row.appendChild(reason);
  }
  if (s.truncated) row.appendChild(elt("span", "trail-trunc", "(truncated)"));
  return row;
}

// sf-findings: the RICH finding row (the runs.html "What it found" parity — runs.html:262-286), replacing
// the old one-line dot row. Renders: the confidence pill (color-mapped EXACTLY high→role-infra /
// low→role-source / medium→role-operator), the entity value as the title, the agent's `claim` as an
// INLINE-markdown summary (escape-first XSS-safe; a leading -/#/| does not become a list/heading/table;
// ABSENT for ingest findings with no claim), the real provenance line (from step N · tool), and the
// promoted "✓ on graph" state. The Save→promote button is the ONE signed divergence (gate-decided
// promotion + corrections-as-authority); the on-graph state is its present-and-functional analog.
function findingRow(f: AttributedEntity): HTMLElement {
  const row = elt("div", "run-finding");

  const titleRow = elt("div", "run-finding-title");
  titleRow.appendChild(elt("span", `role-pill ${confidenceClass(f.confidence)}`, (f.confidence ?? "medium").toLowerCase()));
  titleRow.appendChild(elt("span", "run-finding-name", `${f.value} · ${f.type}${f.grade ? ` · ${f.grade}` : ""}`));
  row.appendChild(titleRow);

  // The claim summary — INLINE markdown (escape-first), only when the agent supplied a non-empty claim.
  if (typeof f.claim === "string" && f.claim.trim()) {
    const summary = elt("div", "run-finding-summary markdown");
    summary.innerHTML = renderMarkdown(claimForInline(f.claim)); // escape-first XSS-safe (markdown.ts)
    row.appendChild(summary);
  }

  // Real provenance: the step that produced this finding (never invented — undefined → no line).
  if (f.stepRef) {
    row.appendChild(elt("div", "run-finding-prov", `from step ${f.stepRef}${f.stepTool ? ` · ${f.stepTool}` : ""}`));
  }

  // Promotion: the gate's call. Promoted → on the graph; otherwise it's a held lead (no manual Save
  // button — the signed divergence; see the function header).
  row.appendChild(elt("div", `run-finding-state ${f.promoted ? "on-graph" : "lead"}`, f.promoted ? "✓ on graph" : "lead — held for corroboration"));
  return row;
}

// sf-findings: one Discovered-assets row (runs.html:299-314) — projected over the step trail. Shows the
// asset value, its type, the on-graph vs surfaced-only state (the REAL gate signal — no fabricated
// live/dead), whether the agent chased it, the found-via step, and the tools it was checked with.
function assetRow(a: DiscoveredAsset): HTMLElement {
  const row = elt("div", "run-asset");
  const head = elt("div", "run-asset-head");
  head.appendChild(elt("span", "run-asset-name", a.asset));
  if (a.type) head.appendChild(elt("span", "run-asset-type", a.type));
  head.appendChild(
    a.onGraph
      ? elt("span", "run-asset-badge on-graph", "✓ on graph")
      : elt("span", "run-asset-badge surfaced", "surfaced"),
  );
  head.appendChild(
    a.chased ? elt("span", "run-asset-badge chased", "chased") : elt("span", "run-asset-badge not-chased", "surfaced only — not chased"),
  );
  row.appendChild(head);
  row.appendChild(elt("div", "run-asset-meta", `found via ${a.foundVia ?? "?"} · step ${a.foundStep}`));
  if (a.checkedWith.length) row.appendChild(elt("div", "run-asset-meta", `checked with: ${a.checkedWith.join(", ")}`));
  return row;
}

// sf-findings: the Next-moves block (runs.html:343-374) — the held leads ranked as the entities worth
// chasing next. The original's reachability now/blocked split is a server feature (recommended_pivots +
// a reachability classifier the browser agent doesn't emit) — documented as a signed divergence in the
// manifest; this is the faithful client-first analog: one honest "chase to corroborate" list.
function pivotsBlock(pivots: Pivot[]): HTMLElement {
  const block = elt("div", "run-pivots");
  block.appendChild(elt("div", "run-section-head", "Next moves · chase to corroborate"));
  const box = elt("div", "run-pivot-list");
  for (const p of pivots) {
    const row = elt("div", "run-pivot now");
    row.appendChild(elt("span", "run-pivot-entity", `${p.entity} · ${p.type}`));
    row.appendChild(elt("span", "run-pivot-why", p.reason));
    box.appendChild(row);
  }
  block.appendChild(box);
  return block;
}

// ---- Deliverables page (briefs) ----

// sf-deliverables: the /deliverables surface = the faithful clone of the original /synthesis page —
// the case brief rendered as MARKDOWN (not the old raw <pre>), a Regenerate-brief affordance, and a
// stale banner. (The /briefs grouped-relatedness viewer is the separate sf-briefs row.)
export function renderDeliverablesPage(d: PageDeps): HTMLElement {
  const briefs = listBriefs(d.vault);
  const { page, body } = pageShell("Deliverables", `${briefs.length} brief(s)`);

  // Regenerate affordance (mirrors synthesis.html:9-21) — gated on a vault/case (always one here).
  const hasCaseBrief = getBrief(d.vault, CASE_BRIEF_KEY) != null;
  const regen = elt("div", "del-regen");
  regen.appendChild(elt("div", "del-regen-hint",
    "The written brief — built from the case's reports + promoted findings. Regenerate rewrites it with the latest findings."));
  const status = elt("div", "del-regen-status");
  const btn = elt("button", "pg-btn primary", hasCaseBrief ? "Regenerate brief" : "Generate brief") as HTMLButtonElement;
  btn.addEventListener("click", async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    btn.textContent = "Regenerating… (LLM pass, ~30s)"; // busy label, faithful to synthesis.html:17
    status.textContent = "";
    status.className = "del-regen-status";
    try {
      await d.synthesize(); // single-writer brief:case (app.ts owns the vault + the offline seam)
      status.textContent = "Brief ready — reloading…";
      status.className = "del-regen-status ok";
      d.navigate("/deliverables"); // re-render with the fresh brief
    } catch (e) {
      // surface the no-key SessionError (and any failure) inline — never a silent no-op
      status.textContent = e instanceof Error ? e.message : "Generation failed";
      status.className = "del-regen-status err";
      btn.disabled = false;
      btn.textContent = hasCaseBrief ? "Regenerate brief" : "Generate brief";
    }
  });
  regen.appendChild(btn);
  regen.appendChild(status);
  body.appendChild(regen);

  // Stale banner for the case brief (mirrors synthesis.html:23-35) — fires when newer reports exist.
  const stale = d.briefStale(CASE_BRIEF_KEY);
  if (stale && stale.live > stale.builtOn) {
    const banner = elt("div", "del-stale");
    const staleIcon = elt("span", "del-stale-icon");
    staleIcon.innerHTML = '<svg class="ico" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    banner.appendChild(staleIcon);
    const txt = elt("div", "del-stale-text");
    txt.appendChild(elt("div", "del-stale-title", "Brief is stale"));
    txt.appendChild(elt("div", "del-stale-body",
      `Built on ${stale.builtOn} report${stale.builtOn === 1 ? "" : "s"}; there ${stale.live === 1 ? "is" : "are"} now ${stale.live}. Regenerate to fold in the newer reports.`));
    banner.appendChild(txt);
    body.appendChild(banner);
  }

  // sf-briefs: the grouped-relatedness trigger (the ./invctl briefs analog — a BUTTON, not a Process step;
  // independent of the case brief, so it sits before the no-brief early return).
  // ux (brief §Deliverables #8): "Generate brief" above is the primary deliverable; this relatedness
  // grouping is an ADVANCED action — set apart under a divider so it doesn't compete for the primary slot.
  const group = elt("div", "del-regen del-advanced");
  group.appendChild(elt("div", "del-divider-label", "Advanced"));
  group.appendChild(elt("div", "del-regen-hint",
    "Group related reports — cluster the case's reports by shared entities + clusters into relatedness briefs (meaningful after Process tags roles + clusters)."));
  const gstatus = elt("div", "del-regen-status");
  const gHas = listGroupBriefs(d.vault).groups.length > 0;
  const gbtn = elt("button", "pg-btn", gHas ? "Regroup reports" : "Group related reports") as HTMLButtonElement;
  gbtn.addEventListener("click", async () => {
    if (gbtn.disabled) return;
    gbtn.disabled = true;
    gbtn.textContent = "Grouping reports… (LLM pass)";
    gstatus.textContent = "";
    gstatus.className = "del-regen-status";
    try {
      const r = await d.groupBriefs();
      gstatus.textContent = `Grouped: ${r.groups} group(s)${r.standalone ? ` + ${r.standalone} standalone` : ""} — opening…`;
      gstatus.className = "del-regen-status ok";
      d.navigate("/briefs");
    } catch (e) {
      gstatus.textContent = e instanceof Error ? e.message : "Grouping failed";
      gstatus.className = "del-regen-status err";
      gbtn.disabled = false;
      gbtn.textContent = gHas ? "Regroup reports" : "Group related reports";
    }
  });
  group.appendChild(gbtn);
  group.appendChild(gstatus);
  body.appendChild(group);

  if (!briefs.length) {
    emptyNote(body, "No brief yet. Run Process, or hit Generate brief above.");
    return page;
  }

  for (const obj of briefs) {
    const card = elt("div", "del-card");
    const head = elt("div", "del-head");
    head.appendChild(elt("span", "del-obj", obj));
    const dl = elt("button", "pg-btn", "Download .md");
    head.appendChild(dl);
    card.appendChild(head);
    const md = (getBrief(d.vault, obj) ?? "(brief unavailable)").slice(0, BRIEF_CAP);
    // MARKDOWN render (escape-first XSS-safe renderBriefMarkdown), replacing the old raw <pre>. The
    // Download stays bound to the SAME truncated `md` so view + download agree (review finding 9).
    const bodyDiv = elt("div", "markdown del-body");
    bodyDiv.innerHTML = renderBriefMarkdown(md);
    card.appendChild(bodyDiv);
    dl.addEventListener("click", () => d.download(`${slug(obj)}.md`, new TextEncoder().encode(md)));
    body.appendChild(card);
  }

  // [[entity]] click delegate — NO inline onclick (CSP); a .brief-entity click navigates to /entities
  // (mirrors the chat dock .chat-node delegate). Links never break the page.
  body.addEventListener("click", (ev) => {
    const target = (ev.target as HTMLElement).closest(".brief-entity");
    if (target) {
      ev.preventDefault();
      d.navigate("/entities");
    }
  });
  return page;
}

function slug(s: string): string {
  return s.replace(/[^a-z0-9]+/gi, "-").replace(/^-+|-+$/g, "").slice(0, 60).toLowerCase() || "brief";
}

// ---- sf-briefs: the grouped relatedness briefs viewer (/briefs) — the faithful clone of the original
// briefs.html LIST + brief.html DETAIL, folded onto ONE route with an INLINE-EXPAND card (the client
// router is exact-Set-match — no parameterized route; this is the same expandable-card pattern as /runs).
// The four parse helpers mirror briefs.html:51-78 exactly so the badge/preview/count read the same.

function briefTitle(c: string): string {
  const m = c.match(/^# (.+)$/m);
  return m ? m[1] : "Brief";
}
function briefVerdict(c: string): string {
  const m = c.match(/\*\*Relatedness verdict:\*\* (\w+)/);
  return m ? m[1] : "unknown";
}
function briefSummaryPreview(c: string): string {
  const m = c.match(/## Summary\n\n([\s\S]+?)(\n\n##|$)/);
  if (!m) return "";
  return m[1].slice(0, 280) + (m[1].length > 280 ? "…" : "");
}
function briefReportsLine(c: string): string {
  const m = c.match(/\*\*Reports in group:\*\* (\d+)/);
  const w = c.match(/\*\*Time window:\*\* (.+)/);
  return (m ? `${m[1]} reports` : "") + (w ? ` · ${w[1]}` : "");
}
function verdictBadgeClass(v: string): string {
  return `brief-badge brief-badge-${["strong", "weak", "disjoint"].includes(v) ? v : "unknown"}`;
}

function expandableBriefCard(content: string, title: string, badgeText: string, badgeClass: string, preview: string, reportsLine: string): HTMLElement {
  const card = elt("div", "del-card");
  const head = elt("button", "brief-head") as HTMLButtonElement;
  const left = elt("div", "brief-head-left");
  left.appendChild(elt("span", "del-obj", title));
  left.appendChild(elt("span", badgeClass, badgeText));
  head.appendChild(left);
  head.appendChild(elt("span", "brief-toggle", "expand"));
  card.appendChild(head);
  if (preview || reportsLine) {
    const meta = elt("div", "brief-meta");
    if (preview) meta.appendChild(elt("div", "brief-preview", preview)); // the ## Summary preview (briefs.html:27)
    if (reportsLine) meta.appendChild(elt("div", "brief-reports", reportsLine));
    card.appendChild(meta);
  }
  // INLINE DETAIL: the full group markdown, rendered via the escape-first renderBriefMarkdown, hidden
  // until the header is clicked (CSP-safe — a DOM .hidden toggle, no inline handler).
  const detail = elt("div", "markdown del-body brief-detail");
  detail.hidden = true;
  detail.innerHTML = renderBriefMarkdown(content);
  card.appendChild(detail);
  head.addEventListener("click", () => {
    detail.hidden = !detail.hidden;
    (head.lastElementChild as HTMLElement).textContent = detail.hidden ? "expand" : "collapse";
  });
  return card;
}

export function renderGroupedBriefsPage(d: PageDeps): HTMLElement {
  const { groups, standalone } = listGroupBriefs(d.vault);
  const { page, body } = pageShell("Briefs", "Grouped relatedness briefs — each covers reports the system found connected. Standalone = no significant overlap.");
  if (!groups.length && !standalone) {
    emptyNote(body, "No grouped briefs yet. Hit 'Group related reports' on Deliverables (meaningful after Process tags roles + clusters).");
    return page;
  }
  for (const g of groups) {
    const v = briefVerdict(g.content);
    body.appendChild(expandableBriefCard(g.content, briefTitle(g.content), v, verdictBadgeClass(v), briefSummaryPreview(g.content), briefReportsLine(g.content)));
  }
  if (standalone) {
    const n = standalone.content.split("\n").filter((l) => l.startsWith("- ")).length;
    body.appendChild(expandableBriefCard(standalone.content, "Standalone reports", "no overlap", "brief-badge brief-badge-unknown", "", `${n} report${n === 1 ? "" : "s"} with no significant overlap`));
  }
  return page;
}

// ---- Cross-case page (entities shared across runs) ----

export function renderCrossCasePage(d: PageDeps): HTMLElement {
  const store = entityDbFor(d.vault, null);
  const cross = crossRunEntities(store);
  const { page, body } = pageShell("Cross-case", "Entities that appear in more than one run — the overlap between your investigations");
  if (!cross.length) {
    emptyNote(body, "No cross-run overlap yet. It appears once an entity shows up in two or more runs.");
    return page;
  }
  for (const e of cross) {
    const row = elt("div", "xc-row");
    row.appendChild(elt("span", "ent-name", e.label));
    row.appendChild(chip(e.type || e.role));
    row.appendChild(chip(`${e.runs.length} runs`, "ok"));
    const runs = elt("div", "xc-runs");
    for (const r of e.runs.slice(0, 8)) runs.appendChild(elt("span", "xc-run", r));
    row.appendChild(runs);
    body.appendChild(row);
  }
  return page;
}

// ig-wire: the REAL upload/process surface — a PDF/CSV/XLSX/TXT file picker + a paste box, extracted
// 100% in the browser. The async ingest deps route through app.ts (which owns the vault + the
// file→text layer); pages.ts never touches the vault/key directly.
// pf-process (INC-1): the Process pipeline panel — mirrors the server _process_panel.html (button +
// step checklist ◐→✓/⊘ + progress bar + live log tail), but the job runs CLIENT-SIDE (in-browser LLM
// passes). The app-level job state is the source of truth (PRD D8): the panel subscribes for live
// updates + paints on each push, so navigating away + back resumes the running job's live state.
function renderProcessPanel(d: PageDeps): HTMLElement {
  const sec = elt("div", "proc-panel");

  const head = elt("div", "proc-head");
  const titleWrap = elt("div", "proc-titlewrap");
  titleWrap.appendChild(elt("div", "proc-title", "Process this case"));
  titleWrap.appendChild(
    elt("div", "proc-hint", "Models the case schema, then classifies + de-dupes entities (AI roles + types). Runs in your browser — safe to switch tabs."),
  );
  const schemaLine = elt("div", "proc-schema");
  titleWrap.appendChild(schemaLine);
  head.appendChild(titleWrap);
  // sp-b90618a0: ONE primary action per screen. Intake (Process file) is step 1 and the sole primary; the
  // case-level analysis is step 2 — secondary, and it auto-runs after intake anyway (scheduleAutoProcess),
  // so a co-equal teal button here only manufactured decision-paralysis at intake. Demoted to secondary.
  const btn = elt("button", "pg-btn proc-btn", "Process case") as HTMLButtonElement;
  head.appendChild(btn);
  // post-audit issue 2: surface the already-wired abort path. PageDeps.abortProcess (app.ts) aborts a real
  // AbortController but was never reachable from the UI — a 10-12min Process run (consolidate alone) could
  // only be stopped by switching case. The Stop button shows only while a run is in progress.
  const stopBtn = elt("button", "pg-btn proc-stop-btn", "Stop") as HTMLButtonElement;
  stopBtn.style.display = "none";
  stopBtn.addEventListener("click", () => d.abortProcess());
  head.appendChild(stopBtn);
  sec.appendChild(head);

  const prog = elt("div", "proc-progress");
  sec.appendChild(prog);

  // codex MAJOR (D6 "exists for no one"): surface the FULL modeled schema the understand pass produced —
  // the discovered roles (weight + actor), entity types, sub-roles, and noise rules — not just a one-line
  // count. The analyst sees the case data model now; INC-3's analyze pass consumes the same record.
  const schemaDetail = elt("div", "proc-schema-detail");
  sec.appendChild(schemaDetail);

  const taxRow = (label: string, items: string[]): HTMLElement | null => {
    if (!items.length) return null;
    const row = elt("div", "proc-tax-row");
    row.appendChild(elt("span", "proc-tax-label", label));
    const vals = elt("span", "proc-tax-vals");
    for (const it of items) vals.appendChild(elt("span", "proc-tax-chip", it)); // textContent — literal
    row.appendChild(vals);
    return row;
  };

  const refreshSchema = (): void => {
    const s = d.schemaSummary();
    schemaLine.textContent = s ? `Modeled: ${s}` : "";
    schemaLine.style.display = s ? "" : "none";

    schemaDetail.replaceChildren();
    const sc = d.schemaDetail();
    if (!sc) {
      schemaDetail.style.display = "none";
      return;
    }
    schemaDetail.style.display = "";
    if (sc.summary) schemaDetail.appendChild(elt("div", "proc-tax-summary", sc.summary));
    const roleRow = taxRow(
      "Roles",
      sc.roles.map((r) => `${r.name}${r.actor ? " (actor)" : ""} · w${r.weight}`),
    );
    if (roleRow) schemaDetail.appendChild(roleRow);
    const etRow = taxRow("Entity types", sc.entityTypes.map((t) => t.name));
    if (etRow) schemaDetail.appendChild(etRow);
    const srRow = taxRow("Sub-roles", sc.subRoles.map((r) => r.name));
    if (srRow) schemaDetail.appendChild(srRow);
    if (sc.noiseNotes) {
      const nr = elt("div", "proc-tax-row");
      nr.appendChild(elt("span", "proc-tax-label", "Noise"));
      nr.appendChild(elt("span", "proc-tax-note", sc.noiseNotes)); // textContent — literal
      schemaDetail.appendChild(nr);
    }
  };

  const stepIcon = (status: ProcessStepStatus): string =>
    status === "ok" ? "✓" : status === "skipped" ? "⊘" : status === "running" ? "◐" : status === "error" ? "✕" : "○";

  const paint = (state: ProcessUiState): void => {
    const running = state.status === "running";
    btn.disabled = running;
    stopBtn.style.display = running ? "" : "none"; // post-audit issue 2: Stop reachable only mid-run
    btn.textContent = running ? "Processing…" : state.status === "done" ? "Re-process" : "Process case";
    prog.replaceChildren();
    refreshSchema();
    if (state.status === "idle") return;

    const done = state.steps.filter((s) => s.status === "ok" || s.status === "skipped").length;
    const total = state.steps.length || 1;
    const pct = Math.round((done / total) * 100);

    const meta = elt("div", "proc-meta");
    meta.appendChild(elt("span", "", `${running ? "Running" : state.status === "error" ? "Stopped" : "Last run"} · ${done}/${total} steps`));
    meta.appendChild(elt("span", "proc-pct", `${pct}%`));
    prog.appendChild(meta);

    const barWrap = elt("div", "proc-bar");
    const bar = elt("div", "proc-bar-fill");
    bar.style.width = `${pct}%`;
    barWrap.appendChild(bar);
    prog.appendChild(barWrap);

    const ul = elt("ul", "proc-steps");
    for (const s of state.steps) {
      const li = elt("li", `proc-step proc-${s.status}`);
      li.appendChild(elt("span", "proc-step-icon", stepIcon(s.status)));
      li.appendChild(elt("span", "proc-step-label", s.label));
      ul.appendChild(li);
    }
    prog.appendChild(ul);

    if (state.log.length) {
      prog.appendChild(elt("div", "proc-log-label", running ? "Live activity · streaming…" : "Activity"));
      const box = elt("div", "proc-log");
      for (const line of state.log) box.appendChild(elt("div", "proc-log-line", line)); // textContent — literal
      prog.appendChild(box);
      box.scrollTop = box.scrollHeight; // auto-scroll to newest
    }
    if (state.status === "error" && state.error) prog.appendChild(elt("div", "proc-err", state.error));
  };

  btn.addEventListener("click", async () => {
    if (btn.disabled) return;
    try {
      await d.startProcess();
    } catch (err) {
      prog.appendChild(elt("div", "proc-err", err instanceof Error ? err.message : String(err)));
    }
  });

  d.subscribeProcess(paint); // app.ts pushes live state here; a re-mount re-subscribes (no stale-DOM leak)
  paint(d.processState()); // initial paint (resumes a running job's state on re-mount)
  return sec;
}

export function renderReportsPage(d: PageDeps): HTMLElement {
  const { page, body } = pageShell(
    "Reports & intake",
    "Upload a PDF / CSV / XLSX / text file, or paste text. Entities are extracted in your browser — nothing leaves.",
  );
  body.appendChild(renderProcessPanel(d)); // pf-process: the Process pipeline lives at the top of /reports
  const card = elt("div", "intake-card");

  const fileRow = elt("div", "intake-row");
  const fileInput = elt("input", "intake-file") as HTMLInputElement;
  fileInput.type = "file";
  fileInput.accept = ".pdf,.csv,.tsv,.xlsx,.txt,.md,.json,.log,.png,.jpg,.jpeg,.tif,.tiff,.webp,.bmp,.gif";
  const fileBtn = elt("button", "pg-btn primary", "Process file") as HTMLButtonElement;
  fileRow.appendChild(fileInput);
  fileRow.appendChild(fileBtn);
  card.appendChild(fileRow);

  const ta = elt("textarea", "intake-paste") as HTMLTextAreaElement;
  ta.placeholder = "…or paste text (a report, a WHOIS dump, a list of indicators)";
  ta.rows = 6; // cl-ui: was browser-default (~2 rows) + the button overlapped — give it room
  card.appendChild(ta);
  // sp-b90618a0: paste is the ALTERNATIVE intake path — secondary to the file picker (the one primary on
  // this screen). Same action (extract entities), de-emphasized so the screen has a single clear next step.
  const pasteBtn = elt("button", "pg-btn", "Process pasted text") as HTMLButtonElement;
  card.appendChild(pasteBtn);

  const out = elt("div", "intake-out");
  card.appendChild(out);
  body.appendChild(card);

  const report = (r: IngestResult): void => {
    // sp-2942cb65 + d2b98925 (discovery-grow): an upload no longer dumps every entity onto the graph — the
    // extracted entities surface as LEADS in Entities/Reports and the graph GROWS as you investigate. Say
    // that honestly instead of promising nodes on the graph that (by design) do not appear on upload.
    out.textContent = `Extracted ${r.count} entit${r.count === 1 ? "y" : "ies"} into "${r.objective}" — see them in Entities & Reports. The graph grows as you investigate (Process assigns roles; a dig promotes leads to nodes).`;
    renderReportsTable(); // a successful ingest must show up in the table below without a remount
  };
  const fail = (e: unknown): void => { out.textContent = e instanceof Error ? e.message : String(e); };

  async function withBusy(btn: HTMLButtonElement, label: string, fn: () => Promise<void>): Promise<void> {
    if (btn.disabled) return;
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = label;
    try {
      await fn();
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  fileBtn.addEventListener("click", () =>
    withBusy(fileBtn, "Processing…", async () => {
      const f = fileInput.files?.[0];
      if (!f) { out.textContent = "Pick a file first."; return; }
      try { report(await d.ingestFile(f)); } catch (e) { fail(e); }
    }),
  );
  pasteBtn.addEventListener("click", () =>
    withBusy(pasteBtn, "Processing…", async () => {
      const text = ta.value.trim();
      if (!text) { out.textContent = "Paste some text first."; return; }
      try { report(await d.ingest("pasted text", text)); } catch (e) { fail(e); }
    }),
  );

  // sf-reports: the reports TABLE (the original /reports table) under the intake card + Process panel.
  // One render function, re-run after each successful ingest — the mount-time-only build left
  // "Reports · 0" + stale rows until a remount (codex, kweb-discovery-grow-intake-contract).
  const tableWrap = elt("div", "rep-table-wrap");
  body.appendChild(tableWrap);
  function renderReportsTable(): void {
    tableWrap.replaceChildren();
    const docs = listIngestedDocs(d.vault); // newest-first by ingestedAt
    tableWrap.appendChild(elt("div", "rep-table-head", `Reports · ${docs.length}`));
    tableWrap.appendChild(elt("div", "rep-table-sub", "The evidence in this case. Click a report for its entities, your notes, and your calls."));
    if (!docs.length) {
      emptyNote(tableWrap, "No reports yet. Add evidence above.");
      return;
    }
    const table = elt("div", "rep-table");
    const hr = elt("div", "rep-row rep-row-head");
    for (const [cls, label] of [["title", "Title"], ["type", "Type"], ["inv", "Investigation"], ["ents", "Entities"], ["ing", "Ingested"]] as const) {
      hr.appendChild(elt("span", `rep-cell rep-${cls}`, label));
    }
    table.appendChild(hr);
    for (const doc of docs) table.appendChild(reportRow(d, doc));
    tableWrap.appendChild(table);
  }
  renderReportsTable();
  return page;
}

// sf-reports: one reports-table row — the 5 columns + an INLINE-EXPAND per-report detail (the
// /reports/{} fold; the exact-Set router has no param routes). The detail is built lazily on first open.
function reportRow(d: PageDeps, doc: IngestedDoc): HTMLElement {
  const wrap = elt("div", "rep-item");
  const row = elt("button", "rep-row") as HTMLButtonElement;
  row.appendChild(elt("span", "rep-cell rep-title", doc.title ?? doc.objective));
  const typeCell = elt("span", "rep-cell rep-type");
  if (doc.sourceType) typeCell.appendChild(elt("span", "role-pill role-source", doc.sourceType));
  row.appendChild(typeCell);
  row.appendChild(elt("span", "rep-cell rep-inv", "—")); // the client has no per-report investigation tag (single-case vault)
  row.appendChild(elt("span", "rep-cell rep-ents", String(doc.count)));
  row.appendChild(elt("span", "rep-cell rep-ing", doc.ingestedAt ? doc.ingestedAt.slice(0, 10) : "—"));
  wrap.appendChild(row);

  const detail = elt("div", "rep-detail");
  detail.hidden = true;
  let built = false;
  row.addEventListener("click", () => {
    detail.hidden = !detail.hidden;
    if (!detail.hidden && !built) {
      buildReportRowDetail(d, detail, doc);
      built = true;
    }
  });
  wrap.appendChild(detail);
  return wrap;
}

// sf-report-detail: the per-report detail (the report-detail.html analog) — header meta + the entities
// card + the analyst-overrides card + the autosave notes editor. No raw-text view (source discarded at
// ingest — zero-retention; the extracted entities ARE the retained projection of the pages).
function buildReportRowDetail(d: PageDeps, detail: HTMLElement, doc: IngestedDoc): void {
  const rd = reportDetailFor(d.vault, doc.objective);

  const meta = elt("div", "rep-detail-meta");
  meta.appendChild(elt("span", "rep-meta-item", `${doc.count} entit${doc.count === 1 ? "y" : "ies"}`));
  if (doc.sourceType) meta.appendChild(elt("span", "rep-meta-item", doc.sourceType));
  if (doc.ingestedAt) meta.appendChild(elt("span", "rep-meta-item", `ingested ${doc.ingestedAt.slice(0, 16).replace("T", " ")}`));
  detail.appendChild(meta);

  detail.appendChild(elt("div", "run-section-head", `Entities in this report · ${rd.entities.length}`));
  if (!rd.entities.length) {
    detail.appendChild(elt("p", "run-muted", "No entities extracted from this report."));
  } else {
    const box = elt("div", "rep-ent-list");
    for (const e of rd.entities) box.appendChild(reportEntityRow(d, e));
    detail.appendChild(box);
  }

  if (rd.overrides.length) {
    detail.appendChild(elt("div", "run-section-head", `Your calls on this report's actors · ${rd.overrides.length}`));
    const box = elt("div", "rep-ovr-list");
    for (const o of rd.overrides) {
      const r = elt("div", "rep-ovr");
      r.appendChild(elt("span", "rep-ovr-ent", o.label));
      r.appendChild(elt("span", "rep-ovr-pred", `${o.predicate} = ${o.value}`));
      r.appendChild(elt("span", "rep-ovr-by", `by ${o.author}`));
      box.appendChild(r);
    }
    detail.appendChild(box);
  }

  detail.appendChild(elt("div", "run-section-head", "Your notes on this report"));
  const notes = elt("textarea", "rep-notes") as HTMLTextAreaElement;
  notes.value = d.getReportNotes(doc.objective); // textarea.value — never innerHTML
  notes.placeholder = "Notes on this report (autosaved)…";
  notes.rows = 4;
  detail.appendChild(notes);
  const status = elt("div", "rep-notes-status");
  detail.appendChild(status);
  let timer: ReturnType<typeof setTimeout> | undefined;
  notes.addEventListener("input", () => {
    status.textContent = "saving…";
    status.className = "rep-notes-status";
    if (timer) clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        await d.setReportNotes(doc.objective, notes.value);
        status.textContent = "saved";
        status.className = "rep-notes-status ok";
      } catch (e) {
        status.textContent = e instanceof Error ? e.message : "save failed";
        status.className = "rep-notes-status err";
      }
    }, 600);
  });
}

// sf-report-detail: one entity row in the per-report detail — value·type + role/grade/threat-score chips
// + on-graph state; click navigates to /entities (the client's entity surface; a dedicated /entity/{id}
// page is the separate sf-entity-detail row).
function reportEntityRow(d: PageDeps, e: ReportDetailEntity): HTMLElement {
  const row = elt("button", "rep-ent") as HTMLButtonElement;
  row.appendChild(elt("span", "rep-ent-name", `${e.value} · ${e.type}`));
  if (e.role) row.appendChild(chip(e.role));
  if (e.grade) row.appendChild(chip(e.grade));
  if (typeof e.threatScore === "number") row.appendChild(chip(`score ${e.threatScore.toFixed(2)}`));
  if (e.promoted) row.appendChild(chip("on graph", "ok"));
  row.addEventListener("click", () => d.navigate("/entities"));
  return row;
}

// ig-wire: the ingested documents (run records with sourceKind === 'file_ingest') + their counts.
export function renderInboxPage(d: PageDeps): HTMLElement {
  const docs = listIngestedDocs(d.vault);
  const { page, body } = pageShell("Inbox", `${docs.length} ingested document(s) — extracted into the case`);
  if (!docs.length) {
    emptyNote(body, "No documents ingested yet. Upload or paste evidence in Reports & intake.");
    return page;
  }
  // sf-sources: a Docs / Sources sub-view toggle (no new route — the established inline-fold pattern). Docs
  // = the per-doc expand; Sources = the gallery over the SAME retained docs + their gate-extracted entities.
  const toggle = elt("div", "inbox-toggle");
  const docsBtn = elt("button", "pg-btn primary", "Docs") as HTMLButtonElement;
  const sourcesBtn = elt("button", "pg-btn ghost", "Sources") as HTMLButtonElement;
  toggle.appendChild(docsBtn);
  toggle.appendChild(sourcesBtn);
  body.appendChild(toggle);

  const docsView = elt("div", "inbox-docs");
  for (const doc of docs) {
    const row = elt("div", "inbox-row");
    const top = elt("button", "inbox-top");
    top.appendChild(elt("span", "inbox-name", doc.title ?? doc.objective)); // textContent
    top.appendChild(chip(`${doc.count} entit${doc.count === 1 ? "y" : "ies"}`, "ok"));
    row.appendChild(top);
    const detail = elt("div", "inbox-detail");
    detail.hidden = true;
    let built = false;
    top.addEventListener("click", () => {
      if (!built) {
        buildReportDetail(d, detail, doc.objective);
        built = true;
      }
      detail.hidden = !detail.hidden;
    });
    row.appendChild(detail);
    docsView.appendChild(row);
  }

  const sourcesView = renderSourcesGallery(d);
  sourcesView.hidden = true;
  body.appendChild(docsView);
  body.appendChild(sourcesView);

  const select = (docsOn: boolean): void => {
    docsView.hidden = !docsOn;
    sourcesView.hidden = docsOn;
    docsBtn.className = docsOn ? "pg-btn primary" : "pg-btn ghost";
    sourcesBtn.className = docsOn ? "pg-btn ghost" : "pg-btn primary";
  };
  docsBtn.addEventListener("click", () => select(true));
  sourcesBtn.addEventListener("click", () => select(false));
  return page;
}

// sf-sources: the Sources gallery — a grid/table view of the retained ingested docs + their gate-extracted
// entities, with report / date / entity / text filters (client-side over the redacted sourcesFor projection).
// SIGNED zero-retention divergence: NO page-image thumbnail + NO raw-OCR snippet/lightbox + the text filter
// is scoped to the RETAINED fields (title / sourceType / entity labels), NOT a discarded OCR blob — the
// page image + OCR text are discarded at ingest write (the sf-report-detail "read the pages" ceiling).
function renderSourcesGallery(d: PageDeps): HTMLElement {
  const sources = sourcesFor(d.vault);
  const wrap = elt("div", "src-wrap");
  let view: "grid" | "table" = "grid";
  let fReport = "", fDate = "", fQ = "", fEntity = "";

  // controls row: grid/table toggle + the filters.
  const controls = elt("div", "src-controls");
  const gridBtn = elt("button", "pg-btn primary", "Grid") as HTMLButtonElement;
  const tableBtn = elt("button", "pg-btn ghost", "Table") as HTMLButtonElement;
  controls.appendChild(gridBtn);
  controls.appendChild(tableBtn);

  const reportSel = elt("select", "src-filter") as HTMLSelectElement;
  const allReports = elt("option", "", "all reports") as HTMLOptionElement;
  allReports.value = "";
  reportSel.appendChild(allReports);
  for (const s of sources) {
    const o = elt("option", "", s.title) as HTMLOptionElement;
    o.value = s.objective;
    reportSel.appendChild(o);
  }
  controls.appendChild(reportSel);

  const dateSel = elt("select", "src-filter") as HTMLSelectElement;
  const allDates = elt("option", "", "all dates") as HTMLOptionElement;
  allDates.value = "";
  dateSel.appendChild(allDates);
  for (const dt of [...new Set(sources.map((s) => s.ingestDate).filter(Boolean))].sort().reverse()) {
    const o = elt("option", "", dt) as HTMLOptionElement;
    o.value = dt;
    dateSel.appendChild(o);
  }
  controls.appendChild(dateSel);

  const qInput = elt("input", "src-filter") as HTMLInputElement;
  qInput.type = "text";
  qInput.placeholder = "search title / type / entities…"; // scoped to RETAINED text (no OCR blob — signed)
  controls.appendChild(qInput);

  const entInput = elt("input", "src-filter") as HTMLInputElement;
  entInput.type = "text";
  entInput.placeholder = "filter by entity…";
  controls.appendChild(entInput);
  wrap.appendChild(controls);

  const count = elt("div", "src-count");
  wrap.appendChild(count);
  const listBox = elt("div", "src-list");
  wrap.appendChild(listBox);

  const matches = (s: SourceDoc): boolean => {
    if (fReport && s.objective !== fReport) return false;
    if (fDate && s.ingestDate !== fDate) return false;
    if (fEntity && !s.entities.some((e) => e.label.toLowerCase().includes(fEntity.toLowerCase()))) return false;
    if (fQ) {
      const hay = `${s.title} ${s.sourceType} ${s.entities.map((e) => e.label).join(" ")}`.toLowerCase();
      if (!hay.includes(fQ.toLowerCase())) return false;
    }
    return true;
  };

  const entityChips = (s: SourceDoc): HTMLElement => {
    const chips = elt("div", "src-chips");
    // codex review: DISPLAY-cap the chips at 12 (the original's per-asset LIMIT 12); the FILTER sees the full
    // s.entities set (sourcesFor no longer caps), so an entity beyond the 12th is still filterable.
    for (const e of s.entities.slice(0, 12)) {
      const c = elt("button", `src-chip role-pill role-${e.role || ""}`, e.label) as HTMLButtonElement; // textContent
      c.addEventListener("click", () => d.navigate("/entities")); // the established entity-nav (report-row precedent)
      chips.appendChild(c);
    }
    if (s.entities.length > 12) chips.appendChild(elt("span", "src-chip-more", `+${s.entities.length - 12} more`));
    return chips;
  };

  // codex review: active removable filter chips + a clear-all (the original Sources control surface). Each
  // active filter shows as a removable chip; clear-all resets every control. `refresh` re-syncs the controls,
  // re-renders the active chips, and re-paints the list (assigned below once paint() exists).
  const activeBox = elt("div", "src-active");
  wrap.insertBefore(activeBox, listBox); // active chips sit above the list, below the controls
  let refresh: () => void = () => {};
  const syncControls = (): void => {
    reportSel.value = fReport;
    dateSel.value = fDate;
    qInput.value = fQ;
    entInput.value = fEntity;
  };
  const renderActive = (): void => {
    activeBox.replaceChildren();
    const active: { label: string; clear: () => void }[] = [];
    // report/date chips show their value (derived from REDACTED retained data). The free-text q/entity chips
    // show a GENERIC label, not the raw typed value (codex impl-review): the input box already shows what was
    // typed, and echoing it into a second DOM node would duplicate a key/secret a user might paste by mistake.
    if (fReport) active.push({ label: `report: ${reportSel.options[reportSel.selectedIndex]?.textContent ?? "selected"}`, clear: () => (fReport = "") });
    if (fDate) active.push({ label: `date: ${fDate}`, clear: () => (fDate = "") });
    if (fQ) active.push({ label: "text filter", clear: () => (fQ = "") });
    if (fEntity) active.push({ label: "entity filter", clear: () => (fEntity = "") });
    if (!active.length) return;
    for (const a of active) {
      const c = elt("button", "src-active-chip", `${a.label} ✕`) as HTMLButtonElement; // textContent (XSS-safe)
      c.addEventListener("click", () => { a.clear(); refresh(); });
      activeBox.appendChild(c);
    }
    const clearAll = elt("button", "pg-btn ghost", "Clear all") as HTMLButtonElement;
    clearAll.addEventListener("click", () => { fReport = fDate = fQ = fEntity = ""; refresh(); });
    activeBox.appendChild(clearAll);
  };

  const paint = (): void => {
    const shown = sources.filter(matches);
    count.textContent = `${shown.length} source${shown.length === 1 ? "" : "s"}`;
    listBox.replaceChildren();
    if (!shown.length) {
      emptyNote(listBox, "No sources match the filters.");
      return;
    }
    if (view === "grid") {
      const grid = elt("div", "src-grid");
      for (const s of shown) {
        const card = elt("div", "src-card");
        card.appendChild(elt("div", "src-card-title", s.title));
        card.appendChild(elt("div", "src-card-meta", `${s.sourceType || "doc"} · ${s.ingestDate || "—"} · ${s.entityCount} entit${s.entityCount === 1 ? "y" : "ies"}`));
        card.appendChild(entityChips(s));
        grid.appendChild(card);
      }
      listBox.appendChild(grid);
    } else {
      const table = elt("div", "src-table");
      const hr = elt("div", "src-row src-row-head");
      for (const [cls, label] of [["title", "Source"], ["type", "Type"], ["date", "Ingested"], ["ents", "Entities"]] as const) {
        hr.appendChild(elt("span", `src-cell src-${cls}`, label));
      }
      table.appendChild(hr);
      for (const s of shown) {
        const row = elt("div", "src-row");
        row.appendChild(elt("span", "src-cell src-title", s.title));
        row.appendChild(elt("span", "src-cell src-type", s.sourceType || "—"));
        row.appendChild(elt("span", "src-cell src-date", s.ingestDate || "—"));
        const ents = elt("span", "src-cell src-ents");
        ents.appendChild(entityChips(s));
        row.appendChild(ents);
        table.appendChild(row);
      }
      listBox.appendChild(table);
    }
  };

  refresh = (): void => { syncControls(); renderActive(); paint(); };
  gridBtn.addEventListener("click", () => { view = "grid"; gridBtn.className = "pg-btn primary"; tableBtn.className = "pg-btn ghost"; paint(); });
  tableBtn.addEventListener("click", () => { view = "table"; tableBtn.className = "pg-btn primary"; gridBtn.className = "pg-btn ghost"; paint(); });
  reportSel.addEventListener("change", () => { fReport = reportSel.value; renderActive(); paint(); });
  dateSel.addEventListener("change", () => { fDate = dateSel.value; renderActive(); paint(); });
  qInput.addEventListener("input", () => { fQ = qInput.value; renderActive(); paint(); });
  entInput.addEventListener("input", () => { fEntity = entInput.value; renderActive(); paint(); });
  paint();
  return wrap;
}

// rb-ui: the per-report drill-in — the doc's gate-faithful entities + an analyst-notes editor. Every
// value reaches the DOM via textContent / textarea.value (codex D4); Save AWAITS the write (D5).
function buildReportDetail(d: PageDeps, detail: HTMLElement, objective: string): void {
  const ents = d.reportEntities(objective);
  detail.appendChild(elt("div", "inbox-ents-head", `Entities (${ents.length})`));
  for (const e of ents.slice(0, 100)) {
    detail.appendChild(elt("div", "inbox-ent", `${e.value} · ${e.type || ""} · ${e.promoted ? "promoted" : "lead"}`));
  }
  const noteWrap = elt("div", "report-notes");
  noteWrap.appendChild(elt("div", "dlabel", "Analyst notes"));
  const ta = document.createElement("textarea");
  ta.className = "report-notes-input";
  ta.value = d.getReportNotes(objective); // textarea.value — never innerHTML
  noteWrap.appendChild(ta);
  const save = elt("button", "pg-btn", "Save notes") as HTMLButtonElement;
  const status = elt("span", "report-notes-status");
  save.addEventListener("click", async () => {
    if (save.disabled) return;
    save.disabled = true;
    status.textContent = "Saving…";
    try {
      await d.setReportNotes(objective, ta.value); // D5: confirm only after the write resolves
      status.textContent = "Saved";
    } catch (e) {
      status.textContent = e instanceof Error ? e.message : "could not save";
    } finally {
      save.disabled = false;
    }
  });
  noteWrap.appendChild(save);
  noteWrap.appendChild(status);
  detail.appendChild(noteWrap);
}

// rb-ui: the Alerts page — the "act first" priority list (grade-A + promoted cross-run entities).
// sf-alerts: the priority-actor alerts — HIGH (watchlist / grade-A) + MEDIUM (cross-run) severity tiers,
// each with its alert_type label + an Acknowledge control + Acknowledge-all + a Show-acknowledged toggle
// (the original alerts.html ack / ack-all / open-count depth). Acks persist through d.acknowledgeAlert
// (alert:<id>:ack). All values via textContent; the list re-paints in place after an ack (no global render).
export function renderAlertsPage(d: PageDeps): HTMLElement {
  const { page, body } = pageShell("Alerts", "Priority actors — HIGH (watchlist / grade-A) and MEDIUM (cross-run) entities to act on first");
  let showAcked = false;

  const controls = elt("div", "alert-controls");
  const ackAllBtn = elt("button", "pg-btn", "Acknowledge all") as HTMLButtonElement;
  const toggleLabel = elt("label", "alert-toggle");
  const toggle = elt("input", "alert-toggle-cb") as HTMLInputElement;
  toggle.type = "checkbox";
  toggleLabel.appendChild(toggle);
  toggleLabel.appendChild(elt("span", "", "Show acknowledged"));
  controls.appendChild(ackAllBtn);
  controls.appendChild(toggleLabel);
  body.appendChild(controls);

  const listEl = elt("div", "alert-list");
  body.appendChild(listEl);

  const paint = (): void => {
    const all = d.alerts();
    const open = all.filter((a) => !a.acknowledged);
    ackAllBtn.disabled = open.length === 0;
    listEl.replaceChildren();
    if (!all.length) {
      emptyNote(listEl, "No alerts yet. Run investigations to surface high-confidence, cross-run entities.");
      return;
    }
    listEl.appendChild(elt("div", "alert-count", `${open.length} open · ${all.length - open.length} acknowledged${all.length >= 100 ? " (top 100)" : ""}`));
    const shown = showAcked ? all : open;
    if (!shown.length) {
      emptyNote(listEl, "All alerts acknowledged. Toggle “Show acknowledged” to review them.");
      return;
    }
    for (const a of shown) {
      const card = elt("div", `alert-card sev-${a.severity}${a.acknowledged ? " acked" : ""}`);
      const head = elt("div", "alert-head");
      head.appendChild(elt("span", `alert-sev sev-${a.severity}`, a.severity.toUpperCase()));
      head.appendChild(elt("span", "alert-type", a.alertType === "watchlist" ? "watchlist" : "cross-run"));
      head.appendChild(elt("span", "alert-name", a.label)); // textContent (XSS-safe)
      card.appendChild(head);
      card.appendChild(elt("div", "alert-row", `${a.type || a.role} · grade ${a.grade} · ${a.runs} run(s)`));
      card.appendChild(elt("div", "alert-reason", a.reason));
      if (a.acknowledged) {
        card.appendChild(elt("span", "alert-acked", "✓ acknowledged"));
      } else {
        const ackBtn = elt("button", "pg-btn ghost", "Acknowledge") as HTMLButtonElement;
        ackBtn.addEventListener("click", async () => {
          ackBtn.disabled = true;
          try {
            await d.acknowledgeAlert(a.id);
            paint(); // re-read the ack state in place
          } catch (err) {
            ackBtn.textContent = err instanceof Error ? err.message : "failed";
            ackBtn.disabled = false;
          }
        });
        card.appendChild(ackBtn);
      }
      listEl.appendChild(card);
    }
  };

  ackAllBtn.addEventListener("click", async () => {
    ackAllBtn.disabled = true;
    try {
      await d.acknowledgeAllAlerts(d.alerts().filter((a) => !a.acknowledged).map((a) => a.id));
      paint();
    } catch {
      ackAllBtn.disabled = false;
    }
  });
  toggle.addEventListener("change", () => {
    showAcked = toggle.checked;
    paint();
  });

  paint();
  return page;
}

// en-wire: the REAL enrich surface (replaces the old port-pending info card). (1) A Keys & providers
// list: one row per CORS-open provider with a write-only masked key field + Save + Test + a status
// chip. (2) An enrich-a-target action over the configured providers. (3) A blocked-providers section,
// honestly labeled "needs the optional proxy tier (not built)" — never a dead button. The page reads
// ONLY through the app.ts-supplied deps; it never builds a client or touches the vault/key directly,
// and every value reaches the DOM via textContent / placeholder.
// ux-enrich (brief §18 P0): infer an entity's type from its value so "run all applicable providers"
// can pick the providers whose targets include it. Mirrors the extractor's coarse buckets (ip / wallet
// / domain); anything else falls through to "domain" but won't match a provider unless one targets it.
function inferEntityType(value: string): string {
  const v = value.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
  // codex: only EVM (0x…40hex) maps to "wallet" — the sole wallet provider is Etherscan (ETH). A BTC/
  // base58 address falls through to "domain", which matches no provider → the honest no-provider message,
  // rather than silently handing a BTC address to the ETH adapter.
  if (/^0x[0-9a-fA-F]{40}$/.test(v)) return "wallet";
  return "domain";
}

// Cap the entity datalist so a large case can't render thousands of <option> nodes (codex). The free
// text input still accepts any target; this only bounds the autocomplete suggestions.
const MAX_ENRICH_DATALIST = 200;

// ux-enrich (brief §18 P0): the entity-first enrichment path. Pick an entity from the case (a datalist
// of its entities) or type a target; "Run all applicable providers" runs every CONFIGURED provider whose
// targets include the entity's type (reusing d.enrich), then shows a per-provider result summary. Keys
// are never read here — d.enrich owns the redacted run path.
function renderEntityEnrich(d: PageDeps, view: ProvidersView): HTMLElement {
  const wrap = elt("div", "enr-entityfirst");
  wrap.appendChild(elt("h2", "enr-h2", "Enrich an entity"));
  wrap.appendChild(
    elt("p", "enr-ef-sub", "Pick an entity from the case (or type a target), then run every configured provider that applies to its type."),
  );

  const store = entityDbFor(d.vault, null);
  const typeByValue = new Map<string, string>();
  const datalist = elt("datalist") as HTMLDataListElement;
  datalist.id = "enr-ent-list";
  const ents = allEntities(store);
  for (const e of ents) typeByValue.set(e.ref.value.toLowerCase(), e.ref.type); // type map covers ALL entities
  for (const e of ents.slice(0, MAX_ENRICH_DATALIST)) { // but the autocomplete list is capped (codex)
    const opt = document.createElement("option");
    opt.value = e.ref.value; // textContent-safe: <option value> is an attribute, not parsed HTML
    opt.label = e.ref.type;
    datalist.appendChild(opt);
  }

  const ctrl = elt("div", "enr-ef-ctrl");
  const input = elt("input", "enr-ef-input") as HTMLInputElement;
  input.type = "text";
  input.autocomplete = "off";
  input.placeholder = "entity (ip / domain / wallet)";
  input.setAttribute("list", "enr-ent-list");
  const prefill = d.takePendingEnrich(); // ux-rowmenu: an /entities row "Enrich" prefilled this target
  if (prefill) input.value = prefill;
  const runBtn = elt("button", "pg-btn primary", "Run all applicable providers") as HTMLButtonElement;
  const out = elt("div", "enr-ef-out");

  runBtn.addEventListener("click", async () => {
    const v = input.value.trim();
    if (!v) { out.textContent = "Pick or enter an entity first."; out.className = "enr-ef-out warn"; return; }
    const type = typeByValue.get(v.toLowerCase()) ?? inferEntityType(v);
    const applicable = view.providers.filter((p) => p.configured && p.targets.includes(type));
    if (!applicable.length) {
      out.className = "enr-ef-out warn";
      out.textContent = `No configured provider applies to a ${type}. Configure one below, or this type has no provider.`;
      return;
    }
    await withBtn(runBtn, "Running…", async () => {
      out.className = "enr-ef-out";
      out.replaceChildren();
      out.appendChild(elt("div", "enr-ef-head", `Ran ${applicable.length} provider${applicable.length === 1 ? "" : "s"} on ${v} (${type}):`));
      for (const p of applicable) {
        const line = elt("div", "enr-ef-line");
        line.appendChild(elt("span", "enr-name", p.label)); // textContent — a hostile provider label is literal
        try {
          const r = await d.enrich(p.id, v);
          line.appendChild(chip(`${r.count} result${r.count === 1 ? "" : "s"} (${r.tier})`, "ok"));
        } catch (e) {
          line.appendChild(chip(mapOsintError(e), "warn")); // clu-error-output: 401/NOTOK/network → guidance
        }
        out.appendChild(line);
      }
    });
  });

  ctrl.appendChild(input);
  ctrl.appendChild(datalist);
  ctrl.appendChild(runBtn);
  wrap.appendChild(ctrl);
  wrap.appendChild(out);
  return wrap;
}

// ---- Capabilities page (read-only OSINT catalog) ----
// The "what Hydra can do" surface. Names every capability in the toolkit — the 39 backend
// adapters, the 55+ Apify social layer, the multi-engine search tier — most of which the
// user never saw because only the 8 CORS-open enrich providers had cards. Pure manifest:
// nothing here fetches; the runnable subset lives on /enrich. Data source: osint/catalog.ts.

function capBadge(access: CapAccess): HTMLElement {
  const kind = access === "free" ? "ok" : access === "key" ? "warn" : "";
  const badge = chip(CAP_ACCESS_LABEL[access], kind);
  badge.title = CAP_ACCESS_HINT[access];
  return badge;
}

export function renderCapabilitiesPage(_d: PageDeps): HTMLElement {
  const counts = capabilityCounts();
  const { page, body } = pageShell(
    "OSINT capabilities",
    `${counts.total} capabilities across the toolkit · ${counts.free} free · ${counts.key} add-key · ${counts.pro} pro`,
  );

  // BYO-key promise up top — the one thing a user must understand: nothing is bundled; a
  // capability with a token name is dormant until you add your own key (founder 2026-07-08).
  body.appendChild(elt("p", "cap-byo", CAP_BYO_NOTE));

  // Legend: what each badge means (the three ways you reach a capability).
  const legend = elt("div", "cap-legend");
  for (const access of ["free", "key", "pro"] as CapAccess[]) {
    const row = elt("span", "cap-legend-item");
    row.appendChild(capBadge(access));
    row.appendChild(elt("span", "cap-legend-txt", CAP_ACCESS_HINT[access]));
    legend.appendChild(row);
  }
  body.appendChild(legend);

  for (const group of OSINT_CAPABILITIES) {
    const card = elt("div", "cap-group");
    const head = elt("div", "cap-group-head");
    head.appendChild(elt("h2", "cap-group-title", group.category));
    head.appendChild(chip(String(group.items.length), ""));
    card.appendChild(head);
    card.appendChild(elt("p", "cap-group-blurb", group.blurb));
    const list = elt("div", "cap-list");
    for (const item of group.items) {
      const row = elt("div", "cap-row");
      const main = elt("div", "cap-main");
      main.appendChild(elt("span", "cap-name", item.name));
      main.appendChild(elt("span", "cap-detail", item.detail));
      // Make the token dependency VISIBLE (not a tooltip): a FREE-tool "key" capability says "needs your
      // <TOKEN>" (you add it in the app). A "pro" capability isn't browser-native (proxy / Apify / server-
      // side), so its token lives in the pro tool — it must NOT read like an in-app vault field (free/pro
      // split, founder 2026-07-08: VirusTotal/Exa/Apify were implying an in-app key that isn't the story).
      if (item.keyName) {
        const keyNote =
          item.access === "pro"
            ? `${item.keyName} (in the pro tool)`
            : `needs your ${item.keyName}`;
        main.appendChild(elt("span", "cap-key", keyNote));
      }
      row.appendChild(main);
      const badge = capBadge(item.access);
      if (item.keyName) badge.title = `${CAP_ACCESS_HINT[item.access]} · ${item.keyName}`;
      row.appendChild(badge);
      list.appendChild(row);
    }
    card.appendChild(list);
    body.appendChild(card);
  }
  return page;
}

// founder 2026-07-09: the "Tools we're using" doc page — what the app ACTUALLY runs, split by how you
// reach it (no key / your own key / pro). DERIVED from the live registries (toolInventory), so it can
// never drift from what's wired. Reuses the cap-* styling from the capabilities page (no new CSS).
export function renderToolsPage(_d: PageDeps): HTMLElement {
  const inv = toolInventory();
  const counts = toolInventoryCounts();
  const { page, body } = pageShell(
    "Tools we use",
    `${counts.total} tools this app runs · ${counts.keyless} no key · ${counts.keyed} your key · ${counts.pro} pro`,
  );
  body.appendChild(
    elt(
      "p",
      "cap-byo",
      "Exactly what this app runs, generated from the live tool registry — not a marketing list. No key: runs now, keyless, direct from your browser. Your key: add your own API key on the OSINT page and it turns on. Pro: not browser-native (CORS-blocked or server-side), so it runs through your own Worker proxy in the pro tool.",
    ),
  );

  const sections: { title: string; blurb: string; kind: string; items: { name: string; detail: string }[] }[] = [
    { title: "No key needed", blurb: "Keyless — runs now, direct from your browser.", kind: "ok", items: inv.keyless },
    { title: "With your own key", blurb: "Add your API key on the OSINT page; then it runs browser-direct.", kind: "warn", items: inv.keyed },
    { title: "Pro (via your Worker proxy)", blurb: "Not browser-native — runs server-side / through a proxy, in the pro tool.", kind: "", items: inv.pro },
  ];
  for (const sec of sections) {
    const card = elt("div", "cap-group");
    const head = elt("div", "cap-group-head");
    head.appendChild(elt("h2", "cap-group-title", sec.title));
    head.appendChild(chip(String(sec.items.length), sec.kind));
    card.appendChild(head);
    card.appendChild(elt("p", "cap-group-blurb", sec.blurb));
    const list = elt("div", "cap-list");
    for (const item of sec.items) {
      const row = elt("div", "cap-row");
      const main = elt("div", "cap-main");
      main.appendChild(elt("span", "cap-name", item.name));
      main.appendChild(elt("span", "cap-detail", item.detail));
      row.appendChild(main);
      list.appendChild(row);
    }
    card.appendChild(list);
    body.appendChild(card);
  }
  return page;
}

// free/pro split (founder 2026-07-08): the "Full tool" upsell page — everything a desktop/server
// investigation tool (like four_points) does that this browser app can't. A dedicated sidebar surface (the
// nudge). Read-only manifest; nothing here runs in the browser (that is the point).
export function renderFullToolPage(_d: PageDeps): HTMLElement {
  const { page, body } = pageShell(
    "Full tool",
    `${fullToolCount()} capabilities beyond the free browser app`,
  );

  body.appendChild(elt("p", "cap-byo", FULL_TOOL_NOTE));

  for (const group of FULL_TOOL_CAPABILITIES) {
    const card = elt("div", "cap-group");
    const head = elt("div", "cap-group-head");
    head.appendChild(elt("h2", "cap-group-title", group.category));
    head.appendChild(chip(String(group.items.length), ""));
    card.appendChild(head);
    card.appendChild(elt("p", "cap-group-blurb", group.blurb));
    const list = elt("div", "cap-list");
    for (const item of group.items) {
      const row = elt("div", "cap-row");
      const main = elt("div", "cap-main");
      main.appendChild(elt("span", "cap-name", item.name));
      main.appendChild(elt("span", "cap-detail", item.detail));
      row.appendChild(main);
      row.appendChild(chip("Full tool", "warn")); // every row is a paid-tool capability
      list.appendChild(row);
    }
    card.appendChild(list);
    body.appendChild(card);
  }

  // free/pro split (founder 2026-07-08): the contact bubble — the nudge's call to action. Opens the user's
  // own email client pre-addressed to the founder (a mailto:, no network, no form, no data collection).
  const contact = elt("div", "ft-contact");
  contact.appendChild(elt("div", "ft-contact-title", "Want the full tool?"));
  contact.appendChild(
    elt("p", "ft-contact-body", "Everything above runs in the full investigation tool. Reach out and I'll get you set up."),
  );
  const cta = elt("a", "pg-btn primary", "Contact for more info") as HTMLAnchorElement;
  cta.href = `mailto:assaf@ktlystlabs.com?subject=${encodeURIComponent("Hydra full tool")}`;
  contact.appendChild(cta);
  body.appendChild(contact);

  return page;
}

export function renderEnrichPage(d: PageDeps): HTMLElement {
  const view = d.providers();
  const { page, body } = pageShell(
    "OSINT enrichment",
    "Enrichment runs OSINT tools (whois, DNS, search, threat-intel) on an entity to pull more about it. Your keys, called direct from your browser — nothing reaches the founder.",
  );

  // clu-workspace-nav: Capabilities is not in the 3-link sidebar (founder 2026-07-08), so it stays reachable
  // via this in-context link from the OSINT page (its natural home — it catalogs the full OSINT toolkit).
  const capLink = elt("a", "enr-cap-link", "See the full capability catalog →") as HTMLAnchorElement;
  capLink.href = "#/capabilities";
  capLink.setAttribute("data-route", "/capabilities");
  body.appendChild(capLink);

  // Stats header (parity with the original). No $ — the BYO-key client never meters cost; the provider
  // bills the user directly (founder 2026-06-18). run count + entities-enriched are the client analogs.
  const stats = d.enrichStats();
  const statHdr = elt("div", "enr-stats");
  statHdr.appendChild(elt("span", "enr-stat", `${stats.runCount} run${stats.runCount === 1 ? "" : "s"}`));
  statHdr.appendChild(elt("span", "enr-stat", `${stats.distinctEntities} entit${stats.distinctEntities === 1 ? "y" : "ies"} enriched`));
  body.appendChild(statHdr);

  // ux-enrich (brief §18 P0): the entity-first path leads — pick/type an entity → run every CONFIGURED
  // provider that applies to its type. The recurring verb, above the (now collapsed) per-provider config.
  body.appendChild(renderEntityEnrich(d, view));

  // Provider catalog: each card carries metadata + a key panel (show/hide + Save + Clear) + a run.
  // ux-enrich (brief §18 P1): setup is separated from use — the key-cards collapse into a Configure
  // section (a one-time chore), collapsed by default so the default view is the entity-first action.
  const configured = view.providers.filter((p) => p.configured).length;
  const details = elt("details", "enr-configure") as HTMLDetailsElement;
  details.open = true; // founder 2026-07-08: default open on the enrich page; the native <summary> lets the user collapse it. (Was: open only when configured===0, which auto-collapsed the moment any key was set.)
  const summary = elt("summary", "enr-configure-summary");
  summary.appendChild(elt("span", "enr-configure-title", "Configure providers"));
  summary.appendChild(chip(`${configured}/${view.providers.length} configured`, configured ? "ok" : "warn"));
  details.appendChild(summary);
  const grid = elt("div", "enr-grid");
  for (const p of view.providers) grid.appendChild(providerCard(d, p));
  details.appendChild(grid);
  body.appendChild(details);

  // Recent runs table + the run-detail modal (built once, shown on a row click).
  body.appendChild(elt("h2", "enr-h2", "Recent runs"));
  const modal = buildRunModal();
  body.appendChild(renderRecentRuns(d, modal));
  body.appendChild(modal.root);

  // free/pro split (founder 2026-07-08): the CORS-blocked / server-side providers are NOT browser-native,
  // so they move to the paid tool. Hydra (free) shows them as a locked upsell teaser — the nudge. The proxy
  // code (proxy.ts + the Worker template + enrichViaProxy/testWorkerProxy deps) is KEPT intact behind the
  // split as the pro tool's foundation; it is simply no longer rendered/reachable in the free app.
  renderProProvidersSection(body, view);
  return page;
}

// free/pro split: the pro-tier providers (VirusTotal, Exa, and the other proxy-backed / server-side tools)
// shown as a LOCKED upsell teaser. No worker setup, no run — the free browser tool only does the add-a-key
// direct providers above; these need a proxy or run server-side, so they live in the paid tool.
function renderProProvidersSection(body: HTMLElement, view: ProvidersView): void {
  body.appendChild(elt("h2", "enr-h2", "Pro providers"));
  body.appendChild(
    elt(
      "p",
      "enr-blocked-note",
      "These aren't browser-native — they need a proxy or run server-side, so they're part of the pro tool, not this free browser app. Everything above runs with just your own key, no setup.",
    ),
  );
  const list = elt("div", "enr-pro-list");
  for (const b of view.blocked) {
    const row = elt("div", "enr-row enr-blocked");
    row.appendChild(elt("span", "enr-name", b.label));
    row.appendChild(chip("Pro", "warn")); // locked — available in the paid tool
    list.appendChild(row);
  }
  body.appendChild(list);
  body.appendChild(
    elt("p", "enr-pro-cta", "VirusTotal, Exa, browser rendering, and social scraping run in the pro tool."),
  );
}

// A single provider card: metadata header + description + docs, a key panel (show/hide + Save + Test +
// Clear + a key-source pill), and a per-provider run (target + Run + lastResult) — the original's layout.
function providerCard(d: PageDeps, p: ProvidersView["providers"][number]): HTMLElement {
  const card = elt("div", `enr-card${p.configured ? "" : " enr-card-off"}`);

  const head = elt("div", "enr-card-head");
  const left = elt("div", "enr-card-title");
  left.appendChild(elt("span", "enr-name", p.label));
  left.appendChild(chip(p.configured ? "configured" : "not configured", p.configured ? "ok" : "warn"));
  head.appendChild(left);
  head.appendChild(elt("span", "enr-cat", p.category));
  card.appendChild(head);

  card.appendChild(elt("div", "enr-desc", p.blurb));

  const meta = elt("div", "enr-meta");
  meta.appendChild(elt("span", "enr-targets", `targets: ${p.targets.join(" / ")}`));
  const docs = elt("a", "enr-docs", "docs ↗") as HTMLAnchorElement;
  docs.href = p.docsUrl;
  docs.target = "_blank";
  docs.rel = "noopener noreferrer";
  meta.appendChild(docs);
  card.appendChild(meta);

  // founder 2026-07-09: per-provider key guidance — where to CREATE the key + one-line steps, and whether
  // the key is required or only lifts the rate limit (GitHub/GitLab run keyless). "Get a key ↗" is a nav
  // anchor (its host is in leakgate ENRICH_DOC_HOSTS, never the CSP connect-src — the user opens it, we
  // never fetch it).
  const guide = elt("div", "enr-keyguide");
  const guideTop = elt("div", "enr-meta");
  const getKey = elt("a", "enr-docs", "Get a key ↗") as HTMLAnchorElement;
  getKey.href = p.keyUrl;
  getKey.target = "_blank";
  getKey.rel = "noopener noreferrer";
  guideTop.appendChild(getKey);
  guideTop.appendChild(chip(p.keyRequired ? "key required" : "optional — lifts rate limit", p.keyRequired ? "warn" : "ok"));
  guide.appendChild(guideTop);
  guide.appendChild(elt("div", "enr-desc", p.keySteps));
  card.appendChild(guide);

  card.appendChild(keyPanel(d, p));
  card.appendChild(runRow(d, p));
  return card;
}

function keyPanel(d: PageDeps, p: ProvidersView["providers"][number]): HTMLElement {
  const panel = elt("div", "enr-keypanel");
  const top = elt("div", "enr-keytop");
  top.appendChild(elt("span", "enr-keylabel", "API key"));
  top.appendChild(elt("span", `enr-keysrc ${p.keySource === "db" ? "ok" : "muted"}`, p.keySource === "db" ? "● saved locally" : "○ not set"));
  panel.appendChild(top);

  const ctrl = elt("div", "enr-ctrl");
  const input = elt("input", "enr-key") as HTMLInputElement;
  input.type = "password";
  input.autocomplete = "off";
  input.placeholder = p.configured ? "key saved ••••• — type to replace" : p.keyHint;
  const showBtn = elt("button", "pg-btn enr-show", "show") as HTMLButtonElement;
  showBtn.addEventListener("click", () => {
    const showing = input.type === "text";
    input.type = showing ? "password" : "text";
    showBtn.textContent = showing ? "show" : "hide";
  });
  const saveBtn = elt("button", "pg-btn primary", "Save") as HTMLButtonElement;
  const testBtn = elt("button", "pg-btn", "Test") as HTMLButtonElement;
  const msg = elt("div", "enr-keymsg");
  ctrl.appendChild(input);
  ctrl.appendChild(showBtn);
  ctrl.appendChild(saveBtn);
  ctrl.appendChild(testBtn);
  if (p.keySource === "db") {
    const clearBtn = elt("button", "pg-btn enr-clear", "Clear") as HTMLButtonElement;
    clearBtn.addEventListener("click", async () => {
      await withBtn(clearBtn, "…", async () => {
        try {
          await d.clearProviderKey(p.id);
          d.navigate("/enrich"); // re-render: the pill drops to "not set", Clear disappears, Run disables
        } catch (e) {
          msg.textContent = errText(e);
          msg.className = "enr-keymsg warn";
        }
      });
    });
    ctrl.appendChild(clearBtn);
  }
  panel.appendChild(ctrl);
  panel.appendChild(msg);

  saveBtn.addEventListener("click", async () => {
    if (saveBtn.disabled) return;
    if (!input.value.trim()) { msg.textContent = "Enter a key."; msg.className = "enr-keymsg warn"; return; }
    await withBtn(saveBtn, "Saving…", async () => {
      try {
        await d.saveProviderKey(p.id, input.value);
        input.value = "";
        d.navigate("/enrich"); // re-render so the configured pill + Clear + the enabled Run reflect the key
      } catch (e) {
        msg.textContent = errText(e);
        msg.className = "enr-keymsg warn";
      }
    });
  });

  testBtn.addEventListener("click", async () => {
    if (testBtn.disabled) return;
    await withBtn(testBtn, "Testing…", async () => {
      const r = await d.testProvider(p.id); // one live probe; the detail is already sanitized (no key)
      msg.textContent = r.ok ? `test ok · ${r.detail}` : `test failed · ${r.detail}`;
      msg.className = `enr-keymsg ${r.ok ? "ok" : "warn"}`;
    });
  });

  return panel;
}

function runRow(d: PageDeps, p: ProvidersView["providers"][number]): HTMLElement {
  const row = elt("div", "enr-run");
  const target = elt("input", "enr-target") as HTMLInputElement;
  target.type = "text";
  target.placeholder = `target: ${p.targets.join(" / ")}`;
  const runBtn = elt("button", "pg-btn primary enr-run-btn", "Run") as HTMLButtonElement;
  runBtn.disabled = !p.configured; // a keyless provider can't run (parity: the original disables Run)
  const out = elt("div", "enr-lastresult");
  runBtn.addEventListener("click", async () => {
    if (runBtn.disabled) return;
    const t = target.value.trim();
    if (!t) { out.textContent = "Enter a target first."; out.className = "enr-lastresult warn"; return; }
    await withBtn(runBtn, "Running…", async () => {
      try {
        const r = await d.enrich(p.id, t);
        out.textContent = `✓ ${r.count} result${r.count === 1 ? "" : "s"} (${r.tier})`;
        out.className = "enr-lastresult ok"; // the run lands in Recent runs on the next /enrich render
      } catch (e) {
        out.textContent = `✗ ${mapOsintError(e)}`; // clu-error-output: 401/NOTOK/network → guidance
        out.className = "enr-lastresult warn";
      }
    });
  });
  row.appendChild(target);
  row.appendChild(runBtn);
  row.appendChild(out);
  return row;
}

interface RunModal {
  root: HTMLElement;
  open(detail: EnrichRunDetail | null): void;
}

// The run-detail modal (parity with the original): built once, populated + shown on a row click.
function buildRunModal(): RunModal {
  const root = elt("div", "enr-modal");
  root.style.display = "none";
  const panel = elt("div", "enr-modal-panel");
  const head = elt("div", "enr-modal-head");
  const titleWrap = elt("div");
  const title = elt("div", "enr-modal-title");
  const sub = elt("div", "enr-modal-sub");
  titleWrap.appendChild(title);
  titleWrap.appendChild(sub);
  head.appendChild(titleWrap);
  const close = elt("button", "enr-modal-close", "✕") as HTMLButtonElement;
  const hide = (): void => { root.style.display = "none"; };
  close.addEventListener("click", hide);
  root.addEventListener("click", (e) => { if (e.target === root) hide(); });
  head.appendChild(close);
  panel.appendChild(head);
  const bodyEl = elt("div", "enr-modal-body");
  panel.appendChild(bodyEl);
  root.appendChild(panel);

  return {
    root,
    open(detail) {
      if (!detail) return;
      title.textContent = `${detail.provider} · ${detail.target}`;
      sub.textContent = detail.objective;
      bodyEl.textContent = "";
      if (!detail.findings.length) {
        bodyEl.appendChild(elt("div", "enr-modal-empty", "No findings extracted."));
      } else {
        for (const f of detail.findings) {
          const r = elt("div", "enr-finding");
          const hd = elt("div", "enr-finding-head");
          hd.appendChild(chip(f.entityType));
          hd.appendChild(chip(`grade ${f.grade}`, f.status === "promoted" ? "ok" : ""));
          hd.appendChild(elt("span", "enr-finding-status", f.status));
          r.appendChild(hd);
          r.appendChild(elt("div", "enr-finding-entity", f.entity));
          bodyEl.appendChild(r);
        }
      }
      root.style.display = "flex";
    },
  };
}

function renderRecentRuns(d: PageDeps, modal: RunModal): HTMLElement {
  const wrap = elt("div", "enr-runs");
  const runs = d.listEnrichRuns();
  const table = elt("table", "enr-table");
  const thead = elt("thead");
  const htr = elt("tr");
  for (const h of ["#", "Provider", "Target", "Status", "Entity", "When"]) htr.appendChild(elt("th", "", h));
  thead.appendChild(htr);
  table.appendChild(thead);
  const tbody = elt("tbody");
  if (!runs.length) {
    const tr = elt("tr");
    const td = elt("td", "enr-empty", "No enrichment runs yet.") as HTMLTableCellElement;
    td.colSpan = 6;
    tr.appendChild(td);
    tbody.appendChild(tr);
  } else {
    runs.forEach((run, i) => {
      const tr = elt("tr", "enr-run-row");
      tr.appendChild(elt("td", "enr-td-num", `#${i + 1}`));
      tr.appendChild(elt("td", "enr-td-prov", run.provider));
      tr.appendChild(elt("td", "enr-td-target", run.target));
      const stTd = elt("td");
      stTd.appendChild(chip(run.status, "ok"));
      tr.appendChild(stTd);
      const ent = run.entities.length
        ? run.entities.length > 1
          ? `${run.entities[0]} +${run.entities.length - 1}`
          : run.entities[0]
        : "—";
      tr.appendChild(elt("td", "enr-td-entity", ent));
      tr.appendChild(elt("td", "enr-td-when", run.at ? run.at.replace("T", " ").slice(0, 19) : "—"));
      tr.addEventListener("click", () => modal.open(d.getEnrichRunDetail(run.objective)));
      tbody.appendChild(tr);
    });
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

async function withBtn(btn: HTMLButtonElement, busy: string, fn: () => Promise<void>): Promise<void> {
  const prev = btn.textContent;
  btn.disabled = true;
  btn.textContent = busy;
  try {
    await fn();
  } finally {
    btn.disabled = false;
    btn.textContent = prev;
  }
}

// td-wire: the REAL Cross-domain view — entities whose runs span >= 2 investigation TYPES (the
// deterministic type detector tags each run). Replaces the old port-pending info card.
export function renderCrossDomainPage(d: PageDeps): HTMLElement {
  const entities = d.crossDomain();
  const { page, body } = pageShell(
    "Cross-type",
    "Entities that span two or more investigation TYPES — the overlap across crypto-fraud, intrusion, disinfo, …",
  );
  if (!entities.length) {
    emptyNote(body, "No cross-type overlap yet. It appears when an entity shows up in runs of two or more DIFFERENT investigation types (e.g. a domain seen in both a crypto-fraud and an intrusion case).");
    return page;
  }
  for (const e of entities) {
    const row = elt("div", "xd-row");
    row.appendChild(elt("span", "ent-name", e.label));
    row.appendChild(chip(e.ref.type));
    const types = elt("div", "xd-types");
    for (const t of e.types) types.appendChild(chip(t, "ok")); // the investigation types it bridges
    row.appendChild(types);
    const runs = elt("div", "xc-runs");
    for (const r of e.runs.slice(0, 8)) runs.appendChild(elt("span", "xc-run", r));
    row.appendChild(runs);
    body.appendChild(row);
  }
  return page;
}
