// ca-analysis (INC-1 of the Process pipeline): the PURE Process-output projection. The Process
// pipeline (auto-schema → consolidate → typing → …) writes its AI findings into an `analysis:<case>`
// vault record; THIS module overlays the AI roles/types onto the entity store + graph model the SAME
// way corrections.ts overlays analyst overrides — by the ONE canonKey, DISPLAY-only (role/type),
// never rekeying / adding / removing an entity and never touching grade / source counts / promotion.
//
// Layering invariant (PRD D1, the analyst-is-top-authority scar): applyAnalysis is layered BELOW
// applyCorrections at every projection chokepoint, so an analyst correction ALWAYS wins over an AI
// role — AI judgment can never masquerade as analyst authority. The projection ORDER is the proof:
//   applyCorrections(applyAnalysis(buildEntityDb(runs), analysis), corrections)
// A correction on the same entity overwrites the AI overlay because it runs last.
//
// PURE: no vault, no clock, no randomness, no LLM, no fetch. The impure half (read/write the record,
// the LLM understand pass, redaction) lives in session.ts — exactly the corrections.ts (pure) vs
// session.applyCorrection (impure) split.

import { canonKey, type EntityStore, type EntityRecord } from "./db.js";
import type { GraphModel, GraphEdge, GraphNode } from "../graph/model.js";
import { CONSOLIDATE_ROLES, SURFACE_TYPES, roleForType } from "./consolidate.js";
import { REL_VOCAB, isCleanToken } from "./rel-vocab.js";

export const ANALYSIS_VERSION = 1;

// The AI overlay reuses the EXACT same closed allowlists as the corrections store (the consolidate
// role set + the typing surface-type set), so an analysis overlay and an analyst correction are
// always over the same value space — a value the corrections layer could not produce, the analysis
// layer must not either.
const ROLE_VALUES = new Set<string>(CONSOLIDATE_ROLES);
const TYPE_VALUES = new Set<string>(SURFACE_TYPES);

export function isAnalysisRole(value: string): boolean {
  return ROLE_VALUES.has(value);
}
export function isAnalysisType(value: string): boolean {
  return TYPE_VALUES.has(value);
}

// ---- the model-discovered case schema (cap-understand-schema; understand.py:_validate shape) ----

export interface SchemaEntityType {
  name: string;
  description: string;
}
export interface SchemaRole {
  name: string;
  description: string;
  actor: boolean;
  weight: number; // 0-5, drives the INC-4 threat-score ranking
}
export interface SchemaSubRole {
  name: string;
  description: string;
}
export interface CaseSchema {
  domain: string;
  summary: string;
  entityTypes: SchemaEntityType[];
  roles: SchemaRole[];
  subRoles: SchemaSubRole[];
  noiseNotes: string;
}

// ---- the persisted Process-output record (the `analysis:<case>` vault value) ----

/**
 * One case's accumulated Process output. INC-1 holds the auto-modeled schema + the per-entity AI
 * roles/types (later increments add edges/clusters/scores). roles/types are keyed by canonKey —
 * the SAME identity the corrections store + the /entities row use — so an overlay can never silently
 * orphan because a caller built the key differently. Stored ONLY via session.putAnalysis (the typed,
 * redacted, single-writer chokepoint).
 */
// ca-analyze (INC-3): the analyze pass's LLM-generated clusters + typed relationships. member/src/dst
// are canonKeys (the client identity) — analyze.py uses integer entity ids, but kipi-web keys by
// canonKey, so the eN opaque ids the model sees are mapped back to canonKeys at the session boundary.
export interface AnalysisCluster {
  name: string;
  kind: string;
  description: string;
  memberKeys: string[]; // canonKeys of the cluster's members
}
export interface AnalysisRelationship {
  srcKey: string; // canonKey
  dstKey: string; // canonKey
  relType: string;
  confidence: string; // high | medium | low
  evidence: string;
}
// INC-4a: the deterministic graph analytics persisted per entity (canonKey-keyed).
export interface EntityScoreRecord {
  threatScore: number; // compute_threat_scores: base + prior + prop
  degree: number;
  reportCount: number;
}
export interface NodeMetricRecord {
  degreeCentrality: number; // normalized by n-1 (NetworkX-faithful)
  betweenness: number;
  eigenvector: number;
  community: number; // Louvain community index
  // PRD-B graph-path-confidence: the strongest (widest-bottleneck) path back to a case seed (compute_path_
  // confidence). Undefined when the node is unreachable from any seed (never 0-faked — distinct from a weak path).
  pathConfidence?: number;
}

export interface AnalysisRecord {
  version: number;
  case: string;
  schema: CaseSchema | null;
  roles: Record<string, string>; // canonKey -> AI role (allowlisted)
  subRoles?: Record<string, string>; // canonKey -> operator sub_role (network FUNCTION); A1, display-only
  types: Record<string, string>; // canonKey -> AI surface type (allowlisted)
  caseTypes?: Record<string, string>; // PRD-B typing-case-type: canonKey -> per-case ANALYTIC type from the
  // schema entity_types (port of typing.py case_type) — free-text vocabulary (the schema names it), not the
  // allowlisted surface `types`. Overlaid onto EntityRecord.caseType by applyAnalysis.
  clusters: AnalysisCluster[]; // ca-analyze: LLM analytic clusters (graph fill color source)
  relationships: AnalysisRelationship[]; // ca-analyze/INC-4a: vocab-gated typed edges (persisted + rendered)
  entityScores: Record<string, EntityScoreRecord>; // INC-4a: canonKey -> threat score
  nodeMetrics: Record<string, NodeMetricRecord>; // INC-4a: canonKey -> centrality + community
  updatedAt?: string;
}

export function emptyAnalysis(caseId: string): AnalysisRecord {
  return { version: ANALYSIS_VERSION, case: caseId, schema: null, roles: {}, subRoles: {}, types: {}, clusters: [], relationships: [], entityScores: {}, nodeMetrics: {} };
}

function hasOverlay(rec: AnalysisRecord | null): rec is AnalysisRecord {
  if (!rec) return false;
  return (
    (!!rec.roles && Object.keys(rec.roles).length > 0) ||
    (!!rec.types && Object.keys(rec.types).length > 0) ||
    (!!rec.caseTypes && Object.keys(rec.caseTypes).length > 0)
  );
}

/** The valid (allowlisted) role/type overlay for one canonKey, or undefined if neither is set. The
 *  subRole (operator network FUNCTION) rides with a valid role — display-only, no shape effect. */
function overlayFor(rec: AnalysisRecord, key: string): { role?: string; type?: string; subRole?: string; caseType?: string } | undefined {
  const roleRaw = rec.roles?.[key];
  const typeRaw = rec.types?.[key];
  const role = roleRaw && isAnalysisRole(roleRaw) ? roleRaw : undefined;
  const type = typeRaw && isAnalysisType(typeRaw) ? typeRaw : undefined;
  // a sub_role only means anything alongside an operator role; carry it only then.
  const subRaw = rec.subRoles?.[key];
  const subRole = role === "operator" && typeof subRaw === "string" && subRaw.trim() ? subRaw.trim() : undefined;
  // case_type is free-text (the schema names the vocabulary), already capped at the parse seam — no allowlist.
  const caseRaw = rec.caseTypes?.[key];
  const caseType = typeof caseRaw === "string" && caseRaw.trim() ? caseRaw.trim() : undefined;
  if (!role && !type && !caseType) return undefined;
  return { role, type, subRole, caseType };
}

/**
 * A NEW store with each entity's role / display type overlaid by its canonKey from the analysis
 * record. Identity (ref), grade, promoted, sourceCount, runs, and connections are UNTOUCHED (an AI
 * label is judgment, not fabricated corroboration). An overlay for an entity not in the store is a
 * no-op (never invents an entity). A null/empty record returns the store unchanged.
 */
export function applyAnalysis(store: EntityStore, rec: AnalysisRecord | null): EntityStore {
  if (!hasOverlay(rec)) return store;
  const entities: Record<string, EntityRecord> = {};
  for (const [key, r] of Object.entries(store.entities)) {
    const ov = overlayFor(rec, key);
    if (!ov) {
      entities[key] = r;
      continue;
    }
    // ROLE DECISION (founder 2026-06-24): an infra-typed entity is never `operator` from the AI pass.
    // roleForType heals EXISTING records too (a case Processed before the fix stored operator on its
    // domains) — applied at this READ seam so the entities page / brief reflect it without a re-Process.
    const aiRole = roleForType(ov.role ?? r.role, r.ref.type);
    entities[key] = {
      ...r,
      role: aiRole,
      subRole: aiRole === "operator" ? (ov.subRole ?? r.subRole) : undefined, // A1: only on a node that stays operator
      type: ov.type ?? r.type, // DISPLAY only — r.ref (identity) is NOT changed, so the key stays
      caseType: ov.caseType ?? r.caseType, // PRD-B: the per-case analytic type (typing.py case_type)
    };
  }
  return { ...store, entities };
}

/**
 * A NEW model with each non-objective node's ROLE overlaid by its canonKey. Nodes are never added or
 * removed. Wired BELOW applyCorrectionsToModel at every graph chokepoint so analyst corrections still
 * win on the graph (the composition is applyCorrectionsToModel(applyAnalysisToModel(model), corr)).
 *
 * ROLE ONLY on the graph (NOT type) — a deliberate correctness call, not an omission. The scar:
 * applyCorrectionsToModel (which corrections.ts owns) recomputes its match key as
 * canonKey(node.entityType, label). If analysis mutated entityType on the model, a type/role
 * correction keyed to the entity's ORIGINAL type would silently MISS (key drift) and the analyst
 * override would be lost on the graph — breaking the top-authority invariant (PRD D1). On the STORE
 * the map key is stable (independent of the display fields), so applyAnalysis there overlays role AND
 * type safely; the AI surface-type surfaces through the store-backed node drawer / Entities page.
 * Role is what drives node styling + the INC-3 cluster coloring, so the graph overlay loses nothing.
 */
export function applyAnalysisToModel(model: GraphModel, rec: AnalysisRecord | null): GraphModel {
  if (!hasOverlay(rec)) return model;
  const nodes = model.nodes.map((n) => {
    if (n.kind === "objective") return n;
    const ov = overlayFor(rec, canonKey(n.entityType, n.label));
    if (!ov || !ov.role) return n; // type overlay is store-only (see scar above)
    // ROLE DECISION (founder 2026-06-24): a domain/IP/URL node is never `operator` — roleForType coerces it
    // to infra at this graph READ seam, so an existing case Processed before the fix renders domains as
    // SQUARES immediately (no re-Process). Analyst corrections apply ABOVE this and still win.
    const role = roleForType(ov.role, n.entityType);
    return { ...n, role, subRole: role === "operator" ? (ov.subRole ?? n.subRole) : undefined }; // A1: sub_role only on a node that stays operator
  });
  return { ...model, nodes };
}

/**
 * A NEW model with each non-objective node's `cluster` (the LLM analytic cluster NAME) set by its
 * canonKey membership — the source of the graph's cluster-color fill (cap-cluster-colors, INC-3).
 * Membership is by the SAME canonKey the store/corrections use (no drift). First cluster a node
 * belongs to wins (a node's FILL is one color; clusters are many-to-many but a fill is singular) —
 * deterministic in cluster order. Nodes are never added/removed. Composed at the graph chokepoints
 * BELOW corrections, alongside applyAnalysisToModel (a node's cluster fill is AI judgment, not an
 * analyst override, so there is no corrections layering to fight here — it only sets node.cluster).
 */
export function applyClustersToModel(model: GraphModel, rec: AnalysisRecord | null): GraphModel {
  if (!rec?.clusters?.length) return model;
  const clusterByKey = new Map<string, string>();
  for (const c of rec.clusters) {
    for (const k of c.memberKeys) {
      if (!clusterByKey.has(k)) clusterByKey.set(k, c.name); // first cluster wins (deterministic)
    }
  }
  if (clusterByKey.size === 0) return model;
  const nodes = model.nodes.map((n) => {
    if (n.kind === "objective") return n;
    const cluster = clusterByKey.get(canonKey(n.entityType, n.label));
    if (cluster) return { ...n, cluster };
    // codex (adversarial): CLEAR a stale cluster on a non-match. The grow/expand base is a prior
    // finalized model whose nodes may already carry a cluster; if the record changed (a node left a
    // cluster), leaving the old value would render a fill outside the current membership set. Only
    // allocate a new node when there's actually a stale value to clear (preserve ref identity otherwise).
    return n.cluster !== undefined ? { ...n, cluster: undefined } : n;
  });
  return { ...model, nodes };
}

/**
 * INC-4a: a NEW model with each non-objective node's `threatScore` set by its canonKey from the score
 * record (drives node sizing + the min_score filter). Same canonKey identity + stale-clear pattern as
 * applyClustersToModel. Composed at the graph chokepoint below corrections (a score is AI judgment).
 */
export function applyScoresToModel(model: GraphModel, rec: AnalysisRecord | null): GraphModel {
  const scores = rec?.entityScores;
  if (!scores || Object.keys(scores).length === 0) {
    // clear any stale score carried by a prior finalized base (grow/expand reuse)
    if (!model.nodes.some((n) => n.threatScore !== undefined)) return model;
    return { ...model, nodes: model.nodes.map((n) => (n.threatScore !== undefined ? { ...n, threatScore: undefined } : n)) };
  }
  const nodes = model.nodes.map((n) => {
    if (n.kind === "objective") return n;
    const s = scores[canonKey(n.entityType ?? "", n.label)];
    if (s) return { ...n, threatScore: s.threatScore };
    return n.threatScore !== undefined ? { ...n, threatScore: undefined } : n;
  });
  return { ...model, nodes };
}

/**
 * INC-4a: a NEW model with each non-objective node's centrality + community set by its canonKey from the
 * metrics record (surfaced in the node drawer; community can color/group). Stale-clear on non-match.
 */
export function applyMetricsToModel(model: GraphModel, rec: AnalysisRecord | null): GraphModel {
  const metrics = rec?.nodeMetrics;
  const hasMetricNode = model.nodes.some((n) => n.community !== undefined || n.degreeCentrality !== undefined);
  if (!metrics || Object.keys(metrics).length === 0) {
    if (!hasMetricNode) return model;
    return { ...model, nodes: model.nodes.map((n) => clearMetrics(n)) };
  }
  const nodes = model.nodes.map((n) => {
    if (n.kind === "objective") return n;
    const m = metrics[canonKey(n.entityType ?? "", n.label)];
    if (m) return { ...n, degreeCentrality: m.degreeCentrality, betweenness: m.betweenness, eigenvector: m.eigenvector, community: m.community };
    return clearMetrics(n);
  });
  return { ...model, nodes };
}

function clearMetrics(n: GraphNode): GraphNode {
  if (n.community === undefined && n.degreeCentrality === undefined && n.betweenness === undefined && n.eigenvector === undefined) return n;
  return { ...n, degreeCentrality: undefined, betweenness: undefined, eigenvector: undefined, community: undefined };
}

/**
 * INC-4a: a NEW model with the persisted typed_relationships rendered as entity↔entity `typed_rel`
 * edges. Each relationship's src/dst canonKey is matched to the graph node(s) carrying that canonKey
 * (an entity may be >1 node across folded runs — connect every match, like mergeGraphModel's cross
 * edge). An endpoint not on the graph is skipped (never a dangling edge). Idempotent on (from,to,relType).
 */
export function applyRelationshipsToModel(model: GraphModel, rec: AnalysisRecord | null): GraphModel {
  // codex A4: REBUILD typed_rel edges every finalize — STRIP any prior typed_rel edges first (finalizeModel
  // runs on an already-finalized base in growCaseGraph/expandFromNode), so a shrunk/empty/changed
  // relationship set never leaves a stale edge. Spoke edges (promoted/lead) are preserved. Mirrors
  // applyClustersToModel's stale-clear.
  const baseEdges = model.edges.filter((e) => e.kind !== "typed_rel");
  if (!rec?.relationships?.length) {
    return baseEdges.length === model.edges.length ? model : { ...model, edges: baseEdges };
  }
  const idsByKey = new Map<string, string[]>();
  for (const n of model.nodes) {
    if (n.kind === "objective") continue;
    const k = canonKey(n.entityType ?? "", n.label);
    const list = idsByKey.get(k);
    if (list) list.push(n.id);
    else idsByKey.set(k, [n.id]);
  }
  const edges: GraphEdge[] = baseEdges.map((e) => ({ ...e }));
  const sig = new Set(edges.map((e) => `${e.from} ${e.to} ${e.relType ?? ""}`));
  for (const rel of rec.relationships) {
    const srcIds = idsByKey.get(rel.srcKey);
    const dstIds = idsByKey.get(rel.dstKey);
    if (!srcIds || !dstIds) continue; // an endpoint isn't a node — skip
    for (const from of srcIds) {
      for (const to of dstIds) {
        if (from === to) continue;
        const s = `${from} ${to} ${rel.relType}`;
        if (sig.has(s)) continue;
        sig.add(s);
        edges.push({ from, to, kind: "typed_rel", relType: rel.relType, confidence: rel.confidence });
      }
    }
  }
  return { ...model, edges };
}

// ---- validation (the typed putAnalysis chokepoint, PRD D7) ----

function asString(v: unknown): string {
  return typeof v === "string" ? v.replace(/\s+/g, " ").trim() : "";
}

const MAX_SCHEMA_FIELD = 400;
const MAX_SCHEMA_LIST = 24; // cap entity_types / roles / sub_roles so a hostile record can't bloat
const MAX_OVERLAY_ENTRIES = 1000; // a case has <= a few hundred entities; bound the maps defensively
const MAX_OVERLAY_KEY_LEN = 512; // a canonKey is a short JSON tuple; reject an oversized forged key

// codex MAJOR (D7): an overlay key MUST be a CANONICAL key — the exact JSON tuple canonKey() emits — or
// a forged/imported record could smuggle a huge / non-canonical / never-matching key into the persisted
// record. The round-trip (canonKey of the parsed [type,value] === the key) proves it is already canonical
// (idempotent): a non-canonical key (wrong case, an un-folded type alias, junk) fails to round-trip.
function isCanonicalOverlayKey(k: string): boolean {
  if (typeof k !== "string" || k.length === 0 || k.length > MAX_OVERLAY_KEY_LEN) return false;
  if (k === "__proto__" || k === "constructor" || k === "prototype") return false; // belt: never a tuple anyway
  let t: unknown;
  try {
    t = JSON.parse(k);
  } catch {
    return false;
  }
  if (!Array.isArray(t) || t.length !== 2 || typeof t[0] !== "string" || typeof t[1] !== "string") return false;
  return canonKey(t[0], t[1]) === k;
}

function clampWeight(raw: unknown, isActor: boolean, name: string): number {
  // understand.py:_clamp_weight — coerce to 0-5; sensible default when missing.
  const n = Number(raw);
  if (Number.isFinite(n)) return Math.max(0, Math.min(5, Math.round(n)));
  if (name === "noise" || name === "source" || name === "context") return 0;
  return isActor ? 5 : 2;
}

/**
 * Coerce an LLM/stored schema into a usable shape (port of understand.py:_validate). Guarantees a
 * 'noise' role and at least one actor role so downstream steps never get a broken model. Returns
 * null only when the input is not an object at all.
 */
export function validateCaseSchema(raw: unknown): CaseSchema | null {
  if (!raw || typeof raw !== "object") return null;
  const s = raw as Record<string, unknown>;
  const out: CaseSchema = {
    domain: asString(s.domain).slice(0, MAX_SCHEMA_FIELD) || "uncharacterized case",
    summary: asString(s.summary).slice(0, MAX_SCHEMA_FIELD),
    entityTypes: [],
    roles: [],
    subRoles: [],
    noiseNotes: asString(s.noiseNotes ?? (s as { noise_notes?: unknown }).noise_notes).slice(0, MAX_SCHEMA_FIELD),
  };
  const etRaw = Array.isArray(s.entityTypes) ? s.entityTypes : Array.isArray((s as { entity_types?: unknown }).entity_types) ? (s as { entity_types: unknown[] }).entity_types : [];
  for (const t of etRaw.slice(0, MAX_SCHEMA_LIST)) {
    if (!t || typeof t !== "object") continue;
    const name = asString((t as Record<string, unknown>).name).slice(0, MAX_SCHEMA_FIELD);
    if (name) out.entityTypes.push({ name, description: asString((t as Record<string, unknown>).description).slice(0, MAX_SCHEMA_FIELD) });
  }
  const seenRoles = new Set<string>();
  const rolesRaw = Array.isArray(s.roles) ? s.roles : [];
  for (const r of rolesRaw.slice(0, MAX_SCHEMA_LIST)) {
    if (!r || typeof r !== "object") continue;
    const rr = r as Record<string, unknown>;
    const name = asString(rr.name).toLowerCase().slice(0, MAX_SCHEMA_FIELD);
    if (!name || seenRoles.has(name)) continue;
    seenRoles.add(name);
    const isActor = !!rr.actor;
    out.roles.push({ name, description: asString(rr.description).slice(0, MAX_SCHEMA_FIELD), actor: isActor, weight: clampWeight(rr.weight, isActor, name) });
  }
  const subRaw = Array.isArray(s.subRoles) ? s.subRoles : Array.isArray((s as { sub_roles?: unknown }).sub_roles) ? (s as { sub_roles: unknown[] }).sub_roles : [];
  for (const sr of subRaw.slice(0, MAX_SCHEMA_LIST)) {
    if (!sr || typeof sr !== "object") continue;
    const name = asString((sr as Record<string, unknown>).name).toLowerCase().slice(0, MAX_SCHEMA_FIELD);
    if (name) out.subRoles.push({ name, description: asString((sr as Record<string, unknown>).description).slice(0, MAX_SCHEMA_FIELD) });
  }
  // Guarantees (understand.py): a 'noise' role + at least one actor role + a non-empty sub_role list.
  if (!seenRoles.has("noise")) out.roles.push({ name: "noise", description: "parser glitch / fragment / not a real entity", actor: false, weight: 0 });
  if (!out.roles.some((r) => r.actor)) {
    // codex MAJOR: promotion only works when a non-noise role EXISTS. For an empty/degenerate schema
    // (e.g. autoModelSchema's parse-failure fallback validateCaseSchema({})), there is nothing to
    // promote, so ADD a default actor role — the "at least one actor" invariant must hold even then.
    const first = out.roles.find((r) => r.name !== "noise");
    if (first) {
      first.actor = true;
      first.weight = Math.max(first.weight, 5);
    } else {
      out.roles.unshift({ name: "operator", description: "the primary human actor in this case", actor: true, weight: 5 });
    }
  }
  if (!out.subRoles.length) out.subRoles = [{ name: "unknown", description: "function unclear from evidence" }];
  return out;
}

/**
 * The typed putAnalysis chokepoint (PRD D7): coerce an arbitrary stored/built record into a SAFE
 * AnalysisRecord — drop overlay entries with a non-string key or a non-allowlisted value, validate
 * the schema, bound the maps. A malformed persisted record can never break a render or load path
 * (fable-discipline: validate persisted external input).
 */
export function validateAnalysisRecord(raw: unknown, caseId: string): AnalysisRecord {
  const out = emptyAnalysis(caseId);
  if (!raw || typeof raw !== "object") return out;
  const r = raw as Record<string, unknown>;
  if (typeof r.case === "string" && r.case.trim()) out.case = r.case.trim();
  out.schema = validateCaseSchema(r.schema);
  const roleMap = r.roles && typeof r.roles === "object" ? (r.roles as Record<string, unknown>) : {};
  const typeMap = r.types && typeof r.types === "object" ? (r.types as Record<string, unknown>) : {};
  let n = 0;
  for (const [k, v] of Object.entries(roleMap)) {
    if (n >= MAX_OVERLAY_ENTRIES) break;
    if (isCanonicalOverlayKey(k) && typeof v === "string" && isAnalysisRole(v)) {
      out.roles[k] = v;
      n++;
    }
  }
  n = 0;
  for (const [k, v] of Object.entries(typeMap)) {
    if (n >= MAX_OVERLAY_ENTRIES) break;
    if (isCanonicalOverlayKey(k) && typeof v === "string" && isAnalysisType(v)) {
      out.types[k] = v;
      n++;
    }
  }
  // A1 sub_role overlay: a short free-form function label (NOT an allowlist — invented sub_roles are
  // intentional, consolidate.py). Without copying it here the overlay is stripped at the persist
  // chokepoint and overlayFor reads nothing after a real Process write/read (codex High).
  const subRoleMap = r.subRoles && typeof r.subRoles === "object" ? (r.subRoles as Record<string, unknown>) : {};
  out.subRoles = {};
  n = 0;
  for (const [k, v] of Object.entries(subRoleMap)) {
    if (n >= MAX_OVERLAY_ENTRIES) break;
    if (isCanonicalOverlayKey(k) && typeof v === "string" && v.trim()) {
      out.subRoles[k] = v.trim().slice(0, 40);
      n++;
    }
  }
  // PRD-B typing-case-type: the per-case analytic type overlay. Like subRoles it is FREE-TEXT (the schema
  // names the vocabulary, parseTyping coerces non-schema values to 'other'), so no allowlist — but it MUST
  // be copied here or putAnalysis strips it and EntityRecord.caseType never overlays end-to-end (codex
  // issue-3 BLOCKER — the exact persist-chokepoint strip the subRoles comment above warns about).
  const caseTypeMap = r.caseTypes && typeof r.caseTypes === "object" ? (r.caseTypes as Record<string, unknown>) : {};
  out.caseTypes = {};
  n = 0;
  for (const [k, v] of Object.entries(caseTypeMap)) {
    if (n >= MAX_OVERLAY_ENTRIES) break;
    if (isCanonicalOverlayKey(k) && typeof v === "string" && v.trim()) {
      out.caseTypes[k] = v.trim().slice(0, 60); // cap defensively (== parseTyping's cap)
      n++;
    }
  }
  out.clusters = validateClusters(r.clusters);
  out.relationships = validateRelationships(r.relationships);
  out.entityScores = validateScores(r.entityScores);
  out.nodeMetrics = validateMetrics(r.nodeMetrics);
  if (typeof r.updatedAt === "string") out.updatedAt = r.updatedAt;
  return out;
}

const MAX_CLUSTERS = 100; // bound a hostile/huge record (a real case has a handful of clusters)
const MAX_CLUSTER_MEMBERS = 500;
const MAX_RELATIONSHIPS = 600; // == analyze.py ANALYZE_MAX_RELATIONSHIPS ballpark
const CONFIDENCE_VALUES = new Set(["high", "medium", "low"]);

/** Coerce stored/LLM clusters into a safe shape: drop non-canonical member keys, bound the lists,
 *  require a name. A malformed persisted record can never break a render (validate persisted input). */
function validateClusters(raw: unknown): AnalysisCluster[] {
  if (!Array.isArray(raw)) return [];
  const out: AnalysisCluster[] = [];
  for (const c of raw.slice(0, MAX_CLUSTERS)) {
    if (!c || typeof c !== "object") continue;
    const cc = c as Record<string, unknown>;
    const name = asString(cc.name).slice(0, MAX_SCHEMA_FIELD);
    if (!name) continue;
    const keysRaw = Array.isArray(cc.memberKeys) ? cc.memberKeys : [];
    const memberKeys: string[] = [];
    const seen = new Set<string>(); // codex (adversarial): dedupe so a hostile record can't spend the
    for (const k of keysRaw.slice(0, MAX_CLUSTER_MEMBERS)) { // budget on duplicate keys / repeat a member
      if (typeof k === "string" && isCanonicalOverlayKey(k) && !seen.has(k)) {
        seen.add(k);
        memberKeys.push(k);
      }
    }
    out.push({
      name,
      kind: asString(cc.kind).slice(0, MAX_SCHEMA_FIELD),
      description: asString(cc.description).slice(0, MAX_SCHEMA_FIELD),
      memberKeys,
    });
  }
  return out;
}

/** Coerce stored/LLM typed relationships: drop non-canonical endpoints, clamp confidence, require a
 *  relType, bound the list. */
function validateRelationships(raw: unknown): AnalysisRelationship[] {
  if (!Array.isArray(raw)) return [];
  const out: AnalysisRelationship[] = [];
  for (const rel of raw.slice(0, MAX_RELATIONSHIPS)) {
    if (!rel || typeof rel !== "object") continue;
    const rr = rel as Record<string, unknown>;
    const srcKey = asString(rr.srcKey);
    const dstKey = asString(rr.dstKey);
    const relType = asString(rr.relType).slice(0, MAX_SCHEMA_FIELD);
    // codex P1: relType must be a vocab term OR a clean schema label (the write path already gated it
    // via normalizeRel; this read-path check drops any junk + never rewrites a clean schema label).
    if (!relType || (!(relType in REL_VOCAB) && !isCleanToken(relType))) continue;
    if (!isCanonicalOverlayKey(srcKey) || !isCanonicalOverlayKey(dstKey)) continue;
    const confRaw = asString(rr.confidence).toLowerCase();
    out.push({
      srcKey,
      dstKey,
      relType,
      confidence: CONFIDENCE_VALUES.has(confRaw) ? confRaw : "medium",
      evidence: asString(rr.evidence).slice(0, MAX_SCHEMA_FIELD),
    });
  }
  return out;
}

function finiteNum(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** Coerce stored entity scores (canonKey → {threatScore, degree, reportCount}): non-canonical keys
 *  dropped, numbers coerced to finite, bounded — a malformed record can never break the graph. */
function validateScores(raw: unknown): Record<string, EntityScoreRecord> {
  const out: Record<string, EntityScoreRecord> = {};
  if (!raw || typeof raw !== "object") return out;
  let n = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (n >= MAX_OVERLAY_ENTRIES) break;
    if (!isCanonicalOverlayKey(k) || !v || typeof v !== "object") continue;
    const s = v as Record<string, unknown>;
    out[k] = { threatScore: finiteNum(s.threatScore), degree: finiteNum(s.degree), reportCount: finiteNum(s.reportCount) };
    n++;
  }
  return out;
}

/** Coerce stored node metrics (canonKey → {degreeCentrality, betweenness, eigenvector, community}). */
function validateMetrics(raw: unknown): Record<string, NodeMetricRecord> {
  const out: Record<string, NodeMetricRecord> = {};
  if (!raw || typeof raw !== "object") return out;
  let n = 0;
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (n >= MAX_OVERLAY_ENTRIES) break;
    if (!isCanonicalOverlayKey(k) || !v || typeof v !== "object") continue;
    const m = v as Record<string, unknown>;
    out[k] = { degreeCentrality: finiteNum(m.degreeCentrality), betweenness: finiteNum(m.betweenness), eigenvector: finiteNum(m.eigenvector), community: finiteNum(m.community) };
    // PRD-B: carry pathConfidence through the persist chokepoint when present (else leave undefined — the
    // node is unreachable from a seed; not 0-faked). Same lesson as the case_type/subRole strip.
    if (typeof m.pathConfidence === "number" && Number.isFinite(m.pathConfidence)) out[k].pathConfidence = m.pathConfidence;
    n++;
  }
  return out;
}
