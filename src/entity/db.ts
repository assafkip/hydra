// The client entity/edge data layer — the "entity DB" the node drawer + chat
// node/edge cards read. A PURE, gate-faithful PROJECTION over accumulated run
// results (no DOM, no clock, no randomness, no persistence). It is NOT a second
// write path: the spine doctrine is ONE write path (createWritable lives only in
// src/vault/store.ts); this layer only READS the already-persisted runs + the
// current graph model and DERIVES. Gate fidelity mirrors src/graph/model.ts —
// every entity is re-run through isAdmissible + promotionGate, so junk never
// lands and a forged-promoted is demoted to a lead.
//
// Trust boundary (codex D3): source_count / infra_source_count are taken from the
// persisted/already-gated findings, EXACTLY as src/graph/model.ts does. RunRecord
// does not retain the raw tool observations, so a finding whose counts were FORGED
// by an attacker who can already WRITE the encrypted vault (i.e. the data key is
// compromised) would be trusted — that is out of this layer's reach and identical
// to the existing graph. Deeper attribution provenance is a RunRecord-schema
// change handled at the ingest layer, not here. db.test.ts pins a forged-high-count case so the
// behavior is defined, not silent.

import { isAdmissible, promotionGate, type Finding, type GateVerdict } from "../agent/gate.js";
import { canonType, type GraphModel } from "../graph/model.js";
import { roleFor } from "../graph/cy-adapter.js";

// codex D6: pair only the first N admissible entities of a run, SLICING before
// pairing, so co-occurrence is bounded at N·(N-1)/2 and never materializes a full
// n² list on a huge run. A slice sets cooccurTruncated (surfaced in the dossier —
// no silent cap).
export const MAX_COOCCUR_ENTITIES = 48;

export type RelType = "surfaced_in" | "co_occurs" | "linked";
export type Confidence = "high" | "medium" | "low";
export type Direction = "in" | "out" | "undirected";

/** Canonical entity identity (type alias-folded, value trim+lowercased). */
export interface EntityRef {
  type: string;
  value: string;
}

/** One entity's appearance in a run (already classified by the caller's adapter). */
export interface IngestEntity {
  value: string; // display value
  type?: string; // raw type label
  promoted: boolean;
  grade?: string;
  sourceCount?: number;
  infraSourceCount?: number;
  reason?: string; // held reason (lead)
}

/** An explicit entity↔entity link (expansion cross-edge); never an objective endpoint. */
export interface IngestLink {
  fromValue: string;
  fromType?: string;
  toValue: string;
  toType?: string;
  promoted: boolean; // the cross-edge's target classification (graph edge kind === 'promoted')
}

export interface IngestRun {
  objective: string;
  entities: IngestEntity[];
  links: IngestLink[];
  // prd-parity-graph-faithful: PROXIMITY co-occurrence pairs (entity VALUE pairs within 200 chars,
  // computed at ingest by infer_relationships). When present (text ingest), buildEntityDb draws
  // co_occurs from these SPARSE pairs; when absent (agent run, no text proximity), it falls back to
  // all-pairs. This is the faithful original structure — not a complete graph (the hairball fix).
  coOccur?: Array<[string, string]>;
}

export interface EntityRecord {
  ref: EntityRef;
  label: string; // display value (first seen)
  type: string; // display type (first seen raw)
  caseType?: string; // PRD-B typing-case-type: the per-case ANALYTIC type from the schema (scam_domain,
  // wallet_address…), an AI overlay from the typing pass — distinct from the crude regex surface `type`
  // (port of typing.py case_type). Undefined until the typing pass assigns one.
  role: string; // operator/channel/ioc/infra/source
  subRole?: string; // A1: operator network FUNCTION (leadership/recruiter/…) — AI overlay, display-only
  promoted: boolean; // promoted in ANY run
  grade?: string; // best across appearances
  sourceCount: number; // max observed
  infraSourceCount: number; // max observed
  runs: string[]; // objectives that surfaced it
  reasons: string[]; // distinct held reasons (when a lead)
}

export interface Connection {
  other: EntityRef; // the other endpoint (may be a synthetic seed ref)
  otherLabel: string;
  otherType: string;
  otherRole: string;
  relType: RelType;
  direction: Direction; // relative to the queried entity
  confidence: Confidence;
  runs: string[]; // supporting objectives
  count: number; // runs.length
}

export interface EdgeEvidence {
  src: EntityRef;
  dst: EntityRef;
  srcLabel: string;
  dstLabel: string;
  relType: RelType;
  confidence: Confidence;
  runs: string[];
}

export interface Dossier {
  headline: string;
  lines: string[];
}

export interface EntityStore {
  entities: Record<string, EntityRecord>; // key = entityKey(ref)
  connections: Record<string, Connection[]>; // key -> that entity's connections
  cooccurTruncated: boolean;
}

const OBJECTIVE_TYPE = "objective";

function canonRef(type: string | undefined, value: string): EntityRef {
  // value is typed string, but a forged/legacy record can pass a non-string at runtime — coerce so `.trim()`
  // can't crash the entity-DB build (canonType already coerces the type; same forged-record discipline).
  return { type: canonType(type), value: (typeof value === "string" ? value : "").trim().toLowerCase() };
}
function seedRef(objective: string): EntityRef {
  return { type: OBJECTIVE_TYPE, value: objective.trim().toLowerCase() };
}
// codex D7: delimiter-SAFE key (JSON tuple, not a '|'-join) so {a, 'b|c'} and
// {'a|b', c} never collide and merge unrelated entities. Exported (cl-build D5) so the
// clusters layer keys entities by EXACTLY the same DB identity (no drift).
export function entityKey(ref: EntityRef): string {
  return JSON.stringify([ref.type, ref.value]);
}

// ca-core (codex D3): THE single canonical entity key, used by the corrections store + the /entities row
// + the ⌘K search, so `ip_address`/`ip` (and crypto_wallet/wallet, hash aliases) + case/trim variants all
// resolve to ONE key — a correction can never silently orphan because a caller built the key differently.
export function canonKey(type: string | undefined, value: string): string {
  return entityKey(canonRef(type, value));
}
function isRenderable(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

// ---- confidence ----

const CONF_ORDER: Confidence[] = ["low", "medium", "high"];
function maxConf(a: Confidence, b: Confidence): Confidence {
  return CONF_ORDER.indexOf(a) >= CONF_ORDER.indexOf(b) ? a : b;
}

const GRADE_ORDER = "ABCD";
function gradeRank(grade: string | undefined): number {
  const g = (grade ?? "").toUpperCase();
  const i = GRADE_ORDER.indexOf(g);
  // "".indexOf is 0, so guard the empty/unknown grade to rank WEAKEST, not strongest.
  return g === "" || i < 0 ? GRADE_ORDER.length : i;
}

// ---- the internal edge accumulator ----

interface Endpoint {
  ref: EntityRef;
  label: string;
  type: string;
  role: string;
  isEntity: boolean; // false for the synthetic objective/seed endpoint
}
interface InternalEdge {
  from: Endpoint;
  to: Endpoint;
  relType: RelType;
  undirected: boolean; // co_occurs
  runs: Set<string>;
  conf: Confidence;
}

function edgeKeyFor(relType: RelType, fromKey: string, toKey: string, undirected: boolean): string {
  if (undirected) return `${relType}|${[fromKey, toKey].sort().join("::")}`;
  return `${relType}|${fromKey}->${toKey}`;
}

// ---- adapters: a run record / a graph model -> a normalized IngestRun ----

function classify(f: Finding | undefined): IngestEntity | null {
  if (!f || !isRenderable(f.entity)) return null;
  if (!isAdmissible(f.entity_type, f.entity)[0]) return null; // gate-faithful: junk never lands
  const verdict: GateVerdict = promotionGate(f); // never trust a supplied verdict — re-gate
  return {
    value: f.entity,
    type: f.entity_type,
    promoted: verdict.promote,
    grade: verdict.grade,
    sourceCount: f.source_count,
    infraSourceCount: f.infra_source_count,
    reason: verdict.promote ? undefined : verdict.reason,
  };
}

/** A persisted RunRecord (objective + promoted + held leads) -> an IngestRun. The
 *  objective is a run endpoint, NOT an entity (codex D4); links are implicit (the
 *  builder derives surfaced_in + co_occurs). Re-gates every finding. */
export function runRecordToIngest(
  objective: string,
  promoted: Finding[] | undefined,
  leads: { finding: Finding; verdict: GateVerdict }[] | undefined,
  coOccur?: Array<[string, string]>,
): IngestRun {
  const entities: IngestEntity[] = [];
  for (const f of Array.isArray(promoted) ? promoted : []) {
    const e = classify(f);
    if (e) entities.push(e);
  }
  for (const entry of Array.isArray(leads) ? leads : []) {
    const e = classify(entry?.finding);
    if (e) entities.push(e);
  }
  // prd-parity-graph-faithful: carry the proximity pairs through (text ingest only; undefined for
  // agent runs → buildEntityDb keeps all-pairs there). Normalized to lowercase value pairs.
  const co = Array.isArray(coOccur)
    ? coOccur.filter((p): p is [string, string] => Array.isArray(p) && p.length === 2 && !!p[0] && !!p[1])
    : undefined;
  return { objective, entities, links: [], coOccur: co };
}

/** The current (gate-faithful, already key-redacted) GraphModel -> an IngestRun.
 *  The objective node is skipped (codex D4: never an entity). Entity↔entity edges
 *  become explicit `linked` links; objective→entity edges are implicit. */
export function graphModelToIngest(model: GraphModel | null | undefined): IngestRun {
  if (!model || typeof model.objective !== "string") return { objective: "", entities: [], links: [] };
  const nodes = Array.isArray(model.nodes) ? model.nodes : [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const entities: IngestEntity[] = [];
  for (const n of nodes) {
    if (n.kind === "objective") continue; // codex D4
    if (!isRenderable(n.label)) continue;
    entities.push({
      value: n.label,
      type: n.entityType,
      promoted: n.kind === "finding",
      grade: n.grade,
      sourceCount: n.sourceCount,
      infraSourceCount: n.infraSourceCount,
      reason: n.kind === "lead" ? n.reason : undefined,
    });
  }
  const links: IngestLink[] = [];
  for (const e of Array.isArray(model.edges) ? model.edges : []) {
    const from = byId.get(e.from);
    const to = byId.get(e.to);
    if (!from || !to) continue;
    if (from.kind === "objective" || to.kind === "objective") continue; // implicit surfaced_in
    if (!isRenderable(from.label) || !isRenderable(to.label)) continue;
    links.push({
      fromValue: from.label,
      fromType: from.entityType,
      toValue: to.label,
      toType: to.entityType,
      promoted: e.kind === "promoted",
    });
  }
  return { objective: model.objective, entities, links };
}

// ---- the builder ----

function mergeEntity(
  entities: Map<string, EntityRecord>,
  key: string,
  ref: EntityRef,
  ie: IngestEntity,
  objective: string,
): EntityRecord {
  let rec = entities.get(key);
  if (!rec) {
    rec = {
      ref,
      label: ie.value,
      type: ie.type ?? "",
      role: roleFor(ie.type),
      promoted: false,
      grade: undefined,
      sourceCount: 0,
      infraSourceCount: 0,
      runs: [],
      reasons: [],
    };
    entities.set(key, rec);
  }
  rec.promoted = rec.promoted || ie.promoted;
  if (gradeRank(ie.grade) < gradeRank(rec.grade)) rec.grade = ie.grade;
  rec.sourceCount = Math.max(rec.sourceCount, ie.sourceCount ?? 0);
  rec.infraSourceCount = Math.max(rec.infraSourceCount, ie.infraSourceCount ?? 0);
  if (!rec.runs.includes(objective)) rec.runs.push(objective);
  if (ie.reason && !ie.promoted && !rec.reasons.includes(ie.reason)) rec.reasons.push(ie.reason);
  return rec;
}

/**
 * Fold a set of IngestRuns into the entity DB. Pure + deterministic (no clock /
 * randomness): the same runs always produce the same store. Accumulates entities
 * (dedup-merged across runs), surfaced_in (objective→entity), co_occurs (entity
 * pairs in a run, sliced-capped), and linked (explicit cross-edges).
 */
export function buildEntityDb(runs: IngestRun[]): EntityStore {
  const entities = new Map<string, EntityRecord>();
  const edges = new Map<string, InternalEdge>();
  let cooccurTruncated = false;

  const addEdge = (from: Endpoint, to: Endpoint, relType: RelType, undirected: boolean, objective: string, conf: Confidence): void => {
    const fk = entityKey(from.ref);
    const tk = entityKey(to.ref);
    if (fk === tk) return; // no self-loop
    const ek = edgeKeyFor(relType, fk, tk, undirected);
    let e = edges.get(ek);
    if (!e) {
      e = { from, to, relType, undirected, runs: new Set(), conf };
      edges.set(ek, e);
    }
    e.runs.add(objective);
    e.conf = maxConf(e.conf, conf);
  };

  for (const run of Array.isArray(runs) ? runs : []) {
    if (!run || typeof run.objective !== "string") continue;
    const seed: Endpoint = {
      ref: seedRef(run.objective),
      label: run.objective,
      type: OBJECTIVE_TYPE,
      role: "seed",
      isEntity: false,
    };

    // Merge entities + collect this run's distinct (per-key) entity endpoints.
    const runEnts: { ep: Endpoint; ie: IngestEntity }[] = [];
    const seenInRun = new Set<string>();
    for (const ie of Array.isArray(run.entities) ? run.entities : []) {
      if (!isRenderable(ie?.value)) continue;
      const ref = canonRef(ie.type, ie.value);
      const key = entityKey(ref);
      const rec = mergeEntity(entities, key, ref, ie, run.objective);
      if (seenInRun.has(key)) continue;
      seenInRun.add(key);
      runEnts.push({ ep: { ref, label: rec.label, type: rec.type, role: rec.role, isEntity: true }, ie });
    }

    // surfaced_in: the seed -> each entity (directed; rendered "in" on the entity).
    for (const { ep, ie } of runEnts) {
      addEdge(seed, ep, "surfaced_in", false, run.objective, ie.promoted ? "high" : "low");
    }

    // co_occurs (prd-parity-graph-faithful): when the run carries PROXIMITY pairs (text ingest,
    // infer_relationships), draw co_occurs from ONLY those sparse pairs — the faithful original
    // structure. When absent (agent run / legacy: no text proximity), keep all-pairs. Single
    // producer of co_occurs; the cap still bounds the endpoint set.
    if (runEnts.length > MAX_COOCCUR_ENTITIES) cooccurTruncated = true;
    const pairEnts = runEnts.slice(0, MAX_COOCCUR_ENTITIES);
    if (Array.isArray(run.coOccur)) {
      // Match by a NORMALIZED value (lowercase+trim) so a casing drift between the stored pair and the
      // admitted IngestEntity.value can't silently drop an edge (codex).
      const norm = (s: string): string => String(s ?? "").trim().toLowerCase();
      const epByValue = new Map<string, { ep: Endpoint; ie: IngestEntity }>();
      for (const re of pairEnts) epByValue.set(norm(re.ie.value), re);
      const seenPair = new Set<string>();
      for (const [av, bv] of run.coOccur) {
        const a = epByValue.get(norm(av));
        const b = epByValue.get(norm(bv));
        if (!a || !b) continue; // an endpoint not in the admitted set → skip (a junk entity was gated out)
        const pk = [av, bv].sort().join(" ");
        if (seenPair.has(pk)) continue;
        seenPair.add(pk);
        const conf: Confidence = a.ie.promoted && b.ie.promoted ? "medium" : "low";
        addEdge(a.ep, b.ep, "co_occurs", true, run.objective, conf);
      }
    } else {
      for (let i = 0; i < pairEnts.length; i++) {
        for (let j = i + 1; j < pairEnts.length; j++) {
          const a = pairEnts[i];
          const b = pairEnts[j];
          const conf: Confidence = a.ie.promoted && b.ie.promoted ? "medium" : "low";
          addEdge(a.ep, b.ep, "co_occurs", true, run.objective, conf);
        }
      }
    }

    // linked: explicit entity↔entity cross-edges (expansion).
    for (const link of Array.isArray(run.links) ? run.links : []) {
      if (!isRenderable(link?.fromValue) || !isRenderable(link?.toValue)) continue;
      const fromRef = canonRef(link.fromType, link.fromValue);
      const toRef = canonRef(link.toType, link.toValue);
      if (fromRef.type === OBJECTIVE_TYPE || toRef.type === OBJECTIVE_TYPE) continue; // defensive
      const fromEp: Endpoint = { ref: fromRef, label: link.fromValue, type: link.fromType ?? "", role: roleFor(link.fromType), isEntity: true };
      const toEp: Endpoint = { ref: toRef, label: link.toValue, type: link.toType ?? "", role: roleFor(link.toType), isEntity: true };
      addEdge(fromEp, toEp, "linked", false, run.objective, link.promoted ? "high" : "medium");
    }
  }

  const connections = resolveConnections(entities, edges);
  return { entities: Object.fromEntries(entities), connections, cooccurTruncated };
}

// Turn the edge accumulator into per-entity connection lists (direction relative
// to each ENTITY endpoint; the synthetic seed endpoint gets no list — codex D4/D5).
function resolveConnections(
  entities: Map<string, EntityRecord>,
  edges: Map<string, InternalEdge>,
): Record<string, Connection[]> {
  const out: Record<string, Connection[]> = {};
  const push = (ownerKey: string, other: Endpoint, e: InternalEdge, direction: Direction): void => {
    if (!entities.has(ownerKey)) return; // seed/objective endpoints carry no list
    const conn: Connection = {
      other: other.ref,
      otherLabel: other.label,
      otherType: other.type,
      otherRole: other.role,
      relType: e.relType,
      direction,
      confidence: e.conf,
      runs: [...e.runs].sort(),
      count: e.runs.size,
    };
    (out[ownerKey] ??= []).push(conn);
  };

  for (const e of edges.values()) {
    const fk = entityKey(e.from.ref);
    const tk = entityKey(e.to.ref);
    if (e.undirected) {
      push(fk, e.to, e, "undirected");
      push(tk, e.from, e, "undirected");
    } else {
      push(fk, e.to, e, "out");
      push(tk, e.from, e, "in");
    }
  }

  for (const key of Object.keys(out)) out[key].sort(connectionSort);
  return out;
}

const REL_PRIORITY: Record<RelType, number> = { linked: 0, surfaced_in: 1, co_occurs: 2 };
function connectionSort(a: Connection, b: Connection): number {
  if (REL_PRIORITY[a.relType] !== REL_PRIORITY[b.relType]) return REL_PRIORITY[a.relType] - REL_PRIORITY[b.relType];
  if (a.count !== b.count) return b.count - a.count;
  if (a.confidence !== b.confidence) return CONF_ORDER.indexOf(b.confidence) - CONF_ORDER.indexOf(a.confidence);
  return a.otherLabel.localeCompare(b.otherLabel);
}

// ---- accessors (pure) ----

/** The entity record for a (type, value), or null. An objective/seed value is
 *  never an entity record (codex D4). */
export function getEntity(store: EntityStore, type: string | undefined, value: string): EntityRecord | null {
  if (canonType(type) === OBJECTIVE_TYPE) return null;
  return store.entities[entityKey(canonRef(type, value))] ?? null;
}

export function connectionsFor(store: EntityStore, type: string | undefined, value: string): Connection[] {
  return store.connections[entityKey(canonRef(type, value))] ?? [];
}

export function coOccurrencesFor(store: EntityStore, type: string | undefined, value: string): Connection[] {
  return connectionsFor(store, type, value).filter((c) => c.relType === "co_occurs");
}

/** The evidence for the connection between two entities, in either order (codex
 *  D5 — symmetric). Prefers a stronger relType (linked > surfaced_in > co_occurs). */
export function edgeEvidence(store: EntityStore, a: EntityRef, b: EntityRef): EdgeEvidence | null {
  const ak = entityKey({ type: canonType(a.type), value: a.value.trim().toLowerCase() });
  const bk = entityKey({ type: canonType(b.type), value: b.value.trim().toLowerCase() });
  const pick = (fromKey: string, otherKey: string): Connection | null => {
    const list = store.connections[fromKey];
    if (!list) return null;
    let best: Connection | null = null;
    for (const c of list) {
      if (entityKey({ type: canonType(c.other.type), value: c.other.value.trim().toLowerCase() }) !== otherKey) continue;
      if (!best || REL_PRIORITY[c.relType] < REL_PRIORITY[best.relType]) best = c;
    }
    return best;
  };
  const fromA = pick(ak, bk);
  const fromB = pick(bk, ak);
  const chosen = fromA && fromB ? (REL_PRIORITY[fromA.relType] <= REL_PRIORITY[fromB.relType] ? fromA : fromB) : fromA ?? fromB;
  if (!chosen) return null;
  // Present src->dst as the caller asked (a -> b); the relation itself is symmetric.
  const aRec = store.entities[ak];
  const bRec = store.entities[bk];
  return {
    src: { type: canonType(a.type), value: a.value.trim().toLowerCase() },
    dst: { type: canonType(b.type), value: b.value.trim().toLowerCase() },
    srcLabel: aRec?.label ?? a.value,
    dstLabel: bRec?.label ?? b.value,
    relType: chosen.relType,
    confidence: chosen.confidence,
    runs: chosen.runs,
  };
}

// ---- page accessors (Entities / Cross-case views) ----

function entitySort(a: EntityRecord, b: EntityRecord): number {
  if (a.promoted !== b.promoted) return a.promoted ? -1 : 1; // promoted first
  const g = gradeRank(a.grade) - gradeRank(b.grade);
  if (g !== 0) return g; // better grade first
  if (a.runs.length !== b.runs.length) return b.runs.length - a.runs.length; // more runs first
  return a.label.localeCompare(b.label);
}

/** Every entity in the DB, sorted (promoted, grade, run-count, label). For the Entities page. */
export function allEntities(store: EntityStore): EntityRecord[] {
  return Object.values(store.entities).sort(entitySort);
}

/** Entities seen in MORE THAN ONE run — the cross-case overlap. For the Cross-case page. */
export function crossRunEntities(store: EntityStore): EntityRecord[] {
  return allEntities(store).filter((e) => e.runs.length > 1);
}

// ---- alias links (INC-2: port of correlate/engine.py auto_link_aliases + _similar) ----
//
// auto_link_aliases flags person/person_candidate entities whose canonical names share a high
// token overlap as the same actor under two spellings ("also known as"). The server PERSISTS these
// in an `aliases` table during Process; kipi-web models it as a PURE LIVE VIEW instead (ca-correlate
// D1) — the computation is deterministic (no LLM), so a stored map could only go STALE when an
// analyst correction or a new run changes the entity set. A live view is always current. This is the
// same reason crossRunEntities / crossDomainEntities are live views, not table writes.

const PERSON_TYPES = new Set(["person", "person_candidate"]);
// codex D6 (ca-correlate): hard person bound. The pass is O(persons^2); above this it returns {} so a
// pathological vault can never freeze the synchronous entity-detail render. 600^2/2 ~ 180k cheap
// token-set ops is the bounded worst case; a real case has well under 600 persons.
export const ALIAS_MAX_PERSONS = 600;
const ALIAS_THRESHOLD = 0.8;

/** Token-overlap ratio (port of engine.py:_similar): |tokens(a) ∩ tokens(b)| / max(|a|,|b|). */
function tokenOverlap(a: string, b: string): number {
  const ta = new Set(a.toLowerCase().split(/\s+/).filter(Boolean));
  const tb = new Set(b.toLowerCase().split(/\s+/).filter(Boolean));
  if (ta.size === 0 || tb.size === 0) return 0;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  return inter / Math.max(ta.size, tb.size);
}

/**
 * Alias links keyed by the store's canonical entityKey -> the OTHER entity's display labels. PURE +
 * deterministic (no clock, no randomness, no LLM). Symmetric: if A aliases B then B aliases A (the
 * relationship is inherently symmetric; the server stored only the lower-id direction, a loop
 * artifact — both sides showing each other is the correct UX). Byte-identical canonical values are
 * NOT aliases (they are the same entity and already merged on one key). Above ALIAS_MAX_PERSONS the
 * map is empty (codex D6 bound).
 */
export function computeAliasLinks(store: EntityStore, threshold = ALIAS_THRESHOLD): Record<string, string[]> {
  // codex (ca-correlate impl review): eligibility is by the STABLE identity ref.type, NOT the mutable
  // display e.type. applyAnalysis (typing) + corrections overlay e.type, so filtering on e.type would
  // drop a person's aliases the moment its display type is retyped — while ref.type (the canonical
  // identity, never overlaid) still says person. The server filters on the persisted entity_type for
  // the same reason (typing writes case_type, not entity_type).
  const persons = Object.values(store.entities).filter((e) => PERSON_TYPES.has(e.ref.type));
  if (persons.length > ALIAS_MAX_PERSONS) return {}; // codex D6: bound the synchronous O(n^2) pass
  const out: Record<string, string[]> = {};
  const push = (key: string, label: string): void => {
    const list = out[key] ?? (out[key] = []);
    if (!list.includes(label)) list.push(label);
  };
  for (let i = 0; i < persons.length; i++) {
    for (let j = i + 1; j < persons.length; j++) {
      const a = persons[i];
      const b = persons[j];
      if (a.ref.value === b.ref.value) continue; // same canonical value → already one entity, not an alias
      if (tokenOverlap(a.ref.value, b.ref.value) < threshold) continue;
      push(entityKey(a.ref), b.label);
      push(entityKey(b.ref), a.label);
    }
  }
  return out;
}

// Memoize per store object (codex D6 — "no memoization strategy"). renderEntitiesPage builds ONE
// store and reuses it for every row, so the WeakMap computes the O(n^2) pass once per render and
// every entity-detail expand reads the cache; the map is GC'd when the store is. The UI + Process
// step both read THROUGH this; the pure computeAliasLinks stays the testable, allocation-free core.
// INVARIANT (codex adversarial — staleness): a store is IMMUTABLE. entityDbFor rebuilds a fresh store
// object on every call (after a correction / new run / re-render), so a changed entity set always
// yields a NEW cache key — never a stale hit. The cache is correct precisely because no caller mutates
// store.entities in place; if that ever changes, key on a content hash instead of object identity.
const aliasCache = new WeakMap<EntityStore, Record<string, string[]>>();
export function aliasLinksFor(store: EntityStore): Record<string, string[]> {
  let m = aliasCache.get(store);
  if (!m) {
    m = computeAliasLinks(store);
    aliasCache.set(store, m);
  }
  return m;
}

const RUN_LIST_CAP = 6;

/** A DERIVED per-entity dossier (no LLM, no fabrication — every line is a real
 *  count from the store). Null for an unknown / objective entity. */
export function buildDossier(store: EntityStore, type: string | undefined, value: string): Dossier | null {
  const rec = getEntity(store, type, value);
  if (!rec) return null;
  const conns = connectionsFor(store, type, value);
  const coCount = conns.filter((c) => c.relType === "co_occurs").length;
  const status = rec.promoted ? "promoted" : "lead";
  const headline =
    `${rec.label} — ${rec.role} · ${rec.type || "entity"}` +
    `${rec.grade ? ` · grade ${rec.grade}` : ""} · ${status}`;

  const lines: string[] = [];
  const runsShown = rec.runs.slice(0, RUN_LIST_CAP);
  const more = rec.runs.length - runsShown.length;
  lines.push(
    `Seen in ${rec.runs.length} run(s)` +
      (runsShown.length ? `: ${runsShown.join(", ")}${more > 0 ? `, +${more} more` : ""}` : ""),
  );
  lines.push(`${conns.length} connection(s) · ${coCount} co-occurring`);
  lines.push(`Sources: ${rec.sourceCount}${rec.infraSourceCount ? ` (infra ${rec.infraSourceCount})` : ""}`);
  if (!rec.promoted && rec.reasons.length) lines.push(`Held: ${rec.reasons[0]}`);
  if (store.cooccurTruncated) lines.push("(co-occurrence sampled — large run)");
  return { headline, lines };
}
