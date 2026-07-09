// PRD-7 p7-graph-model: the PURE graph model + deterministic radial layout for the
// findings graph. No DOM, no clock, no randomness — so it is node-testable and lays
// out identically every time. It feeds src/graph/cy-adapter.ts -> the Cytoscape renderer (cy-graph.ts).
//
// The load-bearing rule (codex finding-1 + finding-3): the model is GATE-FAITHFUL.
// It never trusts result.promoted / result.leads blindly. It re-runs isAdmissible()
// on every entity (so a "not graphed" junk lead never becomes a node) and re-runs
// promotionGate() on every promoted finding (so a forged/adversarial promoted entry
// that no longer promotes is demoted to a lead, not drawn as confirmed).

import { isAdmissible, promotionGate, type Finding } from "../agent/gate.js";
import type { InvestigateResult } from "../agent/loop.js";

export type NodeKind = "objective" | "finding" | "lead";

export interface GraphNode {
  id: string;
  label: string;
  kind: NodeKind;
  promoted: boolean;
  entityType?: string;
  /** An EXPLICIT analyst-corrected role (ca-core / codex D1). When unset the renderer derives the role
   *  from entityType via roleFor(); when set (a role correction) it wins, so the graph shape/color reflect
   *  the analyst's authority. */
  role?: string;
  /** A1: the operator's network FUNCTION (leadership/recruiter/infra_provider/…), set by the AI
   *  analysis overlay (applyAnalysisToModel). Display-only — it does NOT change the shape (role does). */
  subRole?: string;
  grade?: string;
  sourceCount?: number;
  infraSourceCount?: number;
  /** The gate's held-reason — present on lead nodes only. */
  reason?: string;
  /** ca-analyze (INC-3): the LLM analytic cluster NAME this node belongs to, set by
   *  applyClustersToModel. Drives the graph node fill color (cap-cluster-colors). Unset → slate. */
  cluster?: string;
  /** INC-4a: the real threat score (compute_threat_scores) set by applyScoresToModel — drives node
   *  sizing + the min_score filter (fallback to the grade proxy when unset). */
  threatScore?: number;
  /** INC-4a graph_metrics (applyMetricsToModel): NetworkX-faithful centrality + Louvain community. */
  degreeCentrality?: number;
  betweenness?: number;
  eigenvector?: number;
  community?: number;
  /** clu-graph-node-parity: provenance — "intake" (from an ingested report), "osint" (agent-discovered),
   *  or "manual". The original graph.html encodes this as the node BORDER STYLE (solid/dashed/dotted).
   *  Set by the projection from the source record's sourceKind; intake wins when an entity is in both. */
  origin?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  /** "promoted"/"lead" = the run-centric objective→entity spoke; "typed_rel" = an INC-4a entity↔entity
   *  semantic edge from the analyze pass (carries the gated rel_type + confidence); "co_occurs"/"linked" =
   *  the entity↔entity NETWORK edges projected from the entity DB (clu-graph-topology) so the home graph is
   *  a web, not a star off the objective hub. typed_rel is REBUILT by applyRelationshipsToModel; co_occurs/
   *  linked are NOT (they come from the structural entity DB, not the analyze overlay), so they keep their
   *  own kinds and survive finalize. */
  kind: "promoted" | "lead" | "typed_rel" | "co_occurs" | "linked";
  /** typed_rel only: the vocabulary-gated relationship type + its confidence (for the edge label/style). */
  relType?: string;
  confidence?: string;
}

export interface GraphModel {
  objective: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const OBJECTIVE_ID = "objective";

function isRenderableEntity(entity: unknown): entity is string {
  return typeof entity === "string" && entity.trim().length > 0;
}

/**
 * Build the node-link model for one run. The objective is the centre; each promoted
 * finding and each held lead that survives the admission + promotion re-checks becomes
 * a spoke node with a radial edge from the objective.
 */
export function buildGraphModel(objective: string, result: InvestigateResult): GraphModel {
  const nodes: GraphNode[] = [
    { id: OBJECTIVE_ID, label: objective, kind: "objective", promoted: false },
  ];
  const edges: GraphEdge[] = [];
  let seq = 0;

  const add = (node: Omit<GraphNode, "id">): void => {
    const id = `${node.kind}:${seq++}:${node.entityType ?? ""}:${node.label}`;
    nodes.push({ ...node, id });
    edges.push({ from: OBJECTIVE_ID, to: id, kind: node.kind === "finding" ? "promoted" : "lead" });
  };

  const promoted: Finding[] = Array.isArray(result?.promoted) ? result.promoted : [];
  for (const f of promoted) {
    if (!isRenderableEntity(f?.entity)) continue;
    if (!isAdmissible(f.entity_type, f.entity)[0]) continue; // codex-1: omit junk the gate rejects
    const verdict = promotionGate(f); // codex-3: re-gate; a non-promoting "promoted" is demoted
    add({
      label: f.entity,
      kind: verdict.promote ? "finding" : "lead",
      promoted: verdict.promote,
      entityType: f.entity_type,
      grade: verdict.grade,
      sourceCount: f.source_count,
      infraSourceCount: f.infra_source_count,
      reason: verdict.promote ? undefined : verdict.reason,
    });
  }

  const leads = Array.isArray(result?.leads) ? result.leads : [];
  for (const entry of leads) {
    const f = entry?.finding;
    if (!isRenderableEntity(f?.entity)) continue;
    if (!isAdmissible(f.entity_type, f.entity)[0]) continue; // codex-1
    add({
      label: f.entity,
      kind: "lead",
      promoted: false,
      entityType: f.entity_type,
      grade: entry.verdict?.grade,
      sourceCount: f.source_count,
      infraSourceCount: f.infra_source_count,
      reason: entry.verdict?.reason,
    });
  }

  return { objective, nodes, edges };
}

/**
 * An objective-only base model (gh-case-model D1): the whole-case graph is built by folding each
 * run's findings into this via mergeGraphModel(base, base's objective id, result). Exported so the
 * caller never needs the private OBJECTIVE_ID (a mismatched fromNodeId makes mergeGraphModel a silent
 * no-op). The objective node keeps OBJECTIVE_ID, so callers pass model.nodes[0].id as fromNodeId.
 */
export function emptyObjectiveGraphModel(label: string): GraphModel {
  return { objective: label, nodes: [{ id: OBJECTIVE_ID, label, kind: "objective", promoted: false }], edges: [] };
}

// ---- PRD-8: incremental merge (grow a node one hop; gate-faithful; dedup -> cross-edge) ----

interface Classified {
  entity: string;
  entityType?: string;
  kind: "finding" | "lead";
  promoted: boolean;
  grade?: string;
  reason?: string;
  sourceCount?: number;
  infraSourceCount?: number;
}

// codex-3: NEVER trust a supplied verdict on a merge. Re-gate every candidate through
// the one gate path (admission then promotion) and derive everything from the result.
function classifyFinding(f: Finding | undefined): Classified | null {
  if (!f || !isRenderableEntity(f.entity)) return null;
  if (!isAdmissible(f.entity_type, f.entity)[0]) return null;
  const verdict = promotionGate(f);
  return {
    entity: f.entity,
    entityType: f.entity_type,
    kind: verdict.promote ? "finding" : "lead",
    promoted: verdict.promote,
    grade: verdict.grade,
    reason: verdict.promote ? undefined : verdict.reason,
    sourceCount: f.source_count,
    infraSourceCount: f.infra_source_count,
  };
}

// codex-4: alias-fold the type so ip/ip_address and wallet/crypto_wallet dedup together.
const TYPE_ALIASES: Record<string, string> = {
  ip_address: "ip",
  crypto_wallet: "wallet",
  hash_md5: "hash",
  hash_sha256: "hash",
};
export function canonType(entityType: string | undefined): string {
  // coerce by type: a forged/legacy record's non-string entity_type (`?? ""` only catches null/undefined)
  // must not crash `.trim()` (the latent entity-DB-build crash; same discipline as isAdmissible/canonRef).
  const k = (typeof entityType === "string" ? entityType : "").trim().toLowerCase();
  return TYPE_ALIASES[k] ?? k;
}
function dedupKey(entityType: string | undefined, entity: string): string {
  return `${canonType(entityType)}|${entity.trim().toLowerCase()}`;
}

const GRADE_ORDER = "ABCD"; // A strongest
function gradeRank(grade: string | undefined): number {
  const i = GRADE_ORDER.indexOf((grade ?? "").toUpperCase());
  return i < 0 ? GRADE_ORDER.length : i; // unknown grade ranks weakest
}
function isStronger(candidate: Classified, node: GraphNode): boolean {
  if (candidate.promoted !== node.promoted) return candidate.promoted; // promoted beats held
  return gradeRank(candidate.grade) < gradeRank(node.grade); // same class: better grade wins
}

// codex-5: a dedup hit with stronger evidence UPGRADES the existing node in place (id +
// position preserved — position lives in the app, not the model).
function upgradeNode(node: GraphNode, candidate: Classified): void {
  if (!isStronger(candidate, node)) return;
  node.kind = candidate.kind;
  node.promoted = candidate.promoted;
  node.grade = candidate.grade;
  node.sourceCount = candidate.sourceCount;
  node.infraSourceCount = candidate.infraSourceCount;
  node.reason = candidate.promoted ? undefined : candidate.reason;
}

// New ids continue past the max existing seq (the 2nd id segment; kind/seq never contain ':').
function nextSeqStart(nodes: GraphNode[]): number {
  let max = -1;
  for (const n of nodes) {
    const seq = Number(n.id.split(":")[1]);
    if (Number.isFinite(seq) && seq > max) max = seq;
  }
  return max + 1;
}

/**
 * Merge a one-hop expansion's findings into `base`, connecting each to `fromNodeId`.
 * Returns a NEW model (never mutates base). A NEW entity becomes a node + edge; an entity
 * already on the graph adds a cross-edge to EVERY matching node (no duplicate) and upgrades
 * it if the new evidence is stronger. Edges are idempotent. A missing `fromNodeId` is a
 * no-op (returns base unchanged) so a stale/invalid expand can never create a dangling edge.
 */
export function mergeGraphModel(base: GraphModel, fromNodeId: string, addition: InvestigateResult, origin: string = "osint"): GraphModel {
  if (!base.nodes.some((n) => n.id === fromNodeId)) return base; // codex-7: no dangling edge

  const nodes: GraphNode[] = base.nodes.map((n) => ({ ...n })); // clone: upgrades never touch base
  const edges: GraphEdge[] = base.edges.map((e) => ({ ...e }));

  const byKey = new Map<string, GraphNode[]>();
  for (const n of nodes) {
    if (n.kind === "objective") continue;
    const k = dedupKey(n.entityType, n.label);
    const list = byKey.get(k);
    if (list) list.push(n);
    else byKey.set(k, [n]);
  }

  const edgeSig = new Set(edges.map((e) => `${e.from} ${e.to}`));
  const addEdge = (from: string, to: string, kind: "promoted" | "lead"): void => {
    if (from === to) return; // no self-loop
    const sig = `${from} ${to}`;
    if (edgeSig.has(sig)) {
      // gh-case-model D2: the edge exists — SYNC its kind to the (possibly upgraded) node so a
      // lead->promoted upgrade across a fold no longer leaves a stale lead-styled edge. Still no
      // duplicate edge (count is idempotent); base is untouched (edges were cloned above).
      const e = edges.find((x) => x.from === from && x.to === to);
      if (e) e.kind = kind;
      return;
    }
    edgeSig.add(sig);
    edges.push({ from, to, kind });
  };

  let seq = nextSeqStart(nodes);
  const candidates: (Finding | undefined)[] = [
    ...(Array.isArray(addition?.promoted) ? addition.promoted : []),
    ...(Array.isArray(addition?.leads) ? addition.leads.map((l) => l?.finding) : []),
  ];

  for (const f of candidates) {
    const c = classifyFinding(f);
    if (!c) continue;
    const existing = byKey.get(dedupKey(c.entityType, c.entity));
    if (existing && existing.length) {
      for (const node of existing) {
        upgradeNode(node, c);
        // clu-graph-node-parity: intake provenance is sticky + wins (an entity seen in any ingested
        // report reads "from intake"); otherwise take this fold's origin if the node had none.
        if (origin === "intake") node.origin = "intake";
        else if (!node.origin) node.origin = origin;
        addEdge(fromNodeId, node.id, node.promoted ? "promoted" : "lead");
      }
    } else {
      const id = `${c.kind}:${seq++}:${c.entityType ?? ""}:${c.entity}`;
      const node: GraphNode = {
        id,
        label: c.entity,
        kind: c.kind,
        promoted: c.promoted,
        entityType: c.entityType,
        grade: c.grade,
        sourceCount: c.sourceCount,
        infraSourceCount: c.infraSourceCount,
        reason: c.reason,
        origin, // clu-graph-node-parity: provenance for the border style
      };
      nodes.push(node);
      byKey.set(dedupKey(c.entityType, c.entity), [node]);
      addEdge(fromNodeId, id, c.kind === "finding" ? "promoted" : "lead");
    }
  }

  return { objective: base.objective, nodes, edges };
}

// ---- cg-network (PRD prd-case-graph): the case/home graph is an entity↔entity NETWORK, no objective hub ----

/**
 * Drop the objective hub node + every edge incident to it, leaving a pure entity↔entity network.
 * Why (scar prd-case-graph-2026-06-22): the FIFA real-case model diff proved the clone's home graph
 * injected an `objective` hub + a star spoke to every entity that the original `api_graph` never had
 * (clone 9 nodes/36 edges vs original 8/28 on identical input). The keystone entity-network fix
 * (withEntityNetworkEdges) half-landed — it added the web but left the star. graphModelForCase strips
 * the hub here so the home graph reads as the original's web. The single-run view (graphModelForRun)
 * keeps its objective root — the star is meaningful for ONE run, so this is case-path only.
 * The GraphModel.objective string FIELD is kept (it is the label, not the node).
 */
export function stripObjective(model: GraphModel): GraphModel {
  const objIds = new Set(model.nodes.filter((n) => n.kind === "objective").map((n) => n.id));
  if (!objIds.size) return model;
  return {
    objective: model.objective,
    nodes: model.nodes.filter((n) => !objIds.has(n.id)),
    edges: model.edges.filter((e) => !objIds.has(e.from) && !objIds.has(e.to)),
  };
}

/**
 * Fold a just-completed run into the entity↔entity network (the run-complete grow path), with NO
 * objective hub and NO objective→entity spokes. Mirrors mergeGraphModel's gate-faithful admission +
 * dedup, but the run's findings connect to EACH OTHER as a co-occurrence clique (they surfaced in
 * the same run) instead of spoking off a hub — the same edge kind withEntityNetworkEdges projects on
 * mount, so the in-session grow and the next mount agree in shape.
 *
 * No-related-entity rule (PRD finding-2, the silent-drop guard): nodes are added UNCONDITIONALLY;
 * only EDGES depend on relations. A run whose entities relate to nothing already on the graph still
 * lands its nodes — connected to each other if ≥2, an isolated node if a singleton. An isolated node
 * is parity-correct (the original shows a lone role-bearing entity as an isolated node too), so a run
 * can never be dropped; it can only be edge-isolated. Returns a NEW model; never mutates `base`.
 */
export function mergeNetworkModel(
  base: GraphModel,
  addition: InvestigateResult,
  // sp-9ef4fa65: the case-level edge backstop (MAX_NETWORK_EDGES). Required, not defaulted — the only
  // caller (growCaseNetwork) passes it, and a default would silently change the cap. It sits before
  // `origin` because a required param cannot follow an optional/defaulted one in TS. (sp-4285b671: the
  // former maxCooccurEntities field was removed — the co-occurrence clique it capped is gone, so it was dead.)
  caps: { maxNetworkEdges: number },
  origin: string = "osint",
): GraphModel {
  const nodes: GraphNode[] = base.nodes.map((n) => ({ ...n }));
  const edges: GraphEdge[] = base.edges.map((e) => ({ ...e }));

  const byKey = new Map<string, GraphNode[]>();
  for (const n of nodes) {
    if (n.kind === "objective") continue;
    const k = dedupKey(n.entityType, n.label);
    const list = byKey.get(k);
    if (list) list.push(n);
    else byKey.set(k, [n]);
  }

  // one undirected network edge per unordered node-id pair (idempotent across repeated grows).
  // codex: node ids embed the raw entity label (which can contain spaces), so a space-delimited
  // signature is ambiguous and could collide two distinct pairs into one — suppressing a valid edge.
  // Use a JSON-array signature (unambiguous regardless of label content) for the pair key.
  const pairSig = (x: string, y: string): string => (x < y ? JSON.stringify([x, y]) : JSON.stringify([y, x]));
  const edgeSig = new Set(edges.map((e) => pairSig(e.from, e.to)));
  // co_occurs clique helper REMOVED (founder 2026-06-24, [[no-cooccurrence-edges]]): co-occurrence is not a
  // relationship, so no edge. edgeSig/pairSig remain — the agent's typed `linked` edges below still dedup.

  let seq = nextSeqStart(nodes);
  const candidates: (Finding | undefined)[] = [
    ...(Array.isArray(addition?.promoted) ? addition.promoted : []),
    ...(Array.isArray(addition?.leads) ? addition.leads.map((l) => l?.finding) : []),
  ];

  // resolve each finding to its node id (existing-after-dedup or newly added), so the clique edges
  // below connect the run's OWN entities. promoted flag tracked for the co-occurrence confidence.
  const runEntities: { id: string; promoted: boolean }[] = [];
  for (const f of candidates) {
    const c = classifyFinding(f);
    if (!c) continue;
    const existing = byKey.get(dedupKey(c.entityType, c.entity));
    if (existing && existing.length) {
      const node = existing[0]; // dedup-merge into the canonical node (clique connects via its id)
      upgradeNode(node, c);
      if (origin === "intake") node.origin = "intake";
      else if (!node.origin) node.origin = origin;
      runEntities.push({ id: node.id, promoted: node.promoted });
    } else {
      const id = `${c.kind}:${seq++}:${c.entityType ?? ""}:${c.entity}`;
      const node: GraphNode = {
        id, label: c.entity, kind: c.kind, promoted: c.promoted, entityType: c.entityType,
        grade: c.grade, sourceCount: c.sourceCount, infraSourceCount: c.infraSourceCount,
        reason: c.reason, origin,
      };
      nodes.push(node);
      byKey.set(dedupKey(c.entityType, c.entity), [node]);
      runEntities.push({ id, promoted: c.promoted });
    }
  }

  // PRD-B (RCA item 3): fold THIS run's LIVE agent relationships as TYPED `linked` edges BEFORE the
  // co-occurrence clique, so the agent's EXPLICIT links paint as typed edges (not co_occurs) the moment the
  // run completes — codex issue-6 C2 (growCaseNetwork was dropping result.relationships, so a live-emitted
  // link only appeared after a full remount). Both endpoints must be THIS run's admitted nodes (mirrors
  // agentRelationshipsToLinks' both-endpoints-admitted rule — no phantom edge). Adding them first lets the
  // clique's edgeSig dedup keep the typed kind for a pair that is also a co-occurrence.
  const runNodeIds = new Set(runEntities.map((e) => e.id));
  const idByLabel = new Map<string, string>();
  for (const n of nodes) {
    if (n.kind === "objective" || !runNodeIds.has(n.id)) continue;
    const k = n.label.trim().toLowerCase();
    if (!idByLabel.has(k)) idByLabel.set(k, n.id);
  }
  for (const r of Array.isArray(addition?.relationships) ? addition.relationships : []) {
    if (edges.length >= caps.maxNetworkEdges) break;
    const fromId = idByLabel.get((r?.src ?? "").trim().toLowerCase());
    const toId = idByLabel.get((r?.dst ?? "").trim().toLowerCase());
    if (!fromId || !toId || fromId === toId) continue; // both endpoints must be this run's nodes
    const [lo, hi] = fromId < toId ? [fromId, toId] : [toId, fromId];
    const sig = pairSig(lo, hi);
    if (edgeSig.has(sig)) continue;
    edgeSig.add(sig);
    const conf = r.confidence === "high" ? "high" : r.confidence === "low" ? "low" : "medium";
    edges.push({ from: lo, to: hi, kind: "linked", confidence: conf, relType: typeof r.relType === "string" ? r.relType : undefined });
  }

  // co-occurrence clique: REMOVED (founder 2026-06-24, [[no-cooccurrence-edges]]). Two entities surfacing in
  // the SAME run is NOT a relationship and must not draw an edge — the graph is a true relationship network.
  // Only the agent's EXPLICIT typed `linked` relationships (folded above) and the objective `surfaced_in`
  // spoke become edges, mirroring the no-co_occurs buildEntityDb projection. runEntities is still resolved
  // above so the linked edges anchor to this run's nodes.

  return { objective: base.objective, nodes, edges };
}
