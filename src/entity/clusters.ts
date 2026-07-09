// cl-build: deterministic, gate-faithful CLUSTERS — connected components over the entity DB's
// entity↔entity edges (co_occurs + linked). PURE: no DOM, clock, randomness, LLM, or fetch, so the
// same store always yields the same clusters. Nothing is invented — the components are computed
// mechanically from edges the admission+promotion gate already admitted (the cardinal-sin guard).
//
// Two gate-faithfulness invariants the codex review pinned:
//  - surfaced_in edges point at the run's OBJECTIVE endpoint (NOT an entity), so they never merge
//    two entities; adjacency unions ONLY co_occurs|linked edges whose other endpoint is a real
//    entity in store.entities (codex D6) — the objective/seed can never appear in a cluster.
//  - a directed `linked` edge is treated UNDIRECTED for components (codex D3): A→B clusters both.
// Identity is the EXACT db.ts entityKey (codex D5 — no drift). All ordering is a TOTAL order
// (codex D4), so the cluster ids + member order are deterministic regardless of insertion order.

import { entityKey, type EntityStore, type EntityRecord, type EntityRef } from "./db.js";
import { canonType } from "../graph/model.js";

export interface Cluster {
  id: string;
  label: string;
  kind: string;
  members: EntityRef[];
  size: number;
  roleCounts: Record<string, number>;
}

const ROLE_KIND: Record<string, string> = {
  infra: "infrastructure block",
  operator: "crew",
  channel: "venue",
  ioc: "ioc cluster",
  source: "source cluster",
};

const CLUSTER_REL = new Set(["co_occurs", "linked"]);
const ROLE_PRIORITY: Record<string, number> = { operator: 0, channel: 1, ioc: 2, infra: 3, source: 4 };
const GRADE_ORDER = "ABCD";

function gradeRank(g?: string): number {
  const u = (g ?? "").toUpperCase();
  const i = GRADE_ORDER.indexOf(u);
  return u === "" || i < 0 ? GRADE_ORDER.length : i; // unknown grade ranks WEAKEST
}
function rolePriority(role: string): number {
  return role in ROLE_PRIORITY ? ROLE_PRIORITY[role] : 9;
}

// TOTAL order for the representative member (codex D4) — every field is a tie-breaker down to the
// canonical key, so the representative never depends on iteration order.
function representativeBetter(a: EntityRecord, b: EntityRecord): boolean {
  if (rolePriority(a.role) !== rolePriority(b.role)) return rolePriority(a.role) < rolePriority(b.role);
  if (a.promoted !== b.promoted) return a.promoted;
  if (gradeRank(a.grade) !== gradeRank(b.grade)) return gradeRank(a.grade) < gradeRank(b.grade);
  if (a.sourceCount !== b.sourceCount) return a.sourceCount > b.sourceCount;
  if (a.infraSourceCount !== b.infraSourceCount) return a.infraSourceCount > b.infraSourceCount;
  return entityKey(a.ref) < entityKey(b.ref);
}

// FNV-1a over the sorted member keys → a short, stable, traversal-order-independent cluster id.
function stableId(sortedKeys: string[]): string {
  let h = 0x811c9dc5;
  const s = sortedKeys.join("");
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `cluster:${h.toString(16).padStart(8, "0")}`;
}

function dominantRole(roleCounts: Record<string, number>): string {
  let best = "";
  let bestCount = -1;
  for (const role of Object.keys(roleCounts).sort()) {
    const c = roleCounts[role];
    if (c > bestCount || (c === bestCount && rolePriority(role) < rolePriority(best))) {
      best = role;
      bestCount = c;
    }
  }
  return best;
}

/**
 * Connected components of the entity↔entity edge graph. A component of size >= 2 is a cluster
 * (a singleton entity is unclustered). PURE + deterministic.
 */
export function buildClusters(store: EntityStore): Cluster[] {
  const entities = store?.entities ?? {};
  const keys = Object.keys(entities);
  if (!keys.length) return [];

  // adjacency: union ONLY co_occurs|linked edges whose other endpoint is a real entity (D6),
  // treating direction as undirected (D3).
  const adj = new Map<string, Set<string>>();
  for (const k of keys) adj.set(k, new Set());
  const conns = store.connections ?? {};
  for (const ownerKey of keys) {
    for (const c of conns[ownerKey] ?? []) {
      if (!CLUSTER_REL.has(c.relType)) continue; // skip surfaced_in (objective endpoint)
      const otherKey = entityKey(c.other);
      if (otherKey === ownerKey || !entities[otherKey]) continue; // other must be a REAL entity (D6)
      adj.get(ownerKey)!.add(otherKey);
      adj.get(otherKey)!.add(ownerKey); // undirected (D3)
    }
  }

  // BFS components (sorted seed order for determinism — the component set is order-independent
  // anyway, but a sorted scan keeps the build reproducible).
  const seen = new Set<string>();
  const clusters: Cluster[] = [];
  for (const start of [...keys].sort()) {
    if (seen.has(start)) continue;
    const comp: string[] = [];
    const queue = [start];
    seen.add(start);
    while (queue.length) {
      const k = queue.shift()!;
      comp.push(k);
      for (const n of adj.get(k)!) {
        if (!seen.has(n)) {
          seen.add(n);
          queue.push(n);
        }
      }
    }
    if (comp.length < 2) continue; // a singleton is not a cluster

    const recs = comp.map((k) => entities[k]);
    const roleCounts: Record<string, number> = {};
    let rep = recs[0];
    for (const r of recs) {
      roleCounts[r.role] = (roleCounts[r.role] ?? 0) + 1;
      if (representativeBetter(r, rep)) rep = r;
    }
    const sortedKeys = [...comp].sort();
    const members = recs
      .slice()
      .sort((a, b) => (entityKey(a.ref) < entityKey(b.ref) ? -1 : entityKey(a.ref) > entityKey(b.ref) ? 1 : 0))
      .map((r) => r.ref);
    const dom = dominantRole(roleCounts);
    const kind = ROLE_KIND[dom] ?? "cluster";
    const label = `${kind} · ${rep.label}${comp.length > 1 ? ` +${comp.length - 1}` : ""}`;
    clusters.push({ id: stableId(sortedKeys), label, kind, members, size: comp.length, roleCounts });
  }

  // clusters: size desc, then kind, label, id — a total order (D4).
  clusters.sort((a, b) =>
    b.size - a.size ||
    a.kind.localeCompare(b.kind) ||
    a.label.localeCompare(b.label) ||
    a.id.localeCompare(b.id),
  );
  return clusters;
}

/** The cluster an entity belongs to, or null. Keys by the EXACT db.ts entityKey (D5); the query is
 *  canonType-folded the same way db.ts canonRef folds it, so the lookup matches the store's refs. */
export function clusterFor(clusters: Cluster[], type: string | undefined, value: string): Cluster | null {
  const ref: EntityRef = { type: canonType(type), value: (value ?? "").trim().toLowerCase() };
  const target = entityKey(ref);
  for (const c of clusters) {
    if (c.members.some((m) => entityKey(m) === target)) return c;
  }
  return null;
}
