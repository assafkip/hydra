// scoring (INC-4a, parity port of investigations/analyze.py compute_threat_scores:432-523): the threat
// score per entity, PURE + injectable so it unit-tests without a vault/DB.
//   base  = role_weight*10 + report_count*5 + degree*1
//   prior = seed_weight*30
//   prop  = depth-2 BFS from each seed: seed_weight*10 at depth-1, seed_weight*4 at depth-2
// over the typed_relationships adjacency (undirected; degree counts edge ROWS per endpoint, like the
// Python query). Seeds = promoted findings @ weight 1.0 (codex P2 — Python's seeds table default).

// Generic role defaults (analyze.py ROLE_WEIGHTS); the caller overlays approved-schema role weights
// (max wins) to build the merged map it passes in, mirroring _merged_role_weights.
export const DEFAULT_ROLE_WEIGHTS: Record<string, number> = {
  operator: 5,
  channel: 3,
  ioc: 4,
  infra: 1,
  source: 0,
  noise: 0,
};

export interface ScoringEntity {
  key: string; // canonKey
  role: string; // role name (matched against roleWeights; 0 if absent)
  reportCount: number; // distinct reports mentioning the entity
}
export interface ScoringEdge {
  src: string; // canonKey
  dst: string; // canonKey
}
export interface EntityScore {
  threatScore: number;
  degree: number;
  reportCount: number;
}

function bump(m: Map<string, number>, k: string, by: number): void {
  m.set(k, (m.get(k) ?? 0) + by);
}

/** Threat score per entity (canonKey → EntityScore). An entity with role_w=seed_w=prop=degree all 0 is
 *  skipped (parity with the Python skip-gate — keeps the score table to entities that actually score). */
export function computeThreatScores(
  entities: ScoringEntity[],
  edges: ScoringEdge[],
  seedWeights: Map<string, number>,
  roleWeights: Record<string, number> = DEFAULT_ROLE_WEIGHTS,
): Map<string, EntityScore> {
  // adjacency (undirected, a Set) + degree (edge ROWS per endpoint) — exactly the Python construction.
  const adj = new Map<string, Set<string>>();
  const degree = new Map<string, number>();
  for (const { src, dst } of edges) {
    if (!adj.has(src)) adj.set(src, new Set());
    if (!adj.has(dst)) adj.set(dst, new Set());
    adj.get(src)!.add(dst);
    adj.get(dst)!.add(src);
    bump(degree, src, 1);
    if (dst !== src) bump(degree, dst, 1); // a self-loop counts its endpoint once (Python `if d != s`)
  }

  // depth-2 BFS propagation from each seed
  const propagated = new Map<string, number>();
  for (const [seed, w] of seedWeights) {
    const seedAdj = adj.get(seed) ?? new Set<string>();
    for (const n1 of seedAdj) {
      if (n1 === seed) continue;
      bump(propagated, n1, w * 10); // depth 1
    }
    for (const n1 of seedAdj) {
      for (const n2 of adj.get(n1) ?? new Set<string>()) {
        if (n2 === seed || seedAdj.has(n2)) continue; // not the seed, not already a depth-1 neighbor
        bump(propagated, n2, w * 4); // depth 2
      }
    }
  }

  const out = new Map<string, EntityScore>();
  for (const e of entities) {
    const roleW = roleWeights[e.role] ?? 0;
    const seedW = seedWeights.get(e.key) ?? 0;
    const prop = propagated.get(e.key) ?? 0;
    const deg = degree.get(e.key) ?? 0;
    if (roleW === 0 && seedW === 0 && prop === 0 && deg === 0) continue; // skip-gate (parity)
    const base = roleW * 10 + e.reportCount * 5 + deg * 1;
    const prior = seedW * 30;
    out.set(e.key, { threatScore: base + prior + prop, degree: deg, reportCount: e.reportCount });
  }
  return out;
}

/** Merge generic role defaults with per-case schema role weights (max wins) — mirrors
 *  _merged_role_weights. Pure helper the session layer uses to build the roleWeights map. */
export function mergeRoleWeights(schemaRoleWeights?: Record<string, number> | null): Record<string, number> {
  const merged: Record<string, number> = { ...DEFAULT_ROLE_WEIGHTS };
  for (const [role, w] of Object.entries(schemaRoleWeights ?? {})) {
    merged[role] = Math.max(merged[role] ?? 0, w);
  }
  return merged;
}
