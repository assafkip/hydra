// metrics (INC-4a, parity port of investigations/graph_metrics.py:75-142): degree_centrality (normalized
// by n-1, NetworkX-faithful — codex P3) + betweenness + eigenvector centrality + Louvain community over
// the typed_relationships adjacency. Deterministic, no LLM. Uses the BUNDLED, pure-JS graphology stack
// (zero-CDN; tests/deps.test.ts asserts the imports). Degenerate (<2 nodes / 0 edges) → empty (parity:
// graph_metrics.py writes nothing for a graph too small to have structure).

import Graph from "graphology";
import betweennessCentrality from "graphology-metrics/centrality/betweenness";
import eigenvectorCentrality from "graphology-metrics/centrality/eigenvector";
import louvain from "graphology-communities-louvain";

// graph_metrics.py caps NetworkX betweenness at k=min(n,500),seed=42 (a sampled approximation for big
// graphs — exact betweenness is O(n·m) and would freeze the tab). graphology has no k-sampler, so we
// compute EXACT betweenness at/under the cap (identical to Python's k=n exact there) and skip it above
// the cap (codex S3 — the perf cliff the Python guard exists to avoid).
const MAX_BETWEENNESS_NODES = 500;

// A deterministic seeded PRNG (mulberry32) so Louvain gives STABLE communities across re-Process runs —
// graph_metrics.py uses best_partition(random_state=42); graphology's default rng is Math.random, which
// would reshuffle community ids every run (codex S1). Seeded with 42 to mirror the original.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface MetricEdge {
  src: string; // canonKey
  dst: string; // canonKey
}

// graph_metrics.py _EDGE_CONF: a typed relationship's weight = its confidence label. Used by the
// path_confidence widest-bottleneck relaxation below.
const EDGE_CONF: Record<string, number> = { high: 0.85, medium: 0.6, low: 0.35 };

export interface PathConfEdge {
  src: string; // canonKey
  dst: string; // canonKey
  confidence: string; // high | medium | low (defaults to medium=0.6 on anything else)
}

/**
 * Per-node path_confidence — port of graph_metrics.py:153 compute_path_confidence (PRD-B graph-path-confidence;
 * RCA discipline-evaporation: this attribution-chain grader was dropped entirely on port). A node's score is
 * the strongest path back to a case SEED, where a path is only as strong as its WEAKEST edge (widest
 * bottleneck): a node whose only route to a seed crosses a 0.6 bridge scores 0.6 even if its own edges are
 * 0.85 — so a strong sub-chain hanging off one weak link is NOT graphed as if the whole branch were strong.
 *
 * Method: a max-min relaxation (Dijkstra maximizing the minimum edge along the path). Seeds anchor at 1.0;
 * edges are UNDIRECTED (a bridge is a bridge either way) and weighted by EDGE_CONF[confidence].
 * Degenerate cases (defined, not crashed): a node unreachable from any seed is left UNSCORED (absent from
 * the map) — never 0-faked, so 'no path to a seed' stays distinct from 'a weak path'; no seeds present in
 * the node set -> empty map; self-loops and edges to unknown nodes are skipped.
 */
export function computePathConfidence(nodes: string[], edges: PathConfEdge[], seeds: string[]): Map<string, number> {
  const nodeSet = new Set(nodes);
  const seedSet = new Set(seeds.filter((s) => nodeSet.has(s)));
  const pathConfidence = new Map<string, number>();
  if (seedSet.size === 0) return pathConfidence; // no anchored seed -> nothing to score (parity skip)

  // undirected weighted adjacency over edges whose BOTH endpoints are case nodes (self-loops skipped).
  const adj = new Map<string, Array<{ to: string; w: number }>>();
  const link = (a: string, b: string, w: number): void => {
    const list = adj.get(a) ?? [];
    list.push({ to: b, w });
    adj.set(a, list);
  };
  for (const e of edges) {
    if (e.src === e.dst || !nodeSet.has(e.src) || !nodeSet.has(e.dst)) continue;
    const w = EDGE_CONF[(e.confidence || "medium").toLowerCase()] ?? 0.6;
    link(e.src, e.dst, w);
    link(e.dst, e.src, w);
  }

  // max-min relaxation: best[n] = strongest bottleneck from any seed to n. Settle the highest-confidence
  // unsettled node each round (Dijkstra's property holds for max-min) — case subgraphs are small, so the
  // O(V^2) max-scan is fine and avoids a heap dependency.
  const best = new Map<string, number>();
  for (const s of seedSet) best.set(s, 1.0);
  const settled = new Set<string>();
  while (settled.size < best.size) {
    let node: string | null = null;
    let conf = -1;
    for (const [n, c] of best) {
      if (!settled.has(n) && c > conf) {
        conf = c;
        node = n;
      }
    }
    if (node === null) break;
    settled.add(node);
    for (const { to, w } of adj.get(node) ?? []) {
      const cand = Math.min(conf, w);
      if (cand > (best.get(to) ?? 0)) best.set(to, cand);
    }
  }
  for (const [n, c] of best) pathConfidence.set(n, Math.round(c * 10000) / 10000); // == Python round(conf, 4)
  return pathConfidence;
}
export interface NodeMetrics {
  degreeCentrality: number;
  betweenness: number;
  eigenvector: number;
  community: number;
}

/** Per-node graph metrics (canonKey → NodeMetrics). `nodes` are the case entities; `edges` are the
 *  active typed_relationships among them. Isolated nodes are kept (degree_centrality 0). Self-loops and
 *  edges to unknown nodes are skipped. <2 nodes or 0 (real) edges → empty Map (parity degenerate gate). */
export function computeGraphMetrics(nodes: string[], edges: MetricEdge[]): Map<string, NodeMetrics> {
  const nodeSet = new Set(nodes);
  const realEdges = edges.filter((e) => e.src !== e.dst && nodeSet.has(e.src) && nodeSet.has(e.dst));
  if (nodeSet.size < 2 || realEdges.length === 0) return new Map();

  const g = new Graph({ type: "undirected" });
  for (const n of nodeSet) g.addNode(n);
  for (const e of realEdges) g.mergeEdge(e.src, e.dst); // idempotent — dup rows collapse to one edge

  const n = g.order;
  // exact betweenness only at/under the cap (== Python's k=n); above it, skip (no graphology sampler).
  const betweenness: Record<string, number> = n <= MAX_BETWEENNESS_NODES ? betweennessCentrality(g) : {};
  // eigenvector can fail to converge on a disconnected graph (Python silently skips) — degrade to 0.
  // maxIterations pinned to 500 (graph_metrics.py:110 nx.eigenvector_centrality(g, max_iter=500)) — the
  // library default is too low to converge on real case graphs, which would throw and drop the metric
  // entirely (PRD-B metrics-eigenvector-maxiter; RCA discipline-evaporation: the port dropped the cap).
  let eigenvector: Record<string, number> = {};
  try {
    eigenvector = eigenvectorCentrality(g, { maxIterations: 500 });
  } catch {
    eigenvector = {};
  }
  const community = louvain(g, { rng: mulberry32(42), randomWalk: false }); // deterministic communities

  const out = new Map<string, NodeMetrics>();
  g.forEachNode((node) => {
    out.set(node, {
      degreeCentrality: g.degree(node) / (n - 1), // NetworkX degree_centrality
      betweenness: betweenness[node] ?? 0,
      eigenvector: eigenvector[node] ?? 0,
      community: community[node] ?? 0,
    });
  });
  return out;
}
