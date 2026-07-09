import { describe, it, expect } from "vitest";
import { computeGraphMetrics, computePathConfidence } from "../../src/entity/metrics.js";

// PRD-B graph-path-confidence: the widest-bottleneck attribution-chain grader (port of
// graph_metrics.py compute_path_confidence). Each assertion carries its negative proof.
describe("computePathConfidence (PRD-B, port of graph_metrics.py)", () => {
  it("seed anchors at 1.0; a node behind a weak bridge scores the BOTTLENECK, not its own edge", () => {
    // SEED --high(0.85)--> B --low(0.35)--> C : C's only path crosses the 0.35 bridge.
    const pc = computePathConfidence(
      ["SEED", "B", "C"],
      [
        { src: "SEED", dst: "B", confidence: "high" },
        { src: "B", dst: "C", confidence: "low" },
      ],
      ["SEED"],
    );
    expect(pc.get("SEED")).toBe(1.0);
    expect(pc.get("B")).toBeCloseTo(0.85, 6); // strong edge from the seed
    // NEGATIVE proof: C is NOT 0.85 (its own inbound edge) — it is throttled to the 0.35 bottleneck.
    expect(pc.get("C")).toBeCloseTo(0.35, 6);
  });

  it("a node unreachable from any seed is UNSCORED (absent), never 0-faked", () => {
    const pc = computePathConfidence(
      ["SEED", "A", "ISLAND"],
      [{ src: "SEED", dst: "A", confidence: "high" }],
      ["SEED"],
    );
    expect(pc.has("A")).toBe(true);
    expect(pc.has("ISLAND")).toBe(false); // negative: no path → no row (distinct from a weak path)
  });

  it("degenerate: no seed in the node set → empty map", () => {
    const pc = computePathConfidence(["A", "B"], [{ src: "A", dst: "B", confidence: "high" }], ["NOT_A_NODE"]);
    expect(pc.size).toBe(0);
  });

  it("takes the STRONGER of two paths to a node (max over min-bottlenecks)", () => {
    // C reachable via SEED-low-C (0.35) OR SEED-high-B-high-C (0.85) → the stronger path wins.
    const pc = computePathConfidence(
      ["SEED", "B", "C"],
      [
        { src: "SEED", dst: "C", confidence: "low" },
        { src: "SEED", dst: "B", confidence: "high" },
        { src: "B", dst: "C", confidence: "high" },
      ],
      ["SEED"],
    );
    expect(pc.get("C")).toBeCloseTo(0.85, 6);
  });
});

// metrics (INC-4a, codex P3): pins degree_centrality (normalized by n-1) on a 3-node path A—B—C —
// endpoints 0.5, middle 1.0 — plus betweenness/eigenvector/community + the degenerate gate.

describe("computeGraphMetrics (INC-4a)", () => {
  const m = computeGraphMetrics(["A", "B", "C"], [{ src: "A", dst: "B" }, { src: "B", dst: "C" }]);

  it("degree_centrality is normalized by n-1 (path: ends 0.5, middle 1.0)", () => {
    expect(m.get("A")!.degreeCentrality).toBeCloseTo(0.5, 6);
    expect(m.get("B")!.degreeCentrality).toBeCloseTo(1.0, 6);
    expect(m.get("C")!.degreeCentrality).toBeCloseTo(0.5, 6);
  });

  it("betweenness: middle node brokers (1.0), endpoints 0", () => {
    expect(m.get("B")!.betweenness).toBeCloseTo(1.0, 6);
    expect(m.get("A")!.betweenness).toBeCloseTo(0, 6);
    expect(m.get("C")!.betweenness).toBeCloseTo(0, 6);
  });

  it("eigenvector: the central node ranks highest", () => {
    expect(m.get("B")!.eigenvector).toBeGreaterThan(m.get("A")!.eigenvector);
  });

  it("a connected path is one Louvain community", () => {
    expect(m.get("A")!.community).toBe(m.get("B")!.community);
    expect(m.get("B")!.community).toBe(m.get("C")!.community);
  });

  it("degenerate: empty graph → empty map (parity gate)", () => {
    expect(computeGraphMetrics([], []).size).toBe(0);
  });

  it("degenerate: nodes but 0 real edges → empty map", () => {
    expect(computeGraphMetrics(["A", "B"], []).size).toBe(0);
    // a self-loop is not a real edge
    expect(computeGraphMetrics(["A", "B"], [{ src: "A", dst: "A" }]).size).toBe(0);
  });

  it("communities are DETERMINISTIC across runs (seeded Louvain — codex S1)", () => {
    const nodes = ["A", "B", "C", "X", "Y", "Z"];
    const edges = [
      { src: "A", dst: "B" }, { src: "B", dst: "C" }, { src: "C", dst: "A" },
      { src: "X", dst: "Y" }, { src: "Y", dst: "Z" }, { src: "Z", dst: "X" },
    ];
    const a = computeGraphMetrics(nodes, edges);
    const b = computeGraphMetrics(nodes, edges);
    // identical community ids every run (graphology default rng=Math.random would reshuffle them)
    for (const k of nodes) expect(a.get(k)!.community).toBe(b.get(k)!.community);
  });

  it("betweenness is bounded: a >500-node graph skips exact betweenness but keeps the other metrics (codex S3)", () => {
    // a star: 1 hub + 600 leaves = 601 nodes > the cap → betweenness 0; degree_centrality still exact.
    const nodes = ["hub", ...Array.from({ length: 600 }, (_, i) => `n${i}`)];
    const edges = nodes.slice(1).map((n) => ({ src: "hub", dst: n }));
    const m = computeGraphMetrics(nodes, edges);
    expect(m.get("hub")!.betweenness).toBe(0); // skipped above the cap (no freeze)
    expect(m.get("hub")!.degreeCentrality).toBeCloseTo(1, 6); // 600/(601-1) = 1.0 — still computed
    expect(typeof m.get("hub")!.community).toBe("number"); // community still computed
  });

  it("two separate communities are detected", () => {
    // two disjoint triangles → 2 communities
    const t = computeGraphMetrics(
      ["A", "B", "C", "X", "Y", "Z"],
      [
        { src: "A", dst: "B" }, { src: "B", dst: "C" }, { src: "C", dst: "A" },
        { src: "X", dst: "Y" }, { src: "Y", dst: "Z" }, { src: "Z", dst: "X" },
      ],
    );
    expect(t.get("A")!.community).toBe(t.get("C")!.community);
    expect(t.get("A")!.community).not.toBe(t.get("X")!.community);
  });
});
