import { describe, it, expect } from "vitest";
import { computeThreatScores, mergeRoleWeights, DEFAULT_ROLE_WEIGHTS, type ScoringEntity, type ScoringEdge } from "../../src/entity/scoring.js";

// scoring (INC-4a, codex P2): pins compute_threat_scores on a known fixture, incl. seed_w=1.0 → prior=30
// and the depth-2 BFS propagation (seed*10 at depth-1, seed*4 at depth-2). Path A—B—C—D, seed = A.

const EDGES: ScoringEdge[] = [
  { src: "A", dst: "B" },
  { src: "B", dst: "C" },
  { src: "C", dst: "D" },
];
const ENTITIES: ScoringEntity[] = [
  { key: "A", role: "operator", reportCount: 2 }, // w=5
  { key: "B", role: "channel", reportCount: 0 }, // w=3
  { key: "C", role: "infra", reportCount: 1 }, // w=1
  { key: "D", role: "noise", reportCount: 0 }, // w=0 — kept only by degree
  { key: "E", role: "noise", reportCount: 0 }, // w=0, no edges, not seed → SKIPPED
];

describe("computeThreatScores (INC-4a)", () => {
  const scores = computeThreatScores(ENTITIES, EDGES, new Map([["A", 1.0]]));

  it("seed scores itself: base + prior (seed_w 1.0 → 30)", () => {
    // A: base = 5*10 + 2*5 + degree(1) = 61; prior = 1.0*30 = 30; prop = 0 → 91
    expect(scores.get("A")).toEqual({ threatScore: 91, degree: 1, reportCount: 2 });
  });

  it("depth-1 neighbor gets seed*10 propagation", () => {
    // B: base = 3*10 + 0 + degree(2) = 32; prior 0; prop = 1.0*10 = 10 → 42
    expect(scores.get("B")).toEqual({ threatScore: 42, degree: 2, reportCount: 0 });
  });

  it("depth-2 neighbor gets seed*4 propagation (not double-counted as depth-1)", () => {
    // C: base = 1*10 + 1*5 + degree(2) = 17; prior 0; prop = 1.0*4 = 4 → 21
    expect(scores.get("C")).toEqual({ threatScore: 21, degree: 2, reportCount: 1 });
  });

  it("a connected zero-role node is kept by degree, not skipped", () => {
    // D: base = 0 + 0 + degree(1) = 1; prior/prop 0 → 1 (degree keeps it in)
    expect(scores.get("D")).toEqual({ threatScore: 1, degree: 1, reportCount: 0 });
  });

  it("a disconnected zero-everything node is skipped (parity skip-gate)", () => {
    expect(scores.has("E")).toBe(false);
  });

  it("empty graph yields no scores", () => {
    expect(computeThreatScores([], [], new Map()).size).toBe(0);
  });

  it("mergeRoleWeights overlays schema weights (max wins)", () => {
    const merged = mergeRoleWeights({ promoter: 6, infra: 9 });
    expect(merged.promoter).toBe(6); // new per-case role
    expect(merged.infra).toBe(9); // schema raises the generic default (1 -> 9)
    expect(merged.operator).toBe(DEFAULT_ROLE_WEIGHTS.operator); // untouched default
  });
});
