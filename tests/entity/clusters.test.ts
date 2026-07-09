import { describe, it, expect } from "vitest";
import { buildClusters, clusterFor } from "../../src/entity/clusters.js";
import { buildEntityDb, type IngestRun } from "../../src/entity/db.js";

// cl-build: clusters are UNDIRECTED connected components over the entity DB's co_occurs|linked
// edges. surfaced_in (objective endpoint) never merges entities (D6); identity + ordering are
// deterministic (D4/D5); a directed linked edge clusters both endpoints (D3).

// promoted entities co-occur within a run (the entity DB derives co_occurs for every pair).
function run(objective: string, entities: { value: string; type: string; promoted?: boolean }[], links: IngestRun["links"] = []): IngestRun {
  return {
    objective,
    entities: entities.map((e) => ({ value: e.value, type: e.type, promoted: e.promoted !== false, grade: "A", sourceCount: 2, infraSourceCount: 2 })),
    links,
  };
}

describe("buildClusters", () => {
  it("two co-occurring entities form one size-2 cluster", () => {
    const store = buildEntityDb([run("r1", [{ value: "a.com", type: "domain" }, { value: "1.1.1.1", type: "ip" }])]);
    const clusters = buildClusters(store);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].size).toBe(2);
  });

  it("three mutually co-occurring entities form ONE size-3 cluster (not three)", () => {
    const store = buildEntityDb([run("r1", [
      { value: "a.com", type: "domain" }, { value: "b.com", type: "domain" }, { value: "1.1.1.1", type: "ip" },
    ])]);
    const clusters = buildClusters(store);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].size).toBe(3);
  });

  it("two disjoint co-occurring pairs form TWO clusters", () => {
    const store = buildEntityDb([
      run("r1", [{ value: "a.com", type: "domain" }, { value: "1.1.1.1", type: "ip" }]),
      run("r2", [{ value: "x.com", type: "domain" }, { value: "2.2.2.2", type: "ip" }]),
    ]);
    expect(buildClusters(store)).toHaveLength(2);
  });

  it("a singleton (only a surfaced_in edge to the objective) is NOT clustered; the objective never appears (D6)", () => {
    const store = buildEntityDb([run("solo objective", [{ value: "lonely.com", type: "domain" }])]);
    const clusters = buildClusters(store);
    expect(clusters).toHaveLength(0); // one entity, only surfaced_in -> no cluster
    expect(JSON.stringify(clusters)).not.toContain("objective");
    expect(JSON.stringify(clusters)).not.toContain("solo objective");
  });

  it("a single directed A->B linked edge clusters BOTH endpoints (undirected — D3)", () => {
    const store = buildEntityDb([{
      objective: "r1",
      entities: [
        { value: "a.com", type: "domain", promoted: true, grade: "A", sourceCount: 2, infraSourceCount: 2 },
        { value: "b.com", type: "domain", promoted: true, grade: "A", sourceCount: 2, infraSourceCount: 2 },
      ],
      links: [{ fromValue: "a.com", fromType: "domain", toValue: "b.com", toType: "domain", promoted: true }],
    }]);
    const clusters = buildClusters(store);
    expect(clusters).toHaveLength(1);
    const cA = clusterFor(clusters, "domain", "a.com");
    const cB = clusterFor(clusters, "domain", "b.com");
    expect(cA).not.toBeNull();
    expect(cA!.id).toBe(cB!.id); // same cluster for both endpoints
  });

  it("the cluster id + ordering are DETERMINISTIC across different insertion orders (D4)", () => {
    const ents = [{ value: "a.com", type: "domain" }, { value: "b.com", type: "domain" }, { value: "1.1.1.1", type: "ip" }];
    const c1 = buildClusters(buildEntityDb([run("r1", ents)]));
    const c2 = buildClusters(buildEntityDb([run("r1", [...ents].reverse())]));
    expect(JSON.stringify(c1)).toBe(JSON.stringify(c2));
  });

  it("equal-score ties resolve to a single stable representative/order (D4)", () => {
    // two identical-grade promoted infra entities — the rep + member order come from the key tiebreaker
    const c1 = buildClusters(buildEntityDb([run("r1", [{ value: "zzz.com", type: "domain" }, { value: "aaa.com", type: "domain" }])]));
    const c2 = buildClusters(buildEntityDb([run("r1", [{ value: "aaa.com", type: "domain" }, { value: "zzz.com", type: "domain" }])]));
    expect(JSON.stringify(c1)).toBe(JSON.stringify(c2));
  });

  it("a hostile-delimiter member pair stays distinct (D5)", () => {
    const store = buildEntityDb([run("r1", [{ value: "b|c", type: "a" }, { value: "c", type: "a|b" }, { value: "real.com", type: "domain" }])]);
    const clusters = buildClusters(store);
    // all three co-occur -> one cluster of 3 distinct members (the two hostile-delimiter ones did not collide)
    expect(clusters[0].size).toBe(3);
  });

  it("label/kind reflect the dominant role", () => {
    const store = buildEntityDb([run("r1", [{ value: "1.1.1.1", type: "ip" }, { value: "2.2.2.2", type: "ip" }])]);
    const c = buildClusters(store)[0];
    expect(c.kind).toBe("infrastructure block"); // ip -> infra role
    expect(c.label).toContain("infrastructure block");
  });

  it("clusterFor resolves a member and returns null for a non-member; empty store yields []", () => {
    const store = buildEntityDb([run("r1", [{ value: "a.com", type: "domain" }, { value: "1.1.1.1", type: "ip" }])]);
    const clusters = buildClusters(store);
    expect(clusterFor(clusters, "domain", "a.com")).not.toBeNull();
    expect(clusterFor(clusters, "domain", "not-here.com")).toBeNull();
    expect(buildClusters(buildEntityDb([]))).toEqual([]);
  });
});
