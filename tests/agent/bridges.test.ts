import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, bridgesFor } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";

// sf-bridges: bridgesFor is a PURE deterministic projection over the persisted analyze clusters +
// typed_relationships. A bridge spans >= 2 analyze-clusters: by membership in >1 cluster, OR by a typed
// relationship to an entity that is a member of a DIFFERENT cluster. No LLM, no fetch, no vault write.
// These tests build the record directly (bypassing putAnalysis) so they also prove read-side redaction.

const KEY = "sk-ant-BRIDGE-secret-9090";

// Four entities in two disjoint analyze-clusters:
//   cluster A (Infra)    : alpha.example.com (e_a), beta.example.com (e_b)
//   cluster B (Operators): john smith (e_j),       jane doe (e_d)
// A typed relationship john smith --deployed--> alpha.example.com TIES the operator cluster to the
// infra cluster, so BOTH john smith and alpha.example.com become bridge entities. beta.example.com and
// jane doe sit in exactly one cluster with NO cross relationship -> NOT bridges.
const A1 = { type: "domain", value: "alpha.example.com" };
const A2 = { type: "domain", value: "beta.example.com" };
const B1 = { type: "person", value: "john smith" };
const B2 = { type: "person", value: "jane doe" };

async function vaultWithBridge(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  // a single run that surfaces all four entities (so they exist in the entity store).
  await vault.put("run:Investigate the ring", {
    objective: "Investigate the ring",
    steps: [],
    promoted: [
      { entity: A1.value, entity_type: A1.type, grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: A2.value, entity_type: A2.type, grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: B1.value, entity_type: B1.type, grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: B2.value, entity_type: B2.type, grade: "A", source_count: 2, infra_source_count: 2 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  await vault.put("analysis:default", {
    ...emptyAnalysis("default"),
    clusters: [
      { name: "Infra", kind: "infrastructure_block", description: "front domains", memberKeys: [canonKey(A1.type, A1.value), canonKey(A2.type, A2.value)] },
      { name: "Operators", kind: "ring", description: "the operators", memberKeys: [canonKey(B1.type, B1.value), canonKey(B2.type, B2.value)] },
    ],
    relationships: [
      { srcKey: canonKey(B1.type, B1.value), dstKey: canonKey(A1.type, A1.value), relType: "deployed", confidence: "high", evidence: "deployed the drainer" },
    ],
    entityScores: {
      [canonKey(B1.type, B1.value)]: { threatScore: 87, degree: 3, reportCount: 1 },
      [canonKey(A1.type, A1.value)]: { threatScore: 42, degree: 2, reportCount: 1 },
    },
  });
  return vault;
}

describe("bridgesFor (sf-bridges: cross-cluster bridge entities)", () => {
  it("finds the entity spanning 2 clusters via a cross-cluster typed relationship", async () => {
    const vault = await vaultWithBridge();
    const bridges = bridgesFor(vault);
    const labels = bridges.map((b) => b.label).sort();
    // john smith (member of Operators + tied to alpha in Infra) AND alpha.example.com (member of Infra +
    // tied from john in Operators) both bridge the two clusters.
    expect(labels).toEqual(["alpha.example.com", "john smith"]);
    const john = bridges.find((b) => b.label === "john smith")!;
    expect(john.clusterCount).toBe(2);
    expect(john.clusters.map((c) => c.name).sort()).toEqual(["Infra", "Operators"]);
    expect(john.crossRelCount).toBe(1); // the one cross-cluster edge
    expect(john.threatScore).toBe(87); // carried from entityScoreFor
  });

  it("does NOT include a single-cluster entity with no cross relationship", async () => {
    const vault = await vaultWithBridge();
    const labels = bridgesFor(vault).map((b) => b.label);
    expect(labels).not.toContain("beta.example.com"); // Infra only, no cross edge
    expect(labels).not.toContain("jane doe"); // Operators only, no cross edge
  });

  it("sorts by cluster span then threat score (the original ORDER BY)", async () => {
    const vault = await vaultWithBridge();
    const bridges = bridgesFor(vault);
    // both span 2 clusters -> tie on clusterCount -> higher threatScore first (john 87 > alpha 42).
    expect(bridges.map((b) => b.label)).toEqual(["john smith", "alpha.example.com"]);
  });

  it("returns [] with fewer than 2 clusters - honest empty state (pre-Process)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, KEY);
    await vault.put("run:x", {
      objective: "x", steps: [],
      promoted: [{ entity: A1.value, entity_type: A1.type, grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    // one cluster only -> no cross-cluster structure possible.
    await vault.put("analysis:default", {
      ...emptyAnalysis("default"),
      clusters: [{ name: "Solo", kind: "ring", description: "", memberKeys: [canonKey(A1.type, A1.value)] }],
    });
    expect(bridgesFor(vault)).toEqual([]);
    // and with NO analysis record at all:
    const s2 = memoryStorage();
    await Vault.create(s2, "pw");
    const v2 = await Vault.unlock(s2, "pw");
    await setApiKey(v2, KEY);
    expect(bridgesFor(v2)).toEqual([]);
  });

  it("is READ-ONLY: it issues no vault write", async () => {
    const vault = await vaultWithBridge();
    const putSpy = vi.spyOn(vault, "put");
    bridgesFor(vault);
    expect(putSpy).not.toHaveBeenCalled();
  });

  it("never surfaces the live key (a forged cluster name / evidence is redacted on read)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, KEY);
    await vault.put("run:r", {
      objective: "r", steps: [],
      promoted: [
        { entity: A1.value, entity_type: A1.type, grade: "A", source_count: 2, infra_source_count: 2 },
        { entity: B1.value, entity_type: B1.type, grade: "A", source_count: 2, infra_source_count: 2 },
      ],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    await vault.put("analysis:default", {
      ...emptyAnalysis("default"),
      clusters: [
        { name: `leaked-${KEY}-infra`, kind: "ring", description: "", memberKeys: [canonKey(A1.type, A1.value)] },
        { name: "Operators", kind: "ring", description: "", memberKeys: [canonKey(B1.type, B1.value)] },
      ],
      relationships: [
        { srcKey: canonKey(B1.type, B1.value), dstKey: canonKey(A1.type, A1.value), relType: "deployed", confidence: "high", evidence: `secret ${KEY} here` },
      ],
    });
    const json = JSON.stringify(bridgesFor(vault));
    expect(json).not.toContain(KEY); // the raw key never reaches /bridges
  });
});
