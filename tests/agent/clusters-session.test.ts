import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, clustersFor } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";

// cl-session (INC-3): clustersFor now reads the REAL analyze-pass clusters persisted in the
// analysis record (NOT the buildClusters co-occurrence approximation the founder rejected). It is
// read-only, resolves memberKeys → refs + per-member roleCounts from the key-redacted store, and the
// live key (echoed into a cluster name on a forged/imported record) is redacted on READ too (D8).

const KEY = "sk-ant-CLUSTER-secret-7777";

/** A vault with two run entities + a RAW analysis record (written directly, bypassing putAnalysis's
 *  write-redaction) holding ONE cluster over those entities. The raw write lets us prove clustersFor's
 *  OWN read-redaction (defense in depth), not just the write path. */
async function vaultWithClusters(clusterName: string): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  await vault.put("run:Investigate ring.example.com", {
    objective: "Investigate ring.example.com",
    steps: [],
    promoted: [
      { entity: "1.1.1.1", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "host.example", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  await vault.put("analysis:default", {
    ...emptyAnalysis("default"),
    clusters: [
      {
        name: clusterName,
        kind: "ring",
        description: "the ring",
        memberKeys: [canonKey("ip", "1.1.1.1"), canonKey("domain", "host.example")],
      },
    ],
  });
  return vault;
}

describe("clustersFor (INC-3: reads the analyze pass's real record clusters)", () => {
  it("yields the analysis record's clusters with resolved members + roleCounts", async () => {
    const vault = await vaultWithClusters("Ring A");
    const clusters = clustersFor(vault);
    expect(clusters).toHaveLength(1);
    expect(clusters[0].label).toBe("Ring A");
    expect(clusters[0].size).toBe(2); // both members resolved from the store
    expect(clusters[0].roleCounts.infra).toBe(2); // ip + domain both derive role 'infra'
  });

  it("SKIPS a memberKey absent from the current entity store (codex: members come from the store, never the raw key)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, KEY);
    await vault.put("run:r", {
      objective: "r", steps: [],
      promoted: [{ entity: "1.1.1.1", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    // A forged record: one REAL member + one canonical key whose value embeds the secret + is NOT in
    // the store. The phantom must be dropped (so the raw secret never reaches /clusters) and size = 1.
    await vault.put("analysis:default", {
      ...emptyAnalysis("default"),
      clusters: [
        {
          name: "Mixed",
          kind: "ring",
          description: "",
          memberKeys: [canonKey("ip", "1.1.1.1"), canonKey("domain", `evil-${KEY}.example`)],
        },
      ],
    });
    const clusters = clustersFor(vault);
    expect(clusters[0].size).toBe(1); // phantom (not in store) skipped
    expect(JSON.stringify(clusters)).not.toContain(KEY); // its raw value never surfaces
  });

  it("returns [] with NO analysis record — honest empty (no buildClusters approximation until Process)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, KEY);
    await vault.put("run:x", {
      objective: "x", steps: [],
      promoted: [{ entity: "a.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    expect(clustersFor(vault)).toEqual([]); // co-occurring entities but no analyze record → no clusters
  });

  it("the live key (echoed in a cluster NAME) is REDACTED on read, never raw (D8 defense-in-depth)", async () => {
    const vault = await vaultWithClusters(`leaked-${KEY}-ring`);
    const json = JSON.stringify(clustersFor(vault));
    expect(json).not.toContain(KEY);
    expect(json.toLowerCase()).toContain("[redacted]"); // redactForms → [REDACTED]
  });

  it("is READ-ONLY: it issues no vault write", async () => {
    const vault = await vaultWithClusters("Ring A");
    const putSpy = vi.spyOn(vault, "put");
    clustersFor(vault);
    expect(putSpy).not.toHaveBeenCalled();
  });
});
