import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, entityDbFor, ANTHROPIC_KEY } from "../../src/agent/session.js";
import { getEntity } from "../../src/entity/db.js";
import type { GraphModel } from "../../src/graph/model.js";

// ed-session (codex D2 + single-writer): entityDbFor is a READ-ONLY projection over
// run: records (+ the current model). It folds only run: records, drops
// secret:/brief:/pivot:/tainted, UNCONDITIONALLY redacts the live key out of EVERY
// input (even an unredacted model passed by a careless caller), and issues NO vault write.

const LEAK_KEY = "sk-ant-LEAKVALUE0001";

async function vaultWithKey(key = LEAK_KEY): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

const RUN_A = {
  objective: "Investigate acme.io",
  steps: [],
  promoted: [
    { entity: "1.2.3.4", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
    { entity: "acme.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
  ],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("entityDbFor — folds run: records, accumulates", () => {
  it("builds entities + connections from run: records", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A);
    const store = entityDbFor(vault);
    const ip = getEntity(store, "ip", "1.2.3.4")!;
    expect(ip).toBeTruthy();
    expect(ip.runs).toEqual(["Investigate acme.io"]);
    expect(getEntity(store, "domain", "acme.io")).toBeTruthy();
  });

  it("EXCLUDES brief:/pivot:/secret: records — only run: feeds the db", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A);
    await vault.put("brief:Investigate acme.io", { objective: "x", brief: "# brief\nbrief.example.com" });
    await vault.put("pivot:pivot.example.com", [{ provider: "dns", tier: "T1", entities: [{ type: "domain", value: "pivot.example.com" }] }]);
    const store = entityDbFor(vault);
    // brief/pivot entities never enter the db
    expect(getEntity(store, "domain", "brief.example.com")).toBeNull();
    expect(getEntity(store, "domain", "pivot.example.com")).toBeNull();
    // the secret namespace is never read as an entity
    expect(getEntity(store, "domain", ANTHROPIC_KEY)).toBeNull();
  });

  it("DROPS a run whose objective contains the live key (tainted -> excluded)", async () => {
    const vault = await vaultWithKey();
    await vault.put(`run:leaky ${LEAK_KEY}`, {
      ...RUN_A,
      objective: `leaky ${LEAK_KEY}`,
      promoted: [{ entity: "tainted.example.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
    });
    const store = entityDbFor(vault);
    // the whole tainted run is dropped (objectivesUnder contract), so its entity never lands
    expect(getEntity(store, "domain", "tainted.example.com")).toBeNull();
    expect(JSON.stringify(store)).not.toContain(LEAK_KEY);
  });
});

describe("entityDbFor — key redaction (codex D2) + read-only (single-writer)", () => {
  it("redacts the live key from the store EVEN when an UNREDACTED model carrying it is passed", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A);
    // A careless caller hands an UNREDACTED model whose objective + a node label carry the key.
    const dirtyModel: GraphModel = {
      objective: `dig ${LEAK_KEY}`,
      nodes: [
        { id: "objective", label: `dig ${LEAK_KEY}`, kind: "objective", promoted: false },
        { id: "finding:0:domain:exp.example.com", label: "exp.example.com", kind: "finding", promoted: true, entityType: "domain", grade: "A", sourceCount: 2, infraSourceCount: 2 },
        { id: "finding:1:ip:9.9.9.9", label: `9.9.9.9 ${LEAK_KEY}`, kind: "finding", promoted: true, entityType: "ip", grade: "A", sourceCount: 2, infraSourceCount: 2 },
      ],
      edges: [
        { from: "objective", to: "finding:0:domain:exp.example.com", kind: "promoted" },
        { from: "objective", to: "finding:1:ip:9.9.9.9", kind: "promoted" },
      ],
    };
    const store = entityDbFor(vault, dirtyModel);
    // entityDbFor self-redacts: the key appears NOWHERE in the store.
    expect(JSON.stringify(store)).not.toContain(LEAK_KEY);
    // the model's expansion entity still landed (folded, just redacted)
    expect(getEntity(store, "domain", "exp.example.com")).toBeTruthy();
  });

  it("makes NO vault write — read-only (single-writer chokepoint untouched)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN_A);
    let puts = 0;
    const origPut = vault.put.bind(vault);
    vault.put = (async (k: string, v: unknown) => {
      puts++;
      return origPut(k, v);
    }) as typeof vault.put;
    entityDbFor(vault);
    expect(puts).toBe(0);
  });
});
