import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  graphModelForCase,
  entityDbFor,
  excludeEntity,
  restoreEntity,
  excludedKeys,
} from "../../src/agent/session.js";

// analyst node-removal (founder 2026-06-25): a REVERSIBLE exclude. Removing a node drops it (and edges
// touching it) from BOTH projections — the graph (finalizeModel) AND /entities (entityDbFor) — and an
// Undo restores it. Data is never destroyed (tombstone, the no-delete vault). These tests drive the public
// session API (no internals), proving the canonKey match holds across both chokepoints.

const KEY = "sk-ant-" + "AbCdEfGhIjKlMnOp012345";

async function vaultWithKey(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  return vault;
}

const RUN = {
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

const graphLabels = (v: Vault): string[] =>
  (graphModelForCase(v)?.nodes ?? []).filter((n) => n.kind !== "objective").map((n) => n.label);
const dbLabels = (v: Vault): string[] => Object.values(entityDbFor(v).entities).map((e) => e.label);

describe("analyst node-removal — reversible exclude across both projections", () => {
  it("exclude drops the node from the graph AND /entities; the other node stays", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    expect(graphLabels(vault)).toContain("acme.io");
    expect(dbLabels(vault)).toContain("acme.io");

    await excludeEntity(vault, "domain", "acme.io");

    expect(graphLabels(vault)).not.toContain("acme.io"); // gone from the graph
    expect(dbLabels(vault)).not.toContain("acme.io"); // gone from /entities
    expect(graphLabels(vault)).toContain("1.2.3.4"); // the sibling node is untouched
    expect(dbLabels(vault)).toContain("1.2.3.4");
  });

  it("Undo (restore) brings the excluded node back to both projections", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    const key = await excludeEntity(vault, "domain", "acme.io");
    expect(dbLabels(vault)).not.toContain("acme.io");

    await restoreEntity(vault, key);

    expect(graphLabels(vault)).toContain("acme.io"); // restored on the graph
    expect(dbLabels(vault)).toContain("acme.io"); // restored in /entities
    expect(excludedKeys(vault).size).toBe(0); // tombstone clears the active exclusion
  });

  it("matches case-insensitively (canonKey lowercases the value)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    await excludeEntity(vault, "domain", "ACME.IO"); // analyst-typed casing differs from the stored value
    expect(dbLabels(vault)).not.toContain("acme.io");
  });

  it("refuses to exclude a secret-tainted entity", async () => {
    const vault = await vaultWithKey();
    await expect(excludeEntity(vault, "domain", `evil-${KEY}.com`)).rejects.toThrow();
  });
});
