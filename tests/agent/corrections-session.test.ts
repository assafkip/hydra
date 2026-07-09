import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { canonKey } from "../../src/entity/db.js";
import {
  SessionError,
  setApiKey,
  setAnalyst,
  getAnalyst,
  applyCorrection,
  revertCorrection,
  listCorrections,
  entityDbFor,
  graphModelForCase,
} from "../../src/agent/session.js";

// ca-session: the correction store (single-writer vault.put, redacted key, tombstone revert) + the
// analyst name, applied INSIDE entityDbFor + graphModelForCase so the override propagates. New symbols.

async function seeded(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const v = await Vault.unlock(storage, "pw");
  await v.put("run:dig", {
    objective: "dig",
    steps: [],
    promoted: [{ entity: "example.com", entity_type: "domain", source_count: 2, infra_source_count: 2, grade: "A" }],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  return v;
}

function roleOf(v: Vault, value: string): string | undefined {
  return entityDbFor(v).entities[canonKey("domain", value)]?.role;
}

describe("ca-session — corrections store + analyst + projection", () => {
  it("a role correction propagates to entityDbFor + graphModelForCase", async () => {
    const v = await seeded();
    const before = roleOf(v, "example.com");
    await applyCorrection(v, "domain", "example.com", "role", "operator");
    expect(roleOf(v, "example.com")).toBe("operator");
    expect(before).not.toBe("operator"); // the original was something else
    const model = graphModelForCase(v)!;
    const node = model.nodes.find((n) => n.label === "example.com")!;
    expect(node.role).toBe("operator");
  });

  it("an invalid predicate/value is rejected with no write", async () => {
    const v = await seeded();
    await expect(applyCorrection(v, "domain", "example.com", "role", "banana")).rejects.toBeInstanceOf(SessionError);
    await expect(applyCorrection(v, "domain", "example.com", "color", "operator")).rejects.toBeInstanceOf(SessionError);
    expect(listCorrections(v)).toEqual([]);
  });

  it("a tombstone revert restores the original role", async () => {
    const v = await seeded();
    const original = roleOf(v, "example.com");
    await applyCorrection(v, "domain", "example.com", "role", "operator");
    expect(roleOf(v, "example.com")).toBe("operator");
    await revertCorrection(v, canonKey("domain", "example.com"), "role");
    expect(roleOf(v, "example.com")).toBe(original);
    expect(listCorrections(v).filter((c) => c.active)).toEqual([]); // no active correction after revert
  });

  it("the correction record carries the analyst name", async () => {
    const v = await seeded();
    await setAnalyst(v, "Ada");
    expect(getAnalyst(v)).toBe("Ada");
    await applyCorrection(v, "domain", "example.com", "role", "operator");
    expect(listCorrections(v).some((c) => c.author === "Ada")).toBe(true);
  });

  it("a correction whose value embeds a configured secret is rejected (the redacted key has [REDACTED])", async () => {
    const v = await seeded();
    const KEY = "sk-ant-CORR-secret-7777";
    await setApiKey(v, KEY);
    await expect(applyCorrection(v, "domain", `evil-${KEY}.com`, "role", "operator")).rejects.toBeInstanceOf(SessionError);
    // an analyst name embedding the key is redacted, not stored raw
    await setAnalyst(v, `me-${KEY}`);
    expect(getAnalyst(v)).not.toContain(KEY);
  });
});
