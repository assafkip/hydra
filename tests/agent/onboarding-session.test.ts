import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { getOnboarded, setOnboarded } from "../../src/agent/session.js";

// ob-tour: the onboarding flag is a key-safe session chokepoint over `setting:onboarded`,
// mirroring getWorkerUrl/setWorkerUrl. Default false on a fresh vault; true after setOnboarded;
// the write goes through the single chokepoint (never a raw vault.put from the UI).

describe("onboarding flag (session chokepoint)", () => {
  it("defaults false on a fresh vault", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    expect(getOnboarded(vault)).toBe(false);
  });

  it("is true after setOnboarded, and persists across a lock+unlock", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setOnboarded(vault);
    expect(getOnboarded(vault)).toBe(true);
    vault.lock();
    const reopened = await Vault.unlock(storage, "pw");
    expect(getOnboarded(reopened)).toBe(true);
  });

  it("reads false (never throws) when the vault is locked", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setOnboarded(vault);
    vault.lock();
    expect(getOnboarded(vault)).toBe(false); // locked → falls back to false, no throw
  });
});
