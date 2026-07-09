import { describe, it, expect } from "vitest";
import { Vault, VaultError } from "../../src/vault/vault";
import { memoryStorage } from "../../src/vault/store";

describe("Vault: zero-knowledge lifecycle", () => {
  it("creates, persists, locks, and unlocks with the password", async () => {
    const storage = memoryStorage();
    const { vault, recoveryPhrase } = await Vault.create(storage, "hunter2");
    expect(recoveryPhrase).toMatch(/[0-9A-F-]{8,}/);
    await vault.put("case", { name: "nve-403", target: "example.com" });

    // New Vault instance reading the SAME storage = a real persistence round-trip.
    const reopened = await Vault.unlock(storage, "hunter2");
    expect(reopened.get("case")).toEqual({ name: "nve-403", target: "example.com" });
  });

  // NEGATIVE: wrong password must not unlock.
  it("THROWS on wrong password", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "hunter2");
    await expect(Vault.unlock(storage, "wrong")).rejects.toBeInstanceOf(VaultError);
  });

  // NEGATIVE: a tampered vault file must not unlock.
  it("THROWS when the stored ciphertext is tampered", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "hunter2");
    const raw = await storage.read("vault.json");
    const file = JSON.parse(new TextDecoder().decode(raw!));
    // flip a char in the payload ciphertext
    file.payload.ct = file.payload.ct.slice(0, -2) + (file.payload.ct.endsWith("A") ? "B" : "A") + "=";
    await storage.write("vault.json", new TextEncoder().encode(JSON.stringify(file)));
    await expect(Vault.unlock(storage, "hunter2")).rejects.toBeInstanceOf(VaultError);
  });

  it("password change: old password stops working, new one works, data intact", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "old-pass");
    await vault.put("k", "v");
    await vault.changePassword("old-pass", "new-pass");
    await expect(Vault.unlock(storage, "old-pass")).rejects.toBeInstanceOf(VaultError);
    const reopened = await Vault.unlock(storage, "new-pass");
    expect(reopened.get("k")).toBe("v");
  });

  it("changePassword rejects a wrong current password", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "old-pass");
    await expect(vault.changePassword("not-old", "new-pass")).rejects.toBeInstanceOf(VaultError);
  });

  // The recovery-key model: forgot password -> recover with phrase -> set new password.
  it("recovers cases with the recovery phrase after a forgotten password", async () => {
    const storage = memoryStorage();
    const { vault, recoveryPhrase } = await Vault.create(storage, "forgotten");
    await vault.put("case", { id: 1 });

    const recovered = await Vault.recoverWithPhrase(storage, recoveryPhrase, "brand-new");
    expect(recovered.get("case")).toEqual({ id: 1 });
    // new password now works; the forgotten one does not
    expect((await Vault.unlock(storage, "brand-new")).get("case")).toEqual({ id: 1 });
    await expect(Vault.unlock(storage, "forgotten")).rejects.toBeInstanceOf(VaultError);
  });

  it("recovery rejects a wrong recovery phrase", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    await expect(
      Vault.recoverWithPhrase(storage, "0000-0000-0000", "new"),
    ).rejects.toBeInstanceOf(VaultError);
  });

  it("locking clears access until re-unlocked", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "pw");
    await vault.put("k", "v");
    vault.lock();
    expect(vault.locked).toBe(true);
    expect(() => vault.get("k")).toThrow(VaultError);
  });

  it("unlock with no vault present throws", async () => {
    await expect(Vault.unlock(memoryStorage(), "pw")).rejects.toBeInstanceOf(VaultError);
  });
});

// Argon2id KDF + migrate-on-unlock (item 5).
import {
  deriveWrappingKey,
  importDataKey,
  newDataKeyBytes,
  newSalt,
  seal,
  b64encode,
} from "../../src/vault/crypto";

const VAULT_FILE = "vault.json";
const enc = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
const readStored = async (s: ReturnType<typeof memoryStorage>): Promise<Record<string, unknown>> =>
  JSON.parse(new TextDecoder().decode((await s.read(VAULT_FILE))!));

/** Hand-build a LEGACY PBKDF2 vault file (the pre-Argon2id on-disk shape: a single `kdf:{iters}`, no
 *  kdfP/kdfR) so we can prove old vaults still open AND migrate on unlock. */
async function writeLegacyPbkdf2Vault(
  storage: ReturnType<typeof memoryStorage>,
  password: string,
  recoveryPhrase: string,
  doc: Record<string, unknown>,
): Promise<void> {
  const pbkdf2 = { algo: "pbkdf2" as const, iters: 600_000 };
  const dataKeyBytes = newDataKeyBytes();
  const saltP = newSalt();
  const saltR = newSalt();
  const vaultKey = await deriveWrappingKey(password, saltP, pbkdf2);
  const recoveryKey = await deriveWrappingKey(recoveryPhrase, saltR, pbkdf2);
  const dataKey = await importDataKey(dataKeyBytes);
  const legacy = {
    v: 1,
    kdf: { iters: 600_000 }, // the legacy shared shape, NO algo / kdfP / kdfR
    saltP: b64encode(saltP),
    saltR: b64encode(saltR),
    wrappedByPassword: await seal(vaultKey, dataKeyBytes),
    wrappedByRecovery: await seal(recoveryKey, dataKeyBytes),
    payload: await seal(dataKey, enc(doc)),
  };
  await storage.write(VAULT_FILE, enc(legacy));
}

describe("Vault: Argon2id KDF + migration", () => {
  it("a new vault uses Argon2id on both sides", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const f = await readStored(storage);
    expect((f.kdfP as { algo: string }).algo).toBe("argon2id");
    expect((f.kdfR as { algo: string }).algo).toBe("argon2id");
  });

  it("a legacy PBKDF2 vault still unlocks, data intact, and migrates the password side to Argon2id", async () => {
    const storage = memoryStorage();
    await writeLegacyPbkdf2Vault(storage, "pw", "AAAA-BBBB-CCCC", { case: "legacy-403" });

    const v = await Vault.unlock(storage, "pw");
    expect(v.get("case")).toBe("legacy-403"); // decrypts under the legacy PBKDF2 wrap

    const migrated = await readStored(storage);
    expect((migrated.kdfP as { algo: string }).algo).toBe("argon2id"); // password side upgraded on unlock
    // the recovery side is untouched on a PASSWORD unlock (no phrase in hand)
    expect((migrated.kdfR as { algo: string }).algo).toBe("pbkdf2");

    // the migrated file re-unlocks with the same password, data still intact
    const again = await Vault.unlock(storage, "pw");
    expect(again.get("case")).toBe("legacy-403");
  });

  it("wrong password still throws against a legacy vault (no accidental downgrade-bypass)", async () => {
    const storage = memoryStorage();
    await writeLegacyPbkdf2Vault(storage, "right", "AAAA-BBBB-CCCC", { k: "v" });
    await expect(Vault.unlock(storage, "wrong")).rejects.toBeInstanceOf(VaultError);
  });

  it("recovery on a legacy vault migrates the recovery side to Argon2id and resets the password", async () => {
    const storage = memoryStorage();
    await writeLegacyPbkdf2Vault(storage, "old", "AAAA-BBBB-CCCC", { k: "v" });
    const v = await Vault.recoverWithPhrase(storage, "AAAA-BBBB-CCCC", "fresh");
    expect(v.get("k")).toBe("v");
    const f = await readStored(storage);
    expect((f.kdfP as { algo: string }).algo).toBe("argon2id"); // changePassword landed on Argon2id
    expect((f.kdfR as { algo: string }).algo).toBe("argon2id"); // recovery side migrated
    // the new password works; the recovery phrase still recovers
    expect((await Vault.unlock(storage, "fresh")).get("k")).toBe("v");
  });
});
