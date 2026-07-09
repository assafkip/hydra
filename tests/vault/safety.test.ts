import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage, diskStorage, mirrorStorage } from "../../src/vault/store.js";
import { exportVault, importVault } from "../../src/vault/location.js";
import { FakeDirectoryHandle } from "./fake-fs.js";

const dec = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

describe("encrypted export / import portability (Firefox/Safari + backup)", () => {
  it("returns null when there is no vault to export", async () => {
    expect(await exportVault(memoryStorage())).toBeNull();
  });

  it("export -> import moves a real vault between backends, still unlockable", async () => {
    const a = memoryStorage();
    const { recoveryPhrase } = await Vault.create(a, "pw-correct-horse");
    void recoveryPhrase;
    const opened = await Vault.unlock(a, "pw-correct-horse");
    await opened.put("case-001", { subject: "acme-ltd" });

    const bytes = await exportVault(a);
    expect(bytes).not.toBeNull();

    const b = memoryStorage();
    await importVault(b, bytes!);
    const reopened = await Vault.unlock(b, "pw-correct-horse");
    expect(reopened.get("case-001")).toEqual({ subject: "acme-ltd" });
  });

  it("import writes through VaultStorage.write (lands on disk via the backend)", async () => {
    const dir = new FakeDirectoryHandle();
    const disk = diskStorage(dir);
    await importVault(disk, new TextEncoder().encode("sealed-bytes"));
    expect(dec(await disk.read("vault.json"))).toBe("sealed-bytes");
  });
});

describe("zero-knowledge: exported/on-disk bytes carry no plaintext secrets", () => {
  it("a known case string, API key, and password never appear in the sealed bytes", async () => {
    const SECRET_CASE = "OPERATION-NIGHTSHADE-target-was-here";
    const FAKE_API_KEY = "sk-ant-" + "PLAINTEXT-SHOULD-NOT-LEAK-0001";
    const PASSWORD = "correct horse battery staple ZK";

    const storage = memoryStorage();
    const { recoveryPhrase } = await Vault.create(storage, PASSWORD);
    const v = await Vault.unlock(storage, PASSWORD);
    await v.put("case", { note: SECRET_CASE, anthropicKey: FAKE_API_KEY });

    const bytes = await exportVault(storage);
    const text = new TextDecoder().decode(bytes!);

    expect(text).not.toContain(SECRET_CASE);
    expect(text).not.toContain(FAKE_API_KEY);
    expect(text).not.toContain(PASSWORD);
    expect(text).not.toContain(recoveryPhrase); // the recovery phrase is shown once, never stored
    // sanity: the file IS the sealed envelope (non-secret metadata is expected)
    expect(text).toContain("wrappedByPassword");
  });
});

describe("mirror safety under failure", () => {
  it("a stale OPFS mirror never overwrites a present disk vault", async () => {
    const dir = new FakeDirectoryHandle();
    const mirror = memoryStorage();
    await diskStorage(dir).write("vault.json", new TextEncoder().encode("disk-canonical"));
    await mirror.write("vault.json", new TextEncoder().encode("stale"));
    const store = mirrorStorage(diskStorage(dir), mirror);
    expect(dec(await store.read("vault.json"))).toBe("disk-canonical");
  });

  it("a revoked disk write leaves the OPFS last-good intact (no session loss)", async () => {
    const dir = new FakeDirectoryHandle();
    const mirror = memoryStorage();
    const store = mirrorStorage(diskStorage(dir), mirror);
    await store.write("vault.json", new TextEncoder().encode("good"));
    dir.revoke();
    await expect(store.write("vault.json", new TextEncoder().encode("lost"))).rejects.toMatchObject({
      name: "NotAllowedError",
    });
    expect(dec(await mirror.read("vault.json"))).toBe("good");
  });
});
