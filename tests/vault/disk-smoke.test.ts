// PRD-11 p11-smoke: the integration round-trip — a REAL Vault on top of the
// disk-mirror backend, wired through the same handle store + selector the app
// uses, driven against an injected fake DirectoryHandle. This is the automated
// proof; the real OS folder-pick is the documented MANUAL check
// (docs/disk-storage-manual-check.md), because Playwright cannot drive the native
// dialog. The memory mirror + fake handle store persist across the simulated
// reload (the same instances), modeling OPFS + IndexedDB surviving a page reload.

import { describe, it, expect, afterEach } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { saveHandle, __setHandleStore } from "../../src/vault/handle.js";
import { pickBackend } from "../../src/vault/location.js";
import { FakeDirectoryHandle, fakeHandleStore } from "./fake-fs.js";

const g = globalThis as unknown as { showDirectoryPicker?: unknown };

afterEach(() => {
  __setHandleStore(null);
  delete g.showDirectoryPicker;
});

describe("disk storage smoke: full lifecycle against a fake DirectoryHandle", () => {
  it("create on disk -> drop state -> restore handle -> reopen -> read back byte-identical", async () => {
    g.showDirectoryPicker = () => {}; // feature-detect: disk supported
    const opfs = memoryStorage(); // stands in for OPFS, persists across the "reload"
    const folder = new FakeDirectoryHandle("My Investigations");
    __setHandleStore(fakeHandleStore()); // stands in for IndexedDB, persists across "reload"

    // --- session 1: user picks the folder, then creates + uses a vault on disk ---
    const persisted = await saveHandle(folder);
    expect(persisted).toBe(true);

    const s1 = await pickBackend("vault.json", opfs);
    expect(s1.mode).toBe("disk");
    expect(s1.folderName).toBe("My Investigations");

    const { recoveryPhrase } = await Vault.create(s1.storage, "pw-lifecycle");
    expect(recoveryPhrase).toMatch(/[0-9A-F-]+/);
    const v1 = await Vault.unlock(s1.storage, "pw-lifecycle");
    await v1.put("case-007", { subject: "shell-co", risk: "high" });
    v1.lock();

    // the encrypted blob is really sitting in the folder
    const onDisk = folder.files.get("vault.json");
    expect(onDisk).toBeDefined();

    // --- reload: every in-memory reference is dropped; disk + IDB + OPFS persist ---
    const s2 = await pickBackend("vault.json", opfs);
    expect(s2.mode).toBe("disk"); // handle restored from IndexedDB, permission still granted
    expect(s2.conflict).toBeFalsy(); // disk and mirror agree

    const v2 = await Vault.unlock(s2.storage, "pw-lifecycle");
    expect(v2.get("case-007")).toEqual({ subject: "shell-co", risk: "high" });
  });

  it("fallback: an unreadable disk serves the OPFS last-good copy (no data loss)", async () => {
    g.showDirectoryPicker = () => {};
    const opfs = memoryStorage();
    const folder = new FakeDirectoryHandle("Cases");
    __setHandleStore(fakeHandleStore());
    await saveHandle(folder);

    const s1 = await pickBackend("vault.json", opfs);
    await Vault.create(s1.storage, "pw-fallback");
    const v1 = await Vault.unlock(s1.storage, "pw-fallback");
    await v1.put("c", { ok: true });
    v1.lock();

    // disk goes unreadable (e.g. the synced folder is offline)
    folder.corruptReads();
    const s2 = await pickBackend("vault.json", opfs);
    // selection itself does not throw; the mirror covers the read
    const v2 = await Vault.unlock(s2.storage, "pw-fallback");
    expect(v2.get("c")).toEqual({ ok: true });
  });

  it("Firefox/Safari (no picker): selector returns OPFS, the vault still works", async () => {
    delete g.showDirectoryPicker; // no disk picker
    const opfs = memoryStorage();
    const s = await pickBackend("vault.json", opfs);
    expect(s.mode).toBe("opfs");
    await Vault.create(s.storage, "pw-ffx");
    const v = await Vault.unlock(s.storage, "pw-ffx");
    await v.put("c", { browser: "firefox" });
    expect(v.get("c")).toEqual({ browser: "firefox" });
  });
});
