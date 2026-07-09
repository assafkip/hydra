import { describe, it, expect, afterEach } from "vitest";
import { memoryStorage, diskStorage } from "../../src/vault/store.js";
import { __setHandleStore } from "../../src/vault/handle.js";
import {
  supportsDiskPicker,
  pickBackend,
  diskBackend,
  opfsBackend,
} from "../../src/vault/location.js";
import { FakeDirectoryHandle, fakeHandleStore } from "./fake-fs.js";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

const g = globalThis as unknown as { showDirectoryPicker?: unknown };

function withPickerSupport(on: boolean) {
  if (on) g.showDirectoryPicker = () => {};
  else delete g.showDirectoryPicker;
}

afterEach(() => {
  __setHandleStore(null);
  withPickerSupport(false);
});

describe("supportsDiskPicker (feature detect)", () => {
  it("is false without showDirectoryPicker, true with it", () => {
    withPickerSupport(false);
    expect(supportsDiskPicker()).toBe(false);
    withPickerSupport(true);
    expect(supportsDiskPicker()).toBe(true);
  });
});

describe("pickBackend (launch selection, query-only, no silent downgrade)", () => {
  it("unsupported browser -> OPFS", async () => {
    withPickerSupport(false);
    const mirror = memoryStorage();
    const b = await pickBackend("vault.json", mirror);
    expect(b.mode).toBe("opfs");
  });

  it("supported but no folder configured -> OPFS", async () => {
    withPickerSupport(true);
    __setHandleStore(fakeHandleStore());
    const b = await pickBackend("vault.json", memoryStorage());
    expect(b.mode).toBe("opfs");
    expect(b.needsRegrant).toBeFalsy();
  });

  it("configured folder whose permission LAPSED -> OPFS + needsRegrant (no prompt at launch)", async () => {
    withPickerSupport(true);
    const dir = new FakeDirectoryHandle("Cases");
    dir.permission = "prompt"; // would prompt if we (wrongly) called requestPermission
    __setHandleStore(fakeHandleStore(dir));
    const b = await pickBackend("vault.json", memoryStorage());
    expect(b.mode).toBe("opfs");
    expect(b.needsRegrant).toBe(true);
    expect(b.folderName).toBe("Cases");
    expect(dir.permission).toBe("prompt"); // launch must NOT have flipped it to granted
  });

  it("configured + granted -> disk, mirror writes BOTH", async () => {
    withPickerSupport(true);
    const dir = new FakeDirectoryHandle("Cases");
    __setHandleStore(fakeHandleStore(dir));
    const mirror = memoryStorage();
    const b = await pickBackend("vault.json", mirror);
    expect(b.mode).toBe("disk");
    expect(b.folderName).toBe("Cases");
    await b.storage.write("vault.json", enc("v1"));
    expect(dec(await diskStorage(dir).read("vault.json"))).toBe("v1"); // disk
    expect(dec(await mirror.read("vault.json"))).toBe("v1"); // mirror
  });
});

describe("divergence reconciliation (disk canonical, never auto-clobber a stale mirror)", () => {
  it("no conflict when disk and mirror agree", async () => {
    const dir = new FakeDirectoryHandle();
    const mirror = memoryStorage();
    await diskStorage(dir).write("vault.json", enc("same"));
    await mirror.write("vault.json", enc("same"));
    const b = await diskBackend(dir, "vault.json", mirror);
    expect(b.conflict).toBeFalsy();
  });

  it("CONFLICT when a present disk vault and a present mirror disagree", async () => {
    const dir = new FakeDirectoryHandle();
    const mirror = memoryStorage();
    await diskStorage(dir).write("vault.json", enc("disk-newer"));
    await mirror.write("vault.json", enc("mirror-stale"));
    const b = await diskBackend(dir, "vault.json", mirror);
    expect(b.conflict).toBe(true);
    // disk is canonical: reading returns disk, the stale mirror is NOT served/clobbered
    expect(dec(await b.storage.read("vault.json"))).toBe("disk-newer");
  });

  it("fresh disk (no file) is not a conflict", async () => {
    const dir = new FakeDirectoryHandle();
    const mirror = memoryStorage();
    await mirror.write("vault.json", enc("only-mirror"));
    const b = await diskBackend(dir, "vault.json", mirror);
    expect(b.conflict).toBeFalsy();
  });
});

describe("opfsBackend", () => {
  it("returns the OPFS-mode backend", () => {
    const b = opfsBackend(memoryStorage());
    expect(b.mode).toBe("opfs");
  });
});
