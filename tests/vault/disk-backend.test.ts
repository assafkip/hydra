import { describe, it, expect, afterEach } from "vitest";
import {
  diskStorage,
  mirrorStorage,
  memoryStorage,
  bytesHash,
  VaultConflictError,
} from "../../src/vault/store.js";
import {
  saveHandle,
  loadHandle,
  queryGranted,
  requestGranted,
  __setHandleStore,
} from "../../src/vault/handle.js";
import { FakeDirectoryHandle, fakeHandleStore, throwingHandleStore } from "./fake-fs.js";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array | null) => (b === null ? null : new TextDecoder().decode(b));

afterEach(() => __setHandleStore(null));

describe("diskStorage (positive)", () => {
  it("write -> read round-trips bytes, name-agnostic", async () => {
    const dir = new FakeDirectoryHandle();
    const disk = diskStorage(dir);
    await disk.write("vault.json", enc("sealed-A"));
    expect(dec(await disk.read("vault.json"))).toBe("sealed-A");
  });

  it("read of a missing file returns null (not an error)", async () => {
    const disk = diskStorage(new FakeDirectoryHandle());
    expect(await disk.read("vault.json")).toBeNull();
  });

  it("write fully rewrites (no append leakage)", async () => {
    const dir = new FakeDirectoryHandle();
    const disk = diskStorage(dir);
    await disk.write("vault.json", enc("the-long-old-blob"));
    await disk.write("vault.json", enc("new"));
    expect(dec(await disk.read("vault.json"))).toBe("new");
  });

  it("remove deletes; removing a missing file does not throw", async () => {
    const dir = new FakeDirectoryHandle();
    const disk = diskStorage(dir);
    await disk.write("vault.json", enc("x"));
    await disk.remove("vault.json");
    expect(await disk.read("vault.json")).toBeNull();
    await expect(disk.remove("vault.json")).resolves.toBeUndefined();
  });
});

describe("diskStorage (negative)", () => {
  it("read propagates a non-NotFound I/O error (so the mirror can take over)", async () => {
    const dir = new FakeDirectoryHandle();
    await diskStorage(dir).write("vault.json", enc("x"));
    dir.corruptReads();
    await expect(diskStorage(dir).read("vault.json")).rejects.toBeInstanceOf(DOMException);
  });

  it("write after a mid-session permission revoke throws NotAllowedError", async () => {
    const dir = new FakeDirectoryHandle();
    const disk = diskStorage(dir);
    await disk.write("vault.json", enc("good"));
    dir.revoke();
    await expect(disk.write("vault.json", enc("later"))).rejects.toMatchObject({ name: "NotAllowedError" });
  });
});

describe("mirrorStorage (disk canonical + OPFS last-good)", () => {
  it("writes to BOTH backends on every save", async () => {
    const dir = new FakeDirectoryHandle();
    const opfs = memoryStorage();
    const mirror = mirrorStorage(diskStorage(dir), opfs);
    await mirror.write("vault.json", enc("v1"));
    expect(dec(await diskStorage(dir).read("vault.json"))).toBe("v1");
    expect(dec(await opfs.read("vault.json"))).toBe("v1");
  });

  it("read prefers the primary (disk)", async () => {
    const dir = new FakeDirectoryHandle();
    const opfs = memoryStorage();
    await diskStorage(dir).write("vault.json", enc("disk-value"));
    await opfs.write("vault.json", enc("stale-mirror"));
    const mirror = mirrorStorage(diskStorage(dir), opfs);
    expect(dec(await mirror.read("vault.json"))).toBe("disk-value");
  });

  it("falls back to the OPFS last-good when the disk READ throws", async () => {
    const dir = new FakeDirectoryHandle();
    const opfs = memoryStorage();
    const mirror = mirrorStorage(diskStorage(dir), opfs);
    await mirror.write("vault.json", enc("saved")); // both have it
    dir.corruptReads(); // disk now unreadable
    expect(dec(await mirror.read("vault.json"))).toBe("saved"); // served from OPFS
  });

  it("recovers from a wiped disk by returning the mirror copy", async () => {
    const dir = new FakeDirectoryHandle();
    const opfs = memoryStorage();
    await opfs.write("vault.json", enc("last-good")); // disk empty, mirror has it
    const mirror = mirrorStorage(diskStorage(dir), opfs);
    expect(dec(await mirror.read("vault.json"))).toBe("last-good");
  });

  it("NEGATIVE: a concurrent writer triggers VaultConflictError instead of a clobber", async () => {
    const dir = new FakeDirectoryHandle();
    const opfs = memoryStorage();
    const a = mirrorStorage(diskStorage(dir), opfs);
    const b = mirrorStorage(diskStorage(dir), opfs);
    await a.write("vault.json", enc("seed"));
    await a.read("vault.json"); // a observes seed
    await b.read("vault.json"); // b observes seed
    await a.write("vault.json", enc("a-edit")); // a advances the primary
    await expect(b.write("vault.json", enc("b-edit"))).rejects.toBeInstanceOf(VaultConflictError);
    expect(dec(await diskStorage(dir).read("vault.json"))).toBe("a-edit"); // not clobbered
  });

  it("NEGATIVE: a disk write failure surfaces and leaves the OPFS mirror at last-good", async () => {
    const dir = new FakeDirectoryHandle();
    const opfs = memoryStorage();
    const mirror = mirrorStorage(diskStorage(dir), opfs);
    await mirror.write("vault.json", enc("good"));
    dir.revoke(); // disk writes now throw
    await expect(mirror.write("vault.json", enc("never-persisted"))).rejects.toMatchObject({
      name: "NotAllowedError",
    });
    expect(dec(await opfs.read("vault.json"))).toBe("good"); // mirror not advanced past last-good
  });

  it("tolerates a mirror (OPFS) write hiccup because disk is the source of truth", async () => {
    const dir = new FakeDirectoryHandle();
    const flakyMirror = {
      read: memoryStorage().read,
      async write() {
        throw new Error("opfs quota");
      },
      async remove() {},
    };
    const mirror = mirrorStorage(diskStorage(dir), flakyMirror);
    await expect(mirror.write("vault.json", enc("v1"))).resolves.toBeUndefined();
    expect(dec(await diskStorage(dir).read("vault.json"))).toBe("v1");
  });
});

describe("handle persistence + permission split", () => {
  it("saveHandle/loadHandle round-trip through the (fake) store", async () => {
    __setHandleStore(fakeHandleStore());
    const dir = new FakeDirectoryHandle("Investigations");
    expect(await saveHandle(dir)).toBe(true);
    const restored = await loadHandle();
    expect(restored?.name).toBe("Investigations");
  });

  it("NEGATIVE: IndexedDB unavailable -> saveHandle false, loadHandle null (no throw)", async () => {
    __setHandleStore(throwingHandleStore());
    expect(await saveHandle(new FakeDirectoryHandle())).toBe(false);
    expect(await loadHandle()).toBeNull();
  });

  it("queryGranted reflects permission WITHOUT prompting", async () => {
    const dir = new FakeDirectoryHandle();
    dir.permission = "granted";
    expect(await queryGranted(dir)).toBe(true);
    dir.permission = "denied";
    expect(await queryGranted(dir)).toBe(false);
    dir.permission = "prompt"; // a query must not flip prompt -> granted
    expect(await queryGranted(dir)).toBe(false);
    expect(dir.permission).toBe("prompt");
  });

  it("requestGranted resolves a prompt (gesture path); denied stays false", async () => {
    const grant = new FakeDirectoryHandle();
    grant.permission = "prompt";
    grant.grantOnRequest = "granted";
    expect(await requestGranted(grant)).toBe(true);

    const deny = new FakeDirectoryHandle();
    deny.permission = "prompt";
    deny.grantOnRequest = "denied";
    expect(await requestGranted(deny)).toBe(false);
  });
});

describe("bytesHash", () => {
  it("is stable and distinguishes different bytes", () => {
    expect(bytesHash(enc("abc"))).toBe(bytesHash(enc("abc")));
    expect(bytesHash(enc("abc"))).not.toBe(bytesHash(enc("abd")));
  });
});
