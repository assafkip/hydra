// Test double for the File System Access API. The native showDirectoryPicker +
// FileSystemDirectoryHandle cannot run outside a real browser; this in-memory fake
// models exactly the surface our code uses (DiskDirectoryHandle) plus the failure
// switches the negative self-tests need: permission denied, revoked mid-session,
// and an unreadable/corrupt file. The real OS folder-pick is the documented MANUAL
// check (docs/disk-storage-manual-check.md), not faked away.

import type { DiskDirectoryHandle, DiskFileHandle } from "../../src/vault/store.js";
import type { HandleStore } from "../../src/vault/handle.js";

function notFound(): DOMException {
  return new DOMException("not found", "NotFoundError");
}
function notAllowed(): DOMException {
  return new DOMException("permission revoked", "NotAllowedError");
}

class FakeWritable {
  private chunks: Uint8Array[] = [];
  constructor(private commit: (bytes: Uint8Array) => void) {}
  async write(data: BufferSource): Promise<void> {
    this.chunks.push(new Uint8Array(data as ArrayBuffer));
  }
  async close(): Promise<void> {
    // Atomic semantics: nothing is visible until close() commits the swap.
    const total = this.chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of this.chunks) {
      out.set(c, o);
      o += c.length;
    }
    this.commit(out);
  }
}

class FakeFileHandle implements DiskFileHandle {
  constructor(
    private dir: FakeDirectoryHandle,
    private name: string,
  ) {}
  async getFile() {
    if (this.dir.readError) throw this.dir.readError;
    const bytes = this.dir.files.get(this.name);
    if (bytes === undefined) throw notFound();
    return { arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
  }
  async createWritable() {
    if (this.dir.writeError) throw this.dir.writeError;
    return new FakeWritable((bytes) => {
      if (this.dir.writeError) throw this.dir.writeError;
      this.dir.files.set(this.name, bytes);
    });
  }
}

export class FakeDirectoryHandle implements DiskDirectoryHandle {
  files = new Map<string, Uint8Array>();
  permission: PermissionState | "prompt" = "granted";
  /** when set, requestPermission resolves a "prompt" to this state. */
  grantOnRequest: PermissionState = "granted";
  /** when set, createWritable/getFile throw it (simulate revoke / corrupt). */
  writeError: DOMException | null = null;
  readError: DOMException | null = null;

  constructor(public readonly name = "My Cases") {}

  async getFileHandle(name: string, opts?: { create?: boolean }): Promise<DiskFileHandle> {
    if (!this.files.has(name) && !opts?.create) throw notFound();
    if (opts?.create && !this.files.has(name)) {
      // a created-but-unwritten file exists but is empty until a writable commits;
      // we register lazily on first commit, so model "exists" via a 0-byte entry
      // only when create is requested and then immediately written.
    }
    return new FakeFileHandle(this, name);
  }
  async removeEntry(name: string): Promise<void> {
    if (!this.files.delete(name)) throw notFound();
  }
  async queryPermission(_opts: { mode: "read" | "readwrite" }): Promise<PermissionState | "prompt"> {
    return this.permission;
  }
  async requestPermission(_opts: { mode: "read" | "readwrite" }): Promise<PermissionState | "prompt"> {
    if (this.permission === "prompt") {
      this.permission = this.grantOnRequest;
      return this.grantOnRequest;
    }
    return this.permission;
  }

  // ---- test controls ----
  /** Simulate the user revoking access mid-session (next write/read throws). */
  revoke(): void {
    this.permission = "denied";
    this.writeError = notAllowed();
    this.readError = notAllowed();
  }
  /** Simulate an unreadable/corrupt file (reads throw, writes still work). */
  corruptReads(): void {
    this.readError = new DOMException("read failed", "NotReadableError");
  }
}

/** In-memory HandleStore: stands in for IndexedDB in node tests. */
export function fakeHandleStore(initial?: DiskDirectoryHandle): HandleStore {
  let held: DiskDirectoryHandle | null = initial ?? null;
  return {
    async save(h) {
      held = h;
    },
    async load() {
      return held;
    },
    async clear() {
      held = null;
    },
  };
}

/** A HandleStore whose every op throws — simulates IndexedDB unavailable/blocked. */
export function throwingHandleStore(): HandleStore {
  const boom = () => Promise.reject(new Error("indexedDB unavailable"));
  return { save: boom, load: boom, clear: boom };
}
