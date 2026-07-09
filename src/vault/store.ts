// Single-writer persistence chokepoint. EVERY durable write of vault bytes goes
// through a VaultStorage.write. The OPFS implementation is the ONLY code in the
// tree that calls createWritable() — tests/vault/single-writer.test.ts greps the
// tree to prove no other module bypasses it (the bypass_check for kweb-vault).
// Scar (docs/17 / spine doctrine): kipi's recurring bug class is "N creation
// paths validate independently"; the cure is one write path, not another sweep.

export interface VaultStorage {
  read(name: string): Promise<Uint8Array | null>;
  write(name: string, bytes: Uint8Array): Promise<void>;
  remove(name: string): Promise<void>;
}

/** OPFS-backed storage (browser). The single durable writer. */
export const opfsStorage: VaultStorage = {
  async read(name) {
    const dir = await navigator.storage.getDirectory();
    try {
      const fh = await dir.getFileHandle(name);
      const file = await fh.getFile();
      return new Uint8Array(await file.arrayBuffer());
    } catch {
      return null; // not found
    }
  },
  async write(name, bytes) {
    const dir = await navigator.storage.getDirectory();
    const fh = await dir.getFileHandle(name, { create: true });
    const w = await fh.createWritable();
    await w.write(bytes);
    await w.close();
  },
  async remove(name) {
    const dir = await navigator.storage.getDirectory();
    try {
      await dir.removeEntry(name);
    } catch {
      /* already gone */
    }
  },
};

/** In-memory storage for unit tests (test isolation: never touches a live path). */
export function memoryStorage(seed?: Map<string, Uint8Array>): VaultStorage {
  const m = seed ?? new Map<string, Uint8Array>();
  return {
    async read(name) {
      return m.has(name) ? new Uint8Array(m.get(name)!) : null;
    },
    async write(name, bytes) {
      m.set(name, new Uint8Array(bytes));
    },
    async remove(name) {
      m.delete(name);
    },
  };
}

// ---------------------------------------------------------------------------
// PRD-11: own-your-data-on-disk. The disk backend is a SECOND VaultStorage,
// kept in THIS file so the only createWritable() in the tree stays here (the
// grep-enforced single-writer chokepoint — tests/vault/single-writer.test.ts).
// It is name-agnostic: it stores under whatever name the vault layer passes
// (today "vault.json"), so vault.ts is untouched.
// ---------------------------------------------------------------------------

/** Thrown when a durable write would clobber bytes another writer changed under us. */
export class VaultConflictError extends Error {
  constructor(name: string) {
    super(`vault "${name}" changed under us (another tab or writer); refusing to overwrite`);
    this.name = "VaultConflictError";
  }
}

// The File System Access permission methods + the picked-folder name are not in
// the default DOM lib types; declare exactly the narrow surface we use.
export interface DiskFileHandle {
  getFile(): Promise<{ arrayBuffer(): Promise<ArrayBuffer> }>;
  createWritable(opts?: { keepExistingData?: boolean }): Promise<{
    write(data: BufferSource): Promise<void>;
    close(): Promise<void>;
  }>;
}
export interface DiskDirectoryHandle {
  readonly name: string;
  getFileHandle(name: string, opts?: { create?: boolean }): Promise<DiskFileHandle>;
  removeEntry(name: string): Promise<void>;
  queryPermission?(opts: { mode: "read" | "readwrite" }): Promise<PermissionState | "prompt">;
  requestPermission?(opts: { mode: "read" | "readwrite" }): Promise<PermissionState | "prompt">;
}

function isNotFound(e: unknown): boolean {
  return e instanceof DOMException ? e.name === "NotFoundError" : false;
}

/** Disk-folder backend over a picked FileSystemDirectoryHandle. Atomic full rewrite. */
export function diskStorage(dir: DiskDirectoryHandle): VaultStorage {
  return {
    async read(name) {
      let fh: DiskFileHandle;
      try {
        fh = await dir.getFileHandle(name); // no {create}: absent => NotFoundError => null
      } catch (e) {
        if (isNotFound(e)) return null;
        throw e; // I/O or permission error: the mirror decides whether to take over
      }
      const file = await fh.getFile();
      return new Uint8Array(await file.arrayBuffer());
    },
    async write(name, bytes) {
      const fh = await dir.getFileHandle(name, { create: true });
      // Atomic: createWritable() writes a temp swap and replaces on close(). Full
      // rewrite of the sealed blob — NOT keepExistingData (that is for appends).
      const w = await fh.createWritable();
      await w.write(bytes);
      await w.close();
    },
    async remove(name) {
      try {
        await dir.removeEntry(name);
      } catch (e) {
        if (!isNotFound(e)) throw e; // already gone is fine
      }
    },
  };
}

/** Fast non-crypto content hash (FNV-1a, 32-bit hex). A divergence DETECTOR, not security. */
export function bytesHash(bytes: Uint8Array): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/**
 * Compose a canonical PRIMARY (disk) with a best-effort MIRROR (OPFS last-good).
 *
 * write: divergence-guard the primary (throw VaultConflictError rather than
 *   clobber a concurrent writer), then write the primary; the mirror is advanced
 *   ONLY after the primary save succeeds (best-effort), so disk and mirror never
 *   diverge into a silent rollback (the codex finding-2 trap). A failed disk write
 *   surfaces to the caller with the mirror left at its last good state.
 * read: primary wins; the mirror serves the last-good copy only when the primary
 *   READ throws (unreadable disk), never merely because the primary is absent-then-
 *   present. Recovery from a wiped primary returns the mirror's copy.
 */
export function mirrorStorage(primary: VaultStorage, mirror: VaultStorage): VaultStorage {
  // Per-name hash of what we last observed/wrote on the primary; the optimistic
  // concurrency token. Absent key = "never observed" (no guard).
  const expected = new Map<string, string | null>();

  async function primaryHashOrUnknown(name: string): Promise<string | null | undefined> {
    try {
      const cur = await primary.read(name);
      return cur === null ? null : bytesHash(cur);
    } catch {
      return undefined; // unreadable: cannot verify, skip the guard
    }
  }

  return {
    async read(name) {
      try {
        const r = await primary.read(name);
        if (r !== null) {
          expected.set(name, bytesHash(r));
          return r;
        }
        // primary has no file: offer the mirror's last-good (recovery if wiped).
        const m = await mirror.read(name);
        expected.set(name, m === null ? null : bytesHash(m));
        return m;
      } catch {
        // primary unreadable: fall back to the mirror, do not assert a token.
        expected.delete(name);
        return mirror.read(name);
      }
    },
    async write(name, bytes) {
      if (expected.has(name)) {
        const want = expected.get(name)!;
        const got = await primaryHashOrUnknown(name);
        if (got !== undefined && got !== want) throw new VaultConflictError(name);
      }
      await primary.write(name, bytes); // canonical: must succeed (throws surface)
      try {
        await mirror.write(name, bytes); // best-effort; disk is the source of truth
      } catch {
        /* mirror hiccup: disk holds the save; the mirror refreshes on next read */
      }
      expected.set(name, bytesHash(bytes));
    },
    async remove(name) {
      await primary.remove(name);
      try {
        await mirror.remove(name);
      } catch {
        /* best-effort */
      }
      expected.delete(name);
    },
  };
}
