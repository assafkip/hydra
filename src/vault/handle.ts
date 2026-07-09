// PRD-11: persist the picked folder across sessions, and split permission into a
// no-prompt launch query vs a gesture-only request. NO durable vault writes here
// (no createWritable) — that stays in store.ts. The IndexedDB
// handle-store is behind an injectable seam so node tests drive it with a fake
// (the native picker + IndexedDB do not exist outside a real browser; that gap is
// the documented MANUAL check, not hidden).

import type { DiskDirectoryHandle } from "./store.js";

// ---- the directory picker (the one browser call we cannot test headless) ----

type Picker = () => Promise<DiskDirectoryHandle>;

const defaultPicker: Picker = () =>
  (globalThis as unknown as {
    showDirectoryPicker(opts: { mode: string }): Promise<DiskDirectoryHandle>;
  }).showDirectoryPicker({ mode: "readwrite" });

/** Open the OS folder picker. MUST be called from a user gesture. */
export function pickDirectory(): Promise<DiskDirectoryHandle> {
  return defaultPicker();
}

// ---- IndexedDB persistence of the structured-cloneable handle ----

/** The narrow persistence surface. The real impl is IndexedDB; tests inject a fake. */
export interface HandleStore {
  save(handle: DiskDirectoryHandle): Promise<void>;
  load(): Promise<DiskDirectoryHandle | null>;
  clear(): Promise<void>;
}

const DB_NAME = "kipi-vault";
const DB_VERSION = 1;
const STORE = "handles";
const KEY = "dir";

/** Real IndexedDB-backed handle store. Browser-only (IDB absent in node tests). */
export function idbHandleStore(): HandleStore {
  function open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
      req.onblocked = () => reject(new Error("indexedDB blocked"));
    });
  }
  function tx<T>(mode: IDBTransactionMode, run: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return open().then(
      (db) =>
        new Promise<T>((resolve, reject) => {
          const r = run(db.transaction(STORE, mode).objectStore(STORE));
          r.onsuccess = () => resolve(r.result);
          r.onerror = () => reject(r.error ?? new Error("indexedDB request failed"));
        }),
    );
  }
  return {
    save: (handle) => tx("readwrite", (s) => s.put(handle, KEY)).then(() => undefined),
    load: () => tx<DiskDirectoryHandle | undefined>("readonly", (s) => s.get(KEY)).then((v) => v ?? null),
    clear: () => tx("readwrite", (s) => s.delete(KEY)).then(() => undefined),
  };
}

let _store: HandleStore = idbHandleStore();

/** TEST SEAM: inject a fake handle store (node has no IndexedDB). */
export function __setHandleStore(s: HandleStore | null): void {
  _store = s ?? idbHandleStore();
}

/**
 * Persist the picked handle. Returns whether it will survive a reload: false when
 * IndexedDB is unavailable/blocked/quota-denied or the handle is not clonable —
 * the caller keeps using the handle in-session and tells the user persistence is off.
 */
export async function saveHandle(handle: DiskDirectoryHandle): Promise<boolean> {
  try {
    await _store.save(handle);
    return true;
  } catch {
    return false;
  }
}

/** Restore the picked handle, or null if none / IndexedDB is unavailable. Never throws. */
export async function loadHandle(): Promise<DiskDirectoryHandle | null> {
  try {
    return await _store.load();
  } catch {
    return null;
  }
}

/** Forget the picked handle (user switched back to browser storage). Never throws. */
export async function clearHandle(): Promise<void> {
  try {
    await _store.clear();
  } catch {
    /* nothing persisted is acceptable */
  }
}

// ---- permission lifecycle (query at launch, request only on a gesture) ----

/** Launch-safe: queryPermission ONLY — never shows a prompt. */
export async function queryGranted(handle: DiskDirectoryHandle): Promise<boolean> {
  if (!handle.queryPermission) return false;
  return (await handle.queryPermission({ mode: "readwrite" })) === "granted";
}

/** Gesture-only: requestPermission may prompt. Call from a click handler. */
export async function requestGranted(handle: DiskDirectoryHandle): Promise<boolean> {
  if (!handle.requestPermission) return false;
  return (await handle.requestPermission({ mode: "readwrite" })) === "granted";
}
