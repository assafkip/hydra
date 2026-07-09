// Stay signed in on this device (founder: usability is king, 2026-06-20). We persist the vault's
// NON-EXTRACTABLE data CryptoKey in IndexedDB via structured clone. A structured clone of a CryptoKey
// preserves the key WITHOUT ever exposing its raw bytes (the key was imported extractable=false in
// crypto.ts), so a page reload re-opens the encrypted payload with no password re-entry — and a
// compromised bundle still cannot read the raw key material out of storage. We NEVER persist the
// password or the raw dataKeyBytes.
//
// Lifecycle: every unlock site routes through applyVault → rememberDataKey (single chokepoint). An
// explicit Sign out calls forgetDataKey (the real lock). An idle auto-lock or a pagehide only drops
// the in-memory copy; the next load restores from here. No-ops when IndexedDB is unavailable (the
// jsdom unit env), so unit tests and locked-down browsers degrade gracefully instead of throwing.

const DB_NAME = "kipi-session";
const STORE = "keys";
const KEY_ID = "dataKey";

function idbFactory(): IDBFactory | null {
  try {
    return typeof indexedDB !== "undefined" ? indexedDB : null;
  } catch {
    return null;
  }
}

function openDb(): Promise<IDBDatabase | null> {
  const factory = idbFactory();
  if (!factory) return Promise.resolve(null);
  return new Promise((resolve) => {
    let req: IDBOpenDBRequest;
    try {
      req = factory.open(DB_NAME, 1);
    } catch {
      resolve(null);
      return;
    }
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => resolve(null);
    req.onblocked = () => resolve(null);
  });
}

// Run one object-store op; resolve regardless of outcome (best-effort, never throws into the caller).
function run<T>(
  mode: IDBTransactionMode,
  op: (store: IDBObjectStore) => IDBRequest,
  read: boolean,
  fallback: T,
): Promise<T> {
  return openDb().then((db) => {
    if (!db) return fallback;
    return new Promise<T>((resolve) => {
      let tx: IDBTransaction;
      try {
        tx = db.transaction(STORE, mode);
      } catch {
        db.close();
        resolve(fallback);
        return;
      }
      let result: T = fallback;
      let req: IDBRequest;
      try {
        req = op(tx.objectStore(STORE)); // a non-cloneable value throws DataCloneError synchronously here
      } catch {
        try { tx.abort(); } catch { /* already settling */ }
        db.close();
        resolve(fallback);
        return;
      }
      if (read) req.onsuccess = () => { result = (req.result as T) ?? fallback; };
      tx.oncomplete = () => { db.close(); resolve(result); };
      tx.onerror = () => { db.close(); resolve(fallback); };
      tx.onabort = () => { db.close(); resolve(fallback); };
    });
  });
}

/** Persist the (non-extractable) data CryptoKey so the next load can auto-unlock. No-op on null. */
export async function rememberDataKey(key: CryptoKey | null): Promise<void> {
  if (!key) return;
  await run("readwrite", (s) => s.put(key, KEY_ID), false, undefined);
}

/** The persisted data CryptoKey, or null if none / IndexedDB unavailable. */
export async function recallDataKey(): Promise<CryptoKey | null> {
  const v = await run<unknown>("readonly", (s) => s.get(KEY_ID), true, null);
  return v instanceof CryptoKey ? v : null;
}

/** Drop the persisted key — the real "Sign out" / reset. */
export async function forgetDataKey(): Promise<void> {
  await run("readwrite", (s) => s.delete(KEY_ID), false, undefined);
}
