// PRD-11: choose the storage backend and reconcile disk vs the OPFS mirror.
// Disk is canonical when configured + supported + permission-granted; OPFS is the
// mirror + fallback. NO durable writes here (no createWritable) — it composes the
// store.ts primitives. The encrypted export/import portability path lives here too
// (Firefox/Safari and backups), moving only sealed bytes through VaultStorage.

import {
  opfsStorage,
  diskStorage,
  mirrorStorage,
  bytesHash,
  type VaultStorage,
  type DiskDirectoryHandle,
} from "./store.js";
import { loadHandle, queryGranted } from "./handle.js";

// The well-known vault filename. Mirrors VAULT_FILE in vault.ts; the disk/mirror
// backends are name-agnostic at runtime, so this is only the name the
// portability + reconciliation helpers read by default.
export const VAULT_FILE = "vault.json";

export type StorageMode = "disk" | "opfs";

export interface Backend {
  storage: VaultStorage;
  mode: StorageMode;
  /** The picked folder's name, when on disk (for the banner). */
  folderName?: string;
  /** True when a present disk vault and the OPFS mirror disagree (surface, don't clobber). */
  conflict?: boolean;
  /** True when a folder was configured but its permission has lapsed (offer re-grant). */
  needsRegrant?: boolean;
}

/** Feature-detect the File System Access directory picker (Chrome/Edge/Opera). */
export function supportsDiskPicker(): boolean {
  return typeof globalThis !== "undefined" && "showDirectoryPicker" in globalThis;
}

/**
 * Select the active backend on launch. NEVER prompts (queryGranted only). Returns
 * OPFS when the picker is unsupported, no folder was configured, or the stored
 * folder's permission has lapsed (with needsRegrant so the app can offer a
 * gesture-driven re-grant). When disk is active it is wrapped by the OPFS mirror.
 */
export async function pickBackend(
  file: string = VAULT_FILE,
  mirror: VaultStorage = opfsStorage,
): Promise<Backend> {
  if (!supportsDiskPicker()) return { storage: mirror, mode: "opfs" };

  const handle = await loadHandle();
  if (!handle) return { storage: mirror, mode: "opfs" };

  if (!(await queryGranted(handle))) {
    return { storage: mirror, mode: "opfs", folderName: handle.name, needsRegrant: true };
  }

  return diskBackend(handle, file, mirror);
}

/**
 * Build the disk-mirrored backend for a freshly granted handle (after the user
 * picked a folder and granted permission via a gesture). Same composition as the
 * launch path, without re-reading IndexedDB.
 */
export async function diskBackend(
  handle: DiskDirectoryHandle,
  file: string = VAULT_FILE,
  mirror: VaultStorage = opfsStorage,
): Promise<Backend> {
  const disk = diskStorage(handle);
  const conflict = await detectConflict(disk, mirror, file);
  return { storage: mirrorStorage(disk, mirror), mode: "disk", folderName: handle.name, conflict };
}

/** The OPFS-only backend (Firefox/Safari, or the user opted out of disk). */
export function opfsBackend(mirror: VaultStorage = opfsStorage): Backend {
  return { storage: mirror, mode: "opfs" };
}

/**
 * A present disk vault and a present OPFS mirror that DISAGREE = a divergence. Disk
 * is canonical, so we never auto-overwrite it from a stale mirror; the conflict is
 * surfaced for the banner. Absent-on-either-side is not a conflict (fresh disk, or
 * a wiped disk recovered from the mirror).
 */
async function detectConflict(
  disk: VaultStorage,
  mirror: VaultStorage,
  file: string,
): Promise<boolean> {
  let d: Uint8Array | null;
  try {
    d = await disk.read(file);
  } catch {
    return false; // disk unreadable: handled by the mirror fallback, not a content conflict
  }
  if (d === null) return false;
  let m: Uint8Array | null;
  try {
    m = await mirror.read(file);
  } catch {
    return false;
  }
  if (m === null) return false;
  return bytesHash(d) !== bytesHash(m);
}

// ---- encrypted export / import (sealed bytes only; no DOM, no plaintext) ----

/** Read the sealed vault bytes for download/backup. Null when there is no vault. */
export function exportVault(storage: VaultStorage, file: string = VAULT_FILE): Promise<Uint8Array | null> {
  return storage.read(file);
}

/** Write imported sealed vault bytes back through the single-writer chokepoint. */
export function importVault(
  storage: VaultStorage,
  bytes: Uint8Array,
  file: string = VAULT_FILE,
): Promise<void> {
  return storage.write(file, bytes);
}
