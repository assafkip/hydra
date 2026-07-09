// The zero-knowledge vault. The founder can never decrypt this: the data key is
// random, wrapped only by a password-derived key (never sent anywhere) and a
// recovery key (shown once). See docs/17 section 1.2 and the PRD Decisions.
//
// Spine note: the payload here is a JSON document. The vault is payload-agnostic
// (crypto.seal takes bytes), so production swaps the plaintext for
// @sqlite.org/sqlite-wasm export() bytes with no change to this file. A unit test
// round-trips arbitrary (sqlite-shaped) bytes to prove it.

import {
  deriveWrappingKey,
  importDataKey,
  newDataKeyBytes,
  newRecoveryPhrase,
  newSalt,
  open,
  seal,
  b64encode,
  b64decode,
  normalizeKdf,
  kdfMeetsFloor,
  DEFAULT_KDF,
  type KdfDesc,
  type Sealed,
} from "./crypto.js";
import type { VaultStorage } from "./store.js";

const VAULT_FILE = "vault.json";
const VERSION = 1;

export class VaultError extends Error {}

interface VaultFile {
  v: number;
  // Per-side KDF descriptors (Argon2id for new vaults). A legacy file carries only `kdf:{iters}`; readFile
  // normalizes it into kdfP=kdfR=pbkdf2 so old vaults still open, then migrate-on-unlock upgrades them.
  kdfP: KdfDesc; // password-side KDF
  kdfR: KdfDesc; // recovery-side KDF
  saltP: string; // b64 password KDF salt
  saltR: string; // b64 recovery KDF salt
  wrappedByPassword: Sealed; // seal(vaultKey, dataKeyBytes)
  wrappedByRecovery: Sealed; // seal(recoveryKey, dataKeyBytes)
  payload: Sealed; // seal(dataKey, JSON document bytes)
}

type Doc = Record<string, unknown>;

export class Vault {
  // Construct via the static factories (create/unlock/recoverWithPhrase), not directly.
  constructor(
    private readonly storage: VaultStorage,
    private file: VaultFile,
    private dataKeyBytes: Uint8Array | null,
    private dataKey: CryptoKey | null,
    private doc: Doc | null,
  ) {}

  // Single-writer serialization (kweb-chat-persist regression): put/deleteByPrefix/rekey each mutate the
  // shared `doc` then `await seal(...)` then persist. With TWO concurrent mutators (e.g. a chat-history
  // write firing during a file intake's run-record write), the later-started seal could RESOLVE first and
  // its `this.file.payload =` assignment be overwritten by the earlier one — a lost update that dropped a
  // run record (a real OCR'd entity vanished from the graph). Serializing the seal+persist critical section
  // makes concurrent mutators safe: each commit re-seals the LATEST doc (all prior synchronous mutations
  // already applied), so coalescing can never lose a write.
  private writeChain: Promise<void> = Promise.resolve();
  private commit(): Promise<void> {
    this.writeChain = this.writeChain.then(async () => {
      this.file.payload = await seal(this.dataKey!, encodeDoc(this.doc!));
      await this.persist();
    });
    return this.writeChain;
  }

  static async exists(storage: VaultStorage): Promise<boolean> {
    return (await storage.read(VAULT_FILE)) !== null;
  }

  /** Create a brand-new vault. Returns the recovery phrase to show ONCE. */
  static async create(
    storage: VaultStorage,
    password: string,
  ): Promise<{ vault: Vault; recoveryPhrase: string }> {
    if (!password) throw new VaultError("password required");
    const dataKeyBytes = newDataKeyBytes();
    const recoveryPhrase = newRecoveryPhrase();
    const saltP = newSalt();
    const saltR = newSalt();
    const vaultKey = await deriveWrappingKey(password, saltP, DEFAULT_KDF);
    const recoveryKey = await deriveWrappingKey(recoveryPhrase, saltR, DEFAULT_KDF);
    const dataKey = await importDataKey(dataKeyBytes);
    const doc: Doc = {};
    const file: VaultFile = {
      v: VERSION,
      kdfP: DEFAULT_KDF,
      kdfR: DEFAULT_KDF,
      saltP: b64encode(saltP),
      saltR: b64encode(saltR),
      wrappedByPassword: await seal(vaultKey, dataKeyBytes),
      wrappedByRecovery: await seal(recoveryKey, dataKeyBytes),
      payload: await seal(dataKey, encodeDoc(doc)),
    };
    const v = new Vault(storage, file, dataKeyBytes, dataKey, doc);
    await v.persist();
    return { vault: v, recoveryPhrase };
  }

  /** Unlock an existing vault with the password. Throws on wrong password. */
  static async unlock(storage: VaultStorage, password: string): Promise<Vault> {
    const file = await readFile(storage);
    const vaultKey = await deriveWrappingKey(password, b64decode(file.saltP), file.kdfP);
    const dataKeyBytes = await unwrap(vaultKey, file.wrappedByPassword, "wrong password");
    const v = await finishUnlock(storage, file, dataKeyBytes);
    // migrate-on-unlock: a legacy PBKDF2 password side is re-wrapped under Argon2id (fresh salt) once.
    if (!kdfMeetsFloor(file.kdfP)) await v.upgradePasswordKdf(password); // pbkdf2 or below-floor argon2id → upgrade
    return v;
  }

  /** Forgot the password: unlock with the recovery phrase and set a new password. */
  static async recoverWithPhrase(
    storage: VaultStorage,
    recoveryPhrase: string,
    newPassword: string,
  ): Promise<Vault> {
    if (!newPassword) throw new VaultError("new password required");
    const file = await readFile(storage);
    const recoveryKey = await deriveWrappingKey(recoveryPhrase, b64decode(file.saltR), file.kdfR);
    const dataKeyBytes = await unwrap(recoveryKey, file.wrappedByRecovery, "wrong recovery key");
    const v = await finishUnlock(storage, file, dataKeyBytes);
    // migrate-on-unlock (recovery side): re-wrap under Argon2id while we hold the phrase. The password
    // side is set to Argon2id by changePasswordUnlocked below.
    if (!kdfMeetsFloor(file.kdfR)) await v.upgradeRecoveryKdf(recoveryPhrase); // pbkdf2 or below-floor argon2id → upgrade
    await v.changePasswordUnlocked(newPassword);
    return v;
  }

  /** Restore an unlocked session from a persisted (non-extractable) data CryptoKey — NO password.
   *  Powers "stay signed in on this device": the key was kept in IndexedDB (session.ts). dataKeyBytes
   *  stays null, so get/put work but changePassword needs a fresh login (rare, acceptable). A key that
   *  does not match the on-disk payload throws here, so the caller self-heals by forgetting it. */
  static async restore(storage: VaultStorage, dataKey: CryptoKey): Promise<Vault> {
    const file = await readFile(storage);
    let doc: Doc;
    try {
      doc = decodeDoc(await open(dataKey, file.payload));
    } catch {
      throw new VaultError("session key does not match this vault");
    }
    return new Vault(storage, file, null, dataKey, doc);
  }

  /** The non-extractable data CryptoKey for this unlocked session, or null if locked. Persisted via
   *  structured clone for stay-signed-in; the raw key bytes are never exposed (extractable=false). */
  sessionKey(): CryptoKey | null {
    return this.dataKey;
  }

  /** Re-wrap the data key under a new password. Vault must be unlocked. */
  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    // Prove the caller knows the current password before re-wrapping.
    const oldKey = await deriveWrappingKey(oldPassword, b64decode(this.file.saltP), this.file.kdfP);
    await unwrap(oldKey, this.file.wrappedByPassword, "wrong password");
    await this.changePasswordUnlocked(newPassword);
  }

  private async changePasswordUnlocked(newPassword: string): Promise<void> {
    if (!this.dataKeyBytes) throw new VaultError("vault is locked");
    if (!newPassword) throw new VaultError("new password required");
    const saltP = newSalt();
    const vaultKey = await deriveWrappingKey(newPassword, saltP, DEFAULT_KDF);
    this.file.saltP = b64encode(saltP);
    this.file.kdfP = DEFAULT_KDF; // a password change always lands on the current (Argon2id) KDF
    this.file.wrappedByPassword = await seal(vaultKey, this.dataKeyBytes);
    await this.persist();
  }

  // migrate-on-unlock helpers: re-wrap one side's dataKey copy under Argon2id with a fresh salt, then
  // persist. The dataKey is unchanged (the payload is NOT re-encrypted) — only the wrapping is upgraded.
  private async upgradePasswordKdf(password: string): Promise<void> {
    if (!this.dataKeyBytes) return;
    const saltP = newSalt();
    const vaultKey = await deriveWrappingKey(password, saltP, DEFAULT_KDF);
    this.file.saltP = b64encode(saltP);
    this.file.kdfP = DEFAULT_KDF;
    this.file.wrappedByPassword = await seal(vaultKey, this.dataKeyBytes);
    await this.persist();
  }

  private async upgradeRecoveryKdf(recoveryPhrase: string): Promise<void> {
    if (!this.dataKeyBytes) return;
    const saltR = newSalt();
    const recoveryKey = await deriveWrappingKey(recoveryPhrase, saltR, DEFAULT_KDF);
    this.file.saltR = b64encode(saltR);
    this.file.kdfR = DEFAULT_KDF;
    this.file.wrappedByRecovery = await seal(recoveryKey, this.dataKeyBytes);
    await this.persist();
  }

  async put(key: string, value: unknown): Promise<void> {
    this.requireUnlocked();
    this.doc![key] = value;
    await this.commit(); // serialized seal+persist — concurrent puts can't lose updates
  }

  get(key: string): unknown {
    this.requireUnlocked();
    return this.doc![key];
  }

  /** Delete every document key whose name starts with `prefix`, then re-seal + persist ONCE. The keys are
   *  ABSOLUTE names (callers pass a `case:<id>:` prefix to drop a whole case's namespace). Routes through the
   *  same single durable writer as put — a partial wipe can never persist (one seal, one write). Returns the
   *  count removed. No-op write when nothing matched, so it can't churn the payload. */
  async deleteByPrefix(prefix: string): Promise<number> {
    this.requireUnlocked();
    if (!prefix) throw new VaultError("deleteByPrefix requires a non-empty prefix"); // guard: "" would wipe the vault
    let removed = 0;
    for (const key of Object.keys(this.doc!)) {
      if (key.startsWith(prefix)) {
        delete this.doc![key];
        removed++;
      }
    }
    if (removed > 0) await this.commit(); // serialized seal+persist (single-writer)
    return removed;
  }

  /** Re-key document entries: move each `from` → `to`, then re-seal + persist ONCE. Used by the legacy-data
   *  migration (un-prefixed keys → a `case:<id>:` namespace). Refuses to overwrite an existing `to` (a
   *  collision would silently merge two records). Tolerates an absent `from` (a partial re-run). No-op write
   *  when nothing actually moved, so it can't churn the payload. */
  async rekey(mapping: Record<string, string>): Promise<void> {
    this.requireUnlocked();
    let moved = 0;
    for (const [from, to] of Object.entries(mapping)) {
      if (!from || !to) throw new VaultError("rekey requires non-empty key names");
      if (from === to || !(from in this.doc!)) continue; // no-op / source already gone (idempotent re-run)
      if (to in this.doc!) throw new VaultError(`rekey collision: '${to}' already exists`);
      this.doc![to] = this.doc![from];
      delete this.doc![from];
      moved++;
    }
    if (moved > 0) await this.commit(); // serialized seal+persist (single-writer)
  }

  /** Enumerate stored document key NAMES (read-only; no values). For listing saved
   *  runs/briefs. Callers filter the reserved secret: namespace (see session.ts). */
  keys(): string[] {
    this.requireUnlocked();
    return Object.keys(this.doc!);
  }

  lock(): void {
    if (this.dataKeyBytes) this.dataKeyBytes.fill(0);
    this.dataKeyBytes = null;
    this.dataKey = null;
    this.doc = null;
  }

  get locked(): boolean {
    return this.dataKey === null;
  }

  // Single durable writer: every persist routes through storage.write.
  private async persist(): Promise<void> {
    await this.storage.write(VAULT_FILE, new TextEncoder().encode(JSON.stringify(this.file)));
  }

  private requireUnlocked(): void {
    if (!this.dataKey || !this.doc) throw new VaultError("vault is locked");
  }
}

async function finishUnlock(
  storage: VaultStorage,
  file: VaultFile,
  dataKeyBytes: Uint8Array,
): Promise<Vault> {
  const dataKey = await importDataKey(dataKeyBytes);
  let doc: Doc;
  try {
    doc = decodeDoc(await open(dataKey, file.payload));
  } catch {
    throw new VaultError("vault payload is corrupted");
  }
  return new Vault(storage, file, dataKeyBytes, dataKey, doc);
}

async function unwrap(key: CryptoKey, sealed: Sealed, failMsg: string): Promise<Uint8Array> {
  try {
    return await open(key, sealed);
  } catch {
    throw new VaultError(failMsg);
  }
}

async function readFile(storage: VaultStorage): Promise<VaultFile> {
  const bytes = await storage.read(VAULT_FILE);
  if (!bytes) throw new VaultError("no vault on this device");
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new VaultError("vault file is corrupted");
  }
  if (raw.v !== VERSION) throw new VaultError(`unsupported vault version ${String(raw.v)}`);
  // Back-compat: a legacy file has `kdf:{iters}` and no kdfP/kdfR. Normalize BOTH sides — from the new
  // per-side fields when present, else from the legacy shared `kdf`. No version bump: old vaults open.
  const legacy = raw.kdf;
  return {
    v: VERSION,
    kdfP: normalizeKdf(raw.kdfP ?? legacy),
    kdfR: normalizeKdf(raw.kdfR ?? legacy),
    saltP: raw.saltP as string,
    saltR: raw.saltR as string,
    wrappedByPassword: raw.wrappedByPassword as Sealed,
    wrappedByRecovery: raw.wrappedByRecovery as Sealed,
    payload: raw.payload as Sealed,
  };
}

function encodeDoc(doc: Doc): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(doc));
}
function decodeDoc(bytes: Uint8Array): Doc {
  return JSON.parse(new TextDecoder().decode(bytes));
}
