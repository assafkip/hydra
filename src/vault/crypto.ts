// Vault crypto primitives. WebCrypto only (no third-party runtime code — F1).
// Design (PRD finding-2, key separation + IV uniqueness):
//   - vaultKey  = KDF(password, saltP)            wraps the dataKey ONLY
//   - recovKey  = KDF(recoveryPhrase, saltR)      wraps the dataKey ONLY
//   - dataKey   = random 256-bit AES-GCM key       encrypts the payload ONLY
//   - every AES-GCM op uses a FRESH random 96-bit IV (never reused); GCM's
//     128-bit tag is what makes a tampered ciphertext throw on decrypt.
// Scar: a single nonce reused across two payloads under one key is catastrophic
// for AES-GCM, so IVs are generated per-call here, never threaded in.

import { argon2id } from "hash-wasm";

export const KDF_ITERS = 600_000; // PBKDF2-SHA256 (legacy + back-compat for vaults created before Argon2id).
const IV_BYTES = 12;
const SALT_BYTES = 16;
const KEY_BITS = 256;

// The wrapping-key derivation descriptor stored per side in the VaultFile. Argon2id is memory-hard, so an
// exfiltrated vault.json + a weak password is far costlier to crack offline than under PBKDF2 (decisions #2).
export type KdfDesc =
  | { algo: "pbkdf2"; iters: number }
  | { algo: "argon2id"; mem: number; time: number; parallelism: number };

// Argon2id params: 64 MiB memory (mem is KiB), 3 passes, 1 lane — above the OWASP memory-hard floor
// (m=19 MiB,t=2,p=1) with comfortable browser latency (~0.3–0.6s per unlock). New vaults use this; old
// PBKDF2 vaults migrate to it on the next unlock.
export const DEFAULT_KDF = { algo: "argon2id", mem: 65536, time: 3, parallelism: 1 } as const satisfies KdfDesc;

const subtle = globalThis.crypto.subtle;

// Sane bounds for a real kipi vault's Argon2id descriptor. A value outside these is corrupt or hostile
// (codex): reject it (→ PBKDF2 fallback, which just fails to unwrap an Argon2id wrap → "wrong password",
// never a silently-weak key) AND it caps mem so a tampered descriptor can't OOM the browser on unlock.
const ARGON_BOUNDS = { mem: [8192, 1_048_576], time: [1, 10], parallelism: [1, 4] } as const;
function intInRange(n: unknown, [lo, hi]: readonly [number, number]): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= lo && n <= hi;
}

/** Normalize a stored kdf descriptor — including the LEGACY `{ iters }` shape (no `algo`) written before
 *  Argon2id — into a typed KdfDesc. Argon2id params are bounds-validated (an out-of-range / non-integer
 *  shape is rejected, not trusted). An unrecognized shape falls back to the PBKDF2 floor (safe: it only
 *  affects which derivation is TRIED; a wrong guess just fails to unwrap and throws "wrong password"). A
 *  below-floor-but-valid descriptor IS returned as-is so an existing wrap can still be unwrapped — it is
 *  then upgraded by migrate-on-unlock (see kdfMeetsFloor). */
export function normalizeKdf(raw: unknown): KdfDesc {
  if (raw && typeof raw === "object") {
    const r = raw as Record<string, unknown>;
    if (
      r.algo === "argon2id" &&
      intInRange(r.mem, ARGON_BOUNDS.mem) &&
      intInRange(r.time, ARGON_BOUNDS.time) &&
      intInRange(r.parallelism, ARGON_BOUNDS.parallelism)
    ) {
      return { algo: "argon2id", mem: r.mem, time: r.time, parallelism: r.parallelism };
    }
    if (typeof r.iters === "number" && Number.isInteger(r.iters) && r.iters > 0) {
      return { algo: "pbkdf2", iters: r.iters }; // legacy {iters} or explicit pbkdf2
    }
  }
  return { algo: "pbkdf2", iters: KDF_ITERS };
}

/** True iff the descriptor meets the CURRENT memory-hard floor (DEFAULT_KDF). PBKDF2 never does, so it
 *  always migrates; a below-floor (weak/old) Argon2id descriptor migrates too. This decides
 *  migrate-on-unlock — it never weakens the derivation actually used to unwrap an existing wrap. */
export function kdfMeetsFloor(kdf: KdfDesc): boolean {
  return (
    kdf.algo === "argon2id" &&
    kdf.mem >= DEFAULT_KDF.mem &&
    kdf.time >= DEFAULT_KDF.time &&
    kdf.parallelism >= DEFAULT_KDF.parallelism
  );
}

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function newSalt(): Uint8Array {
  return randomBytes(SALT_BYTES);
}

/** Derive a non-extractable AES-GCM wrapping key from a secret string, under the given KDF. */
export async function deriveWrappingKey(secret: string, salt: Uint8Array, kdf: KdfDesc): Promise<CryptoKey> {
  if (kdf.algo === "argon2id") {
    // hash-wasm Argon2id → 32 raw bytes → import as a non-extractable AES-GCM key. The WASM ships inline
    // (base64) in the bundle, so it loads SAME-ORIGIN (no CDN, no separate .wasm fetch); compiles under the
    // the app's strict CSP.
    const raw = await argon2id({
      password: secret,
      salt,
      parallelism: kdf.parallelism,
      iterations: kdf.time,
      memorySize: kdf.mem, // KiB
      hashLength: KEY_BITS / 8,
      outputType: "binary",
    });
    return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  // PBKDF2 (legacy + back-compat): unchanged from the original.
  const base = await subtle.importKey("raw", new TextEncoder().encode(secret), "PBKDF2", false, [
    "deriveKey",
  ]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: kdf.iters, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Fresh random 256-bit data key, returned as raw bytes (so it can be wrapped). */
export function newDataKeyBytes(): Uint8Array {
  return randomBytes(KEY_BITS / 8);
}

/** Import raw key bytes as an AES-GCM key for payload encryption. */
export async function importDataKey(bytes: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export interface Sealed {
  iv: string; // base64
  ct: string; // base64 (ciphertext + GCM tag)
}

/** AES-GCM encrypt bytes under a key with a fresh IV. */
export async function seal(key: CryptoKey, plaintext: Uint8Array): Promise<Sealed> {
  const iv = randomBytes(IV_BYTES);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { iv: b64encode(iv), ct: b64encode(new Uint8Array(ct)) };
}

/** AES-GCM decrypt. THROWS if the key is wrong or the ciphertext was tampered. */
export async function open(key: CryptoKey, sealed: Sealed): Promise<Uint8Array> {
  const iv = b64decode(sealed.iv);
  const ct = b64decode(sealed.ct);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

// ---- base64 (works in browser and node; no Buffer dependency on the import path) ----
export function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** A human-handleable recovery phrase: 32 random bytes as base32-ish hex groups. */
export function newRecoveryPhrase(): string {
  const b = randomBytes(20);
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return (hex.match(/.{1,4}/g) ?? []).join("-").toUpperCase();
}
