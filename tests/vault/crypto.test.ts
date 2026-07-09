import { describe, it, expect } from "vitest";
import {
  deriveWrappingKey,
  importDataKey,
  newDataKeyBytes,
  newSalt,
  open,
  seal,
  randomBytes,
  normalizeKdf,
  kdfMeetsFloor,
  DEFAULT_KDF,
} from "../../src/vault/crypto";

describe("vault crypto primitives", () => {
  it("seals and opens bytes round-trip", async () => {
    const key = await importDataKey(newDataKeyBytes());
    const msg = new TextEncoder().encode("hello kipi");
    const sealed = await seal(key, msg);
    const out = await open(key, sealed);
    expect(new TextDecoder().decode(out)).toBe("hello kipi");
  });

  it("is payload-agnostic: round-trips a 5KB sqlite-shaped blob (proves prod sqlite swap)", async () => {
    const key = await importDataKey(newDataKeyBytes());
    const blob = randomBytes(5120); // stand-in for sqlite-wasm export() bytes
    const sealed = await seal(key, blob);
    const out = await open(key, sealed);
    expect(out).toEqual(blob);
  });

  it("uses a fresh IV every seal (no nonce reuse)", async () => {
    const key = await importDataKey(newDataKeyBytes());
    const a = await seal(key, new Uint8Array([1, 2, 3]));
    const b = await seal(key, new Uint8Array([1, 2, 3]));
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
  });

  // NEGATIVE self-test: a wrong key MUST fail, or "decrypt succeeds" is meaningless.
  it("THROWS when opened with the wrong key", async () => {
    const k1 = await importDataKey(newDataKeyBytes());
    const k2 = await importDataKey(newDataKeyBytes());
    const sealed = await seal(k1, new Uint8Array([9, 9, 9]));
    await expect(open(k2, sealed)).rejects.toBeTruthy();
  });

  // NEGATIVE self-test: a tampered ciphertext MUST fail (GCM tag).
  it("THROWS when the ciphertext is tampered", async () => {
    const key = await importDataKey(newDataKeyBytes());
    const sealed = await seal(key, new Uint8Array([4, 5, 6, 7]));
    const ctBytes = atob(sealed.ct);
    const flipped = ctBytes.slice(0, -1) + String.fromCharCode(ctBytes.charCodeAt(ctBytes.length - 1) ^ 0xff);
    await expect(open(key, { iv: sealed.iv, ct: btoa(flipped) })).rejects.toBeTruthy();
  });

  it("same password+salt derives an interoperable key (Argon2id)", async () => {
    const salt = newSalt();
    const k1 = await deriveWrappingKey("correct horse", salt, DEFAULT_KDF);
    const k2 = await deriveWrappingKey("correct horse", salt, DEFAULT_KDF);
    const sealed = await seal(k1, new Uint8Array([1, 1]));
    expect(await open(k2, sealed)).toEqual(new Uint8Array([1, 1]));
  });

  it("PBKDF2 and Argon2id are distinct KDFs (a key from one cannot open the other's seal)", async () => {
    const salt = newSalt();
    const argon = await deriveWrappingKey("pw", salt, DEFAULT_KDF);
    const pbkdf2 = await deriveWrappingKey("pw", salt, { algo: "pbkdf2", iters: 600_000 });
    const sealed = await seal(argon, new Uint8Array([9, 9]));
    await expect(open(pbkdf2, sealed)).rejects.toBeTruthy();
  });

  it("normalizeKdf maps the legacy {iters} shape to pbkdf2 and an argon2id record to argon2id", () => {
    expect(normalizeKdf({ iters: 600_000 })).toEqual({ algo: "pbkdf2", iters: 600_000 });
    expect(normalizeKdf({ algo: "argon2id", mem: 65536, time: 3, parallelism: 1 })).toEqual({
      algo: "argon2id", mem: 65536, time: 3, parallelism: 1,
    });
    expect(normalizeKdf(undefined)).toEqual({ algo: "pbkdf2", iters: 600_000 });
  });

  it("normalizeKdf REJECTS out-of-bounds / non-integer argon2id params (codex: no hostile weak descriptor)", () => {
    // below the memory floor, absurd values, non-integers, and bad iters all fall back to the pbkdf2 floor.
    expect(normalizeKdf({ algo: "argon2id", mem: 8, time: 1, parallelism: 1 })).toEqual({ algo: "pbkdf2", iters: 600_000 });
    expect(normalizeKdf({ algo: "argon2id", mem: 9e15, time: 3, parallelism: 1 })).toEqual({ algo: "pbkdf2", iters: 600_000 });
    expect(normalizeKdf({ algo: "argon2id", mem: 65536.5, time: 3, parallelism: 1 })).toEqual({ algo: "pbkdf2", iters: 600_000 });
    expect(normalizeKdf({ algo: "argon2id", mem: 65536, time: 3 })).toEqual({ algo: "pbkdf2", iters: 600_000 }); // missing parallelism
    expect(normalizeKdf({ iters: 0 })).toEqual({ algo: "pbkdf2", iters: 600_000 }); // non-positive iters
  });

  it("kdfMeetsFloor: pbkdf2 and below-floor argon2id are NOT at floor; DEFAULT_KDF is", () => {
    expect(kdfMeetsFloor({ algo: "pbkdf2", iters: 600_000 })).toBe(false);
    expect(kdfMeetsFloor({ algo: "argon2id", mem: 8192, time: 1, parallelism: 1 })).toBe(false); // weak argon2id migrates
    expect(kdfMeetsFloor(DEFAULT_KDF)).toBe(true);
  });
});
