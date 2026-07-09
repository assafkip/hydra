import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { Vault } from "../src/vault/vault.js";
import { memoryStorage } from "../src/vault/store.js";
import { scopedVault, setApiKey, getApiKey } from "../src/agent/session.js";

// Pairs with the post-audit `vault-isolation-hardening` issue (prd-kipi-web-post-audit-fixes-2026-06-20).
// scopedVault is THE case-isolation chokepoint; deep A/B bleed is already proven by cases-session.test.ts.
// This file guards the HARDENING: the Proxy is now an ALLOWLIST (scope get/put/keys; pass classified
// members + symbols + Object.prototype probes; THROW on an unclassified Vault function member) + the
// reserved `case:` namespace invariant. Registered as a permanent prd-os gate (bypass_check).

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

describe("scopedVault hardening", () => {
  it("scopes get/put/keys per case and shares secret: globally", async () => {
    const raw = await freshVault();
    await setApiKey(raw, "sk-ant-ISO-secret-9"); // a GLOBAL secret: key
    const def = scopedVault(raw, "default");
    const caseB = scopedVault(raw, "case-b");

    await def.put("run:x", { case: "default" });
    await caseB.put("run:x", { case: "b" });

    expect(def.get("run:x")).toEqual({ case: "default" });
    expect(caseB.get("run:x")).toEqual({ case: "b" }); // no bleed
    expect(def.keys()).toContain("run:x");
    expect(def.keys().some((k) => k.startsWith("case:"))).toBe(false); // default never sees a case: key
    // secret: is global — both views read the same key
    expect(getApiKey(def)).toBe("sk-ant-ISO-secret-9");
    expect(getApiKey(caseB)).toBe("sk-ant-ISO-secret-9");
  });

  it("passes through every CURRENT Vault member (no false throw)", async () => {
    const raw = await freshVault();
    const view = scopedVault(raw, "case-x");
    // accessing each classified member must NOT throw (the allowlist permits them)
    expect(typeof view.put).toBe("function");
    expect(typeof view.get).toBe("function");
    expect(typeof view.keys).toBe("function");
    expect(typeof view.lock).toBe("function");
    expect(typeof view.changePassword).toBe("function");
    expect(typeof view.locked).toBe("boolean"); // getter passes through
    // runtime-private internal methods (also in the pass-through allowlist) must not throw either
    expect(typeof (view as unknown as { persist: unknown }).persist).toBe("function");
    expect(typeof (view as unknown as { changePasswordUnlocked: unknown }).changePasswordUnlocked).toBe("function");
  });

  it("does not break Promise / String / constructor probes — and does NOT leak raw internals via JSON", async () => {
    const raw = await freshVault();
    await setApiKey(raw, "sk-ant-LEAK-probe-1");
    const view = scopedVault(raw, "case-x");
    await view.put("run:secretish", { note: "case data only" });
    expect(() => Promise.resolve(view)).not.toThrow(); // reads .then (undefined)
    expect(() => String(view)).not.toThrow(); // reads .toString (Object.prototype)
    expect(view.constructor).toBeTruthy(); // Object.prototype builtin passes through
    // TS `private` fields are enumerable at runtime; the proxy MUST block own-field access so a
    // serializer/log probe can't dump the RAW decrypted doc / keys / secrets (codex major).
    const json = JSON.stringify(view);
    expect(json).toBe("{}"); // every own internal field is hidden — nothing serializes
    expect(json).not.toContain("sk-ant-LEAK-probe-1");
    expect(json).not.toContain("case data only");
    expect((view as unknown as { doc: unknown }).doc).toBeUndefined(); // raw doc unreachable via [[Get]]
    // descriptor-based reads (util.inspect / Object.entries / getOwnPropertyDescriptor) are sealed too
    expect(Object.getOwnPropertyDescriptor(view, "doc")).toBeUndefined();
    expect(Object.keys(view)).not.toContain("doc");
    expect(Object.keys(view)).not.toContain("dataKeyBytes");
  });

  it("THROWS on an unclassified key-addressed mutator (the cross-case-bleed tripwire)", async () => {
    const raw = await freshVault();
    // simulate a FUTURE Vault gaining an unclassified method. Methods live on the PROTOTYPE (not an own
    // field), so add it there; clean up after so no other test sees it.
    const proto = Object.getPrototypeOf(raw) as Record<string, unknown>;
    proto.deleteKey = function () {};
    try {
      const view = scopedVault(raw, "case-x");
      expect(() => (view as unknown as { deleteKey: unknown }).deleteKey).toThrow(/unhandled Vault member/);
    } finally {
      delete proto.deleteKey;
    }
  });
});

describe("reserved case: namespace invariant", () => {
  it("no source writes a base DATA key literally under the case: prefix", () => {
    // CASE_PREFIX is 'case:'; ONLY scopedVault.enc() may produce a case:-prefixed key. A literal
    // vault.put("case:...") anywhere else would collide and vanish from the default view (critic #3).
    for (const f of ["src/agent/session.ts", "src/app.ts", "src/pages.ts"]) {
      const src = readFileSync(f, "utf8");
      expect(/\.put\(\s*[`"']case:/.test(src)).toBe(false);
    }
  });
});
