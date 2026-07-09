import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  getProviderKey,
  setProviderKey,
  providerStatus,
  enrichTarget,
  listEnrichRuns,
  entityDbFor,
  SessionError,
} from "../../src/agent/session.js";
import { allEntities } from "../../src/entity/db.js";
import { base64, type FetchLike } from "../../src/osint/types.js";

// en-session: BYO-key enrichment — read the provider key from secret:<id>_key, fetch the provider
// DIRECT, re-gate via the SAME admission + attribution + promotion path as the agent loop, and land
// the result as a sanitized run: record through the EXISTING vault.put. No secret reaches the vault
// key, the record, or any encoded form (codex D1/D2/D3).

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

function cannedFetch(response: unknown): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => response })) as unknown as FetchLike;
}

const SHODAN_OK = {
  ip_str: "8.8.8.8",
  hostnames: ["good.example.com", "iana.org"], // iana.org is registry boilerplate -> gate drops it
  domains: ["google.com"],
  asn: "AS15169",
  ports: [443],
};

describe("provider keys", () => {
  it("setProviderKey/getProviderKey round-trip under secret:<id>_key", async () => {
    const vault = await freshVault();
    expect(getProviderKey(vault, "shodan")).toBeNull();
    await setProviderKey(vault, "shodan", "  shdn-123  ");
    expect(getProviderKey(vault, "shodan")).toBe("shdn-123"); // trimmed
    await expect(setProviderKey(vault, "shodan", "   ")).rejects.toBeInstanceOf(SessionError); // empty rejected
  });

  it("providerStatus reflects configured + lists the blocked holdouts", async () => {
    const vault = await freshVault();
    await setProviderKey(vault, "shodan", "k");
    const view = providerStatus(vault);
    expect(view.providers.find((p) => p.id === "shodan")?.configured).toBe(true);
    expect(view.providers.find((p) => p.id === "censys")?.configured).toBe(false);
    expect(view.blocked.map((b) => b.id)).toContain("virustotal");
  });
});

describe("enrichTarget", () => {
  it("lands gated entities into a run: record; the gate drops registry boilerplate", async () => {
    const vault = await freshVault();
    await setProviderKey(vault, "shodan", "shdn-key");
    const r = await enrichTarget(vault, "shodan", "8.8.8.8", { fetchImpl: cannedFetch(SHODAN_OK), retries: 0 });
    expect(r.provider).toBe("shodan");
    expect(r.objective).toBe("enrich: shodan 8.8.8.8");
    expect(r.count).toBeGreaterThanOrEqual(3); // good.example.com + google.com + AS15169 + the ip

    const values = allEntities(entityDbFor(vault, null)).map((e) => e.label);
    expect(values).toContain("good.example.com");
    expect(values).toContain("google.com");
    expect(values).toContain("AS15169");
    expect(values).not.toContain("iana.org"); // dropped by isAdmissible (NOISE_DOMAINS)
  });

  it("routes through vault.put exactly once (single writer untouched)", async () => {
    const vault = await freshVault();
    await setProviderKey(vault, "shodan", "shdn-key");
    const putSpy = vi.spyOn(vault, "put");
    await enrichTarget(vault, "shodan", "1.1.1.1", { fetchImpl: cannedFetch(SHODAN_OK), retries: 0 });
    expect(putSpy).toHaveBeenCalledTimes(1);
    expect(putSpy.mock.calls[0][0]).toMatch(/^run:enrich: shodan /);
  });

  it("a missing provider key surfaces a clean SessionError", async () => {
    const vault = await freshVault();
    await expect(enrichTarget(vault, "shodan", "8.8.8.8", { fetchImpl: cannedFetch(SHODAN_OK) })).rejects.toBeInstanceOf(SessionError);
  });

  it("an unknown provider id surfaces a clean SessionError", async () => {
    const vault = await freshVault();
    await expect(enrichTarget(vault, "nope", "8.8.8.8")).rejects.toBeInstanceOf(SessionError);
  });

  it("listEnrichRuns filters the enrich runs by sourceKind", async () => {
    const vault = await freshVault();
    await setProviderKey(vault, "shodan", "k");
    await enrichTarget(vault, "shodan", "8.8.8.8", { fetchImpl: cannedFetch(SHODAN_OK), retries: 0 });
    // a non-enrich run must not show up
    await vault.put("run:some investigation", { objective: "some investigation", steps: [], promoted: [], leads: [], usage: {}, stopReason: "end_turn" });
    const runs = listEnrichRuns(vault);
    expect(runs).toHaveLength(1);
    expect(runs[0].provider).toBe("shodan");
  });
});

describe("enrichTarget key hygiene (codex D2/D3)", () => {
  it("a provider key pasted as the TARGET never lands in the vault key name or the record (D2)", async () => {
    const vault = await freshVault();
    const KEY = "shdn-PASTED-secret-7777";
    await setProviderKey(vault, "shodan", KEY);
    const r = await enrichTarget(vault, "shodan", KEY, { fetchImpl: cannedFetch(SHODAN_OK), retries: 0 });
    expect(r.objective).not.toContain(KEY); // objective redacted -> vault key redacted
    expect(vault.keys().some((k) => k.includes(KEY))).toBe(false); // no vault key embeds the secret
    expect(JSON.stringify(vault.get(`run:${r.objective}`))).not.toContain(KEY);
  });

  it("a malicious provider response echoing the credential in any form is redacted (D3)", async () => {
    const vault = await freshVault();
    const cred = "APIID9999:secrethalf8888"; // Censys id:secret
    await setProviderKey(vault, "censys", cred);
    const b64 = base64(cred);
    // The malicious response echoes the secret HALF (as a domain value) and the base64 cred (as the
    // ASN org name -> a stored note). Both must be scrubbed before the record is persisted.
    const malicious = {
      result: {
        ip: "8.8.8.8",
        names: ["secrethalf8888.evil.com", "clean.example.com"],
        autonomous_system: { asn: 15169, name: b64 },
        services: [],
      },
    };
    const r = await enrichTarget(vault, "censys", "8.8.8.8", { fetchImpl: cannedFetch(malicious), retries: 0 });
    const stored = JSON.stringify(vault.get(`run:${r.objective}`));
    expect(stored).not.toContain("secrethalf8888"); // the secret half
    expect(stored).not.toContain(b64); // the base64(id:secret) Basic form
    expect(stored).not.toContain(cred); // the raw credential
    expect(stored).toContain("clean.example.com"); // the legitimate entity still lands
    expect(stored).toContain("[REDACTED]"); // proof the redaction actually fired
  });

  it("redacts a key echoed in a LOWERCASED domain — case-insensitive (en-smoke scar)", async () => {
    const vault = await freshVault();
    const KEY = "shdn-MixedCase-Secret-5151"; // mixed case; the adapter lowercases the domain value
    await setProviderKey(vault, "shodan", KEY);
    // Shodan lowercases hostnames/domains, so the echoed key arrives as evil-shdn-mixedcase-secret-5151.com
    const malicious = { ip_str: "8.8.8.8", domains: [`evil-${KEY}.com`], hostnames: ["clean.example.com"] };
    const r = await enrichTarget(vault, "shodan", "8.8.8.8", { fetchImpl: cannedFetch(malicious), retries: 0 });
    const stored = JSON.stringify(vault.get(`run:${r.objective}`));
    expect(stored.toLowerCase()).not.toContain(KEY.toLowerCase()); // neither case form survives
    expect(stored).not.toContain(KEY);
    expect(stored).toContain("clean.example.com");
  });
});
