import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import type { FetchLike } from "../../src/osint/types.js";
import { SessionError, setProviderKey, transformNode, availableTransforms } from "../../src/agent/session.js";

// nd-transform-core: a deterministic OSINT transform that returns a GATED, REDACTED InvestigateResult
// WITHOUT persisting. The queried node (self) never re-adds; counts are DERIVED via attributeFindings;
// availableTransforms validates the target kind. New symbols (negative self-test).

function cannedFetch(body: unknown): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => body }) as Response) as unknown as FetchLike;
}
const DNS_BODY = { Status: 0, Answer: [{ type: 1, data: "1.2.3.4" }] }; // A record for the queried domain
const SHODAN_BODY = { ip_str: "8.8.8.8", hostnames: ["dns.google"], asn: "AS15169", org: "Google" };

async function freshVault(providers: Record<string, string> = {}): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const v = await Vault.unlock(storage, "pw");
  for (const [id, key] of Object.entries(providers)) await setProviderKey(v, id, key);
  return v;
}

describe("nd-transform-core — transformNode + availableTransforms", () => {
  it("a free dns transform promotes the resolved infra entity with a DERIVED source count, no persist", async () => {
    const v = await freshVault();
    const before = v.keys().length;
    const r = await transformNode(v, "domain", "example.com", "dns", { fetchImpl: cannedFetch(DNS_BODY) });
    expect(r.promoted.map((f) => f.entity)).toContain("1.2.3.4");
    expect(r.promoted[0].source_count).toBe(1); // derived via attributeFindings, not forged
    expect(r.promoted[0].infra_source_count).toBe(1);
    expect(v.keys().length).toBe(before); // NO vault write
  });

  it("a keyed transform excludes the queried-self echo and promotes a related entity", async () => {
    const v = await freshVault({ shodan: "shdn-key-xyz" });
    const r = await transformNode(v, "ip", "8.8.8.8", "enrich:shodan", { fetchImpl: cannedFetch(SHODAN_BODY) });
    const all = [...r.promoted.map((f) => f.entity), ...r.leads.map((l) => l.finding.entity)];
    expect(all).not.toContain("8.8.8.8"); // self echo excluded (D3)
    expect(r.promoted.map((f) => f.entity)).toContain("dns.google"); // a related infra entity promotes
  });

  it("availableTransforms is value- and key-aware (D2)", async () => {
    const keyless = await freshVault();
    expect(availableTransforms(keyless, "domain", "example.com").map((t) => t.id)).toEqual(
      expect.arrayContaining(["dns", "rdap", "crtsh"]),
    );
    expect(availableTransforms(keyless, "ip", "8.8.8.8")).toEqual([]); // no keyless transform for an ip, no keys
    const keyed = await freshVault({ shodan: "k" });
    const ids = availableTransforms(keyed, "ip", "8.8.8.8").map((t) => t.id);
    expect(ids).toContain("enrich:shodan");
    // a malformed ip value offers no shodan transform (target validation, D2)
    expect(availableTransforms(keyed, "ip", "not-an-ip").map((t) => t.id)).not.toContain("enrich:shodan");
  });

  it("an unconfigured keyed transform throws a clean SessionError (no key/url)", async () => {
    const v = await freshVault();
    await expect(transformNode(v, "ip", "8.8.8.8", "enrich:shodan", { fetchImpl: cannedFetch(SHODAN_BODY) })).rejects.toBeInstanceOf(
      SessionError,
    );
  });

  it("a keyed-adapter HTTP error surfaces as a sanitized SessionError (no key/url)", async () => {
    const v = await freshVault({ shodan: "shdn-key-xyz" });
    // shodan throws on !res.ok; runEnrichTool turns it into an is_error outcome -> transformNode throws a
    // SANITIZED SessionError (never the raw "Shodan HTTP 500" / the key-bearing URL).
    const failFetch = (async () => ({ ok: false, status: 500, json: async () => ({}) }) as Response) as unknown as FetchLike;
    await expect(
      transformNode(v, "ip", "8.8.8.8", "enrich:shodan", { fetchImpl: failFetch, retries: 0 }),
    ).rejects.toBeInstanceOf(SessionError);
    await expect(
      transformNode(v, "ip", "8.8.8.8", "enrich:shodan", { fetchImpl: failFetch, retries: 0 }),
    ).rejects.toThrow(/transform returned no usable result/);
  });

  it("an empty adapter result resolves with no findings (not an error)", async () => {
    const v = await freshVault();
    const r = await transformNode(v, "domain", "example.com", "dns", { fetchImpl: cannedFetch({ Status: 0, Answer: [] }), retries: 0 });
    expect(r.promoted).toEqual([]);
    expect(r.leads).toEqual([]);
  });
});
