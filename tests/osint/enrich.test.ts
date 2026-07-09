import { describe, it, expect } from "vitest";
import { shodanHost } from "../../src/osint/shodan";
import { censysHost } from "../../src/osint/censys";
import { otxPassiveDns } from "../../src/osint/otx";
import { etherscanAddress } from "../../src/osint/etherscan";
import { urlscanSearch } from "../../src/osint/urlscan";
import { ipinfoIp } from "../../src/osint/ipinfo";
import { ENRICH_PROVIDERS, BLOCKED_PROVIDERS, enrichProvider, isBlockedProvider } from "../../src/osint/enrich";
import { base64, type FetchLike } from "../../src/osint/types";

const KEY = "SECRET-enrich-key-9k2"; // distinctive so the no-leak assertions are unambiguous

interface Captured {
  url: string;
  headers: Record<string, string>;
}

// A fakeFetch that records the request (url + headers) so a test can prove WHERE the key went.
function capturing(response: unknown, init: { ok?: boolean; status?: number } = {}): {
  fetchImpl: FetchLike;
  calls: Captured[];
} {
  const calls: Captured[] = [];
  const fetchImpl = (async (url: string, req?: RequestInit) => {
    calls.push({ url: String(url), headers: (req?.headers as Record<string, string>) ?? {} });
    return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => response };
  }) as unknown as FetchLike;
  return { fetchImpl, calls };
}

describe("enrich adapters parse canned fixtures + place the key correctly (no network)", () => {
  it("Shodan: ip/domain/asn entities; the key is in the ?key= query slot", async () => {
    const { fetchImpl, calls } = capturing({
      ip_str: "8.8.8.8",
      hostnames: ["dns.google"],
      domains: ["google.com"],
      asn: "AS15169",
      org: "Google LLC",
      ports: [443, 53],
    });
    const r = await shodanHost("8.8.8.8", KEY, { fetchImpl, retries: 0 });
    expect(r.provider).toBe("shodan");
    expect(calls[0].url).toContain(`key=${encodeURIComponent(KEY)}`); // disclosed flow: query-param key
    expect(r.entities).toContainEqual({ type: "domain", value: "dns.google", note: "Shodan hostname" });
    expect(r.entities).toContainEqual({ type: "domain", value: "google.com", note: "Shodan domain" });
    expect(r.entities.some((e) => e.type === "asn" && e.value === "AS15169")).toBe(true);
    expect(r.entities.some((e) => e.type === "ip" && e.value === "8.8.8.8")).toBe(true);
  });

  it("Censys: dns names + asn; the key is base64(id:secret) in the Authorization header", async () => {
    const { fetchImpl, calls } = capturing({
      result: {
        ip: "8.8.8.8",
        names: ["dns.google"],
        autonomous_system: { asn: 15169, name: "GOOGLE" },
        services: [{ port: 443 }],
      },
    });
    const cred = `API_ID:${KEY}`;
    const r = await censysHost("8.8.8.8", cred, { fetchImpl, retries: 0 });
    expect(calls[0].headers.authorization).toBe(`Basic ${base64(cred)}`); // header auth, base64
    expect(calls[0].url).not.toContain(KEY); // never in the URL
    expect(r.entities).toContainEqual({ type: "domain", value: "dns.google", note: "Censys name" });
    expect(r.entities.some((e) => e.type === "asn" && e.value === "AS15169")).toBe(true);
  });

  it("Censys: a malformed key (no colon) throws a fixed message, never echoing the value", async () => {
    const { fetchImpl } = capturing({ result: {} });
    await expect(censysHost("8.8.8.8", KEY, { fetchImpl, retries: 0 })).rejects.toThrow('Censys key must be "API ID:Secret"');
  });

  it("OTX: passive DNS -> domain + ip; the key is in the X-OTX-API-KEY header; domain vs IPv4 path", async () => {
    const fixture = { passive_dns: [{ hostname: "sub.example.com", address: "1.2.3.4", record_type: "A" }] };
    const dom = capturing(fixture);
    const rd = await otxPassiveDns("example.com", KEY, { fetchImpl: dom.fetchImpl, retries: 0 });
    expect(dom.calls[0].headers["x-otx-api-key"]).toBe(KEY);
    expect(dom.calls[0].url).toContain("/domain/");
    expect(rd.entities).toContainEqual({ type: "domain", value: "sub.example.com", note: "OTX passive DNS" });
    expect(rd.entities).toContainEqual({ type: "ip", value: "1.2.3.4", note: "OTX passive DNS" });

    const ip = capturing(fixture);
    await otxPassiveDns("1.2.3.4", KEY, { fetchImpl: ip.fetchImpl, retries: 0 });
    expect(ip.calls[0].url).toContain("/IPv4/"); // an IP target hits the IPv4 endpoint
  });

  it("Etherscan: target wallet + distinct counterparties; the key is in ?apikey=", async () => {
    const self = "0x" + "c".repeat(40);
    const from = "0x" + "a".repeat(40);
    const to = "0x" + "b".repeat(40);
    const { fetchImpl, calls } = capturing({ status: "1", message: "OK", result: [{ from, to }] });
    const r = await etherscanAddress(self, KEY, { fetchImpl, retries: 0 });
    expect(calls[0].url).toContain(`apikey=${encodeURIComponent(KEY)}`);
    // V2 upgrade (finding-2): the unified endpoint with a default mainnet chainid — the existing keyed path
    // is unchanged in behavior, just routed through /v2/api?chainid=1.
    expect(calls[0].url).toContain("/v2/api?chainid=1");
    expect(r.tier).toBe("T1"); // on-chain
    const wallets = r.entities.filter((e) => e.type === "wallet").map((e) => e.value).sort();
    expect(wallets).toEqual([from, self, to].sort());
  });

  it("Etherscan V2: an explicit chainid routes to that chain (multi-chain via one key)", async () => {
    const self = "0x" + "f".repeat(40);
    const { fetchImpl, calls } = capturing({ status: "1", message: "OK", result: [] });
    await etherscanAddress(self, KEY, { fetchImpl, retries: 0 }, 56); // BSC
    expect(calls[0].url).toContain("chainid=56");
  });

  it("Etherscan: an empty result array is no-tx (a wallet, not an error)", async () => {
    const self = "0x" + "d".repeat(40);
    const { fetchImpl } = capturing({ status: "0", message: "No transactions found", result: [] });
    const r = await etherscanAddress(self, KEY, { fetchImpl, retries: 0 });
    expect(r.entities).toEqual([{ type: "wallet", value: self, note: "Etherscan: 0 recent tx(s)" }]);
  });

  it("Etherscan: a string result (API error / rate limit) throws on the message, never the key", async () => {
    const self = "0x" + "e".repeat(40);
    const { fetchImpl } = capturing({ status: "0", message: "NOTOK", result: "Invalid API Key" });
    await expect(etherscanAddress(self, KEY, { fetchImpl, retries: 0 })).rejects.toThrow("Etherscan error (NOTOK)");
  });

  it("urlscan: page domain/ip/url; the key is in the API-Key header; a non-http url is dropped (D8)", async () => {
    const { fetchImpl, calls } = capturing({
      results: [
        { page: { domain: "example.com", ip: "1.2.3.4", url: "https://example.com/x" } },
        { page: { domain: "evil.test", url: "javascript:alert(1)" } }, // not http(s) -> never a url entity
      ],
    });
    const r = await urlscanSearch("example.com", KEY, { fetchImpl, retries: 0 });
    expect(calls[0].headers["api-key"]).toBe(KEY);
    expect(calls[0].url).not.toContain(KEY);
    expect(r.entities.some((e) => e.type === "url" && e.value === "https://example.com/x")).toBe(true);
    expect(r.entities.some((e) => e.type === "ip" && e.value === "1.2.3.4")).toBe(true);
    expect(r.entities.some((e) => e.type === "url")).toBe(true);
    expect(r.entities.filter((e) => e.type === "url")).toHaveLength(1); // the javascript: url was dropped
  });

  it("IPinfo: hostname + asn parsed from org; the token is in the Authorization header", async () => {
    const { fetchImpl, calls } = capturing({
      ip: "8.8.8.8",
      hostname: "dns.google",
      org: "AS15169 Google LLC",
      city: "Mountain View",
      country: "US",
    });
    const r = await ipinfoIp("8.8.8.8", KEY, { fetchImpl, retries: 0 });
    expect(calls[0].headers.authorization).toBe(`Bearer ${KEY}`);
    expect(calls[0].url).not.toContain(KEY);
    expect(r.entities).toContainEqual({ type: "domain", value: "dns.google", note: "IPinfo hostname" });
    expect(r.entities.some((e) => e.type === "asn" && e.value === "AS15169")).toBe(true);
  });
});

describe("enrich adapters never leak the key in a thrown error (401 fixture)", () => {
  // Every provider's adapter, driven through the registry, must throw on a 401 with a message that
  // carries the HTTP status but NEVER the key string (codex: key hygiene through error paths).
  for (const p of ENRICH_PROVIDERS) {
    it(`${p.id}: a 401 throws status, not the key`, async () => {
      // Censys needs a colon-bearing credential to reach the fetch (else it throws on parse, which
      // is also key-free). Use an "id:KEY" form so the 401 path is exercised for it too.
      const cred = p.id === "censys" ? `API_ID:${KEY}` : KEY;
      const { fetchImpl } = capturing(null, { ok: false, status: 401 });
      let threw = false;
      try {
        await p.run(p.probe, cred, { fetchImpl, retries: 0 });
      } catch (e) {
        threw = true;
        const msg = e instanceof Error ? e.message : String(e);
        expect(msg).not.toContain(KEY); // the key never reaches an error string
        expect(msg).toContain("401");
      }
      expect(threw).toBe(true);
    });
  }
});

describe("enrich registry", () => {
  it("exposes the CORS-open providers (+ A6 perplexity + restore-tool-belt jina + Tavily) + the blocked holdouts", () => {
    expect(ENRICH_PROVIDERS.map((p) => p.id).sort()).toEqual(
      // A6: perplexity (free-text web-search). restore-tool-belt: jina (URL reader). hydra-osint-provider-
      // inputs (2026-07-08): tavily (agent web-search) — re-tested LIVE and its ACTUAL POST response now
      // carries ACAO (they fixed the CORS that once put it in the proxy tier), so it is CORS-open/direct now.
      // finding-5: github + gitlab are the keyed BYO-token variants of the free identity tools (username target).
      ["censys", "etherscan", "github", "gitlab", "ipinfo", "jina", "otx", "perplexity", "shodan", "tavily", "urlscan"],
    );
    expect(BLOCKED_PROVIDERS.map((p) => p.id)).toContain("virustotal");
    expect(BLOCKED_PROVIDERS.map((p) => p.id)).toContain("exa"); // hydra-osint-provider-inputs: POST-proxy provider
    expect(BLOCKED_PROVIDERS).toHaveLength(7);
  });

  it("enrichProvider + isBlockedProvider resolve correctly", () => {
    expect(enrichProvider("shodan")?.label).toBe("Shodan");
    expect(enrichProvider("nope")).toBeUndefined();
    expect(isBlockedProvider("virustotal")).toBe(true);
    expect(isBlockedProvider("shodan")).toBe(false);
  });

  it("every provider origin is a fixed https origin (no per-user/dynamic/wildcard)", () => {
    for (const p of ENRICH_PROVIDERS) {
      expect(p.origin).toMatch(/^https:\/\/[a-z0-9.]+$/);
      expect(p.origin).not.toContain("*");
    }
  });
});
