import { describe, it, expect } from "vitest";
import { shodanInternetDb } from "../../src/osint/shodan-internetdb.js";
import { ripestatNetworkInfo } from "../../src/osint/ripestat.js";
import { ipGuideLookup } from "../../src/osint/ip-guide.js";
import { ipWhoIsLookup } from "../../src/osint/ipwho-is.js";
import { stopForumSpamLookup } from "../../src/osint/stopforumspam.js";
import { sansIscLookup } from "../../src/osint/sans-isc.js";
import type { FetchLike } from "../../src/osint/types.js";

const IP = "8.8.8.8";

// shapes captured live 2026-07-09 from each provider's real response.
function fetchJson(payload: unknown, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, json: async () => payload })) as unknown as FetchLike;
}

describe("shodanInternetDb (internetdb.shodan.io)", () => {
  it("emits hostnames as domain pivots + ports/CVEs in the summary (T1)", async () => {
    const impl = fetchJson({ hostnames: ["dns.google"], ip: IP, ports: [53, 443], tags: [], vulns: ["CVE-2021-1234"] });
    const r = await shodanInternetDb(IP, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("shodan-internetdb");
    expect(r.tier).toBe("T1");
    expect(r.entities).toHaveLength(1);
    expect(r.entities[0]).toMatchObject({ type: "domain", value: "dns.google" });
    expect(r.summary).toContain("open ports: 53, 443");
    expect(r.summary).toContain("CVEs: CVE-2021-1234");
  });
  it("treats a 404 as an empty answer, not an error", async () => {
    const r = await shodanInternetDb(IP, { fetchImpl: fetchJson({}, 404), retries: 0 });
    expect(r.entities).toHaveLength(0);
  });
});

describe("hostile-response hardening (codex adversarial finding-1..4)", () => {
  it("shodanInternetDb rejects non-domain hostnames and caps a huge list", async () => {
    const hostnames = ["dns.google", "not a domain!!", "javascript:alert(1)", ...Array.from({ length: 500 }, (_, i) => `h${i}.evil.test`)];
    const r = await shodanInternetDb(IP, { fetchImpl: fetchJson({ hostnames, ports: [] }), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(100); // MAX_ENRICH_RESULTS cap
    expect(r.entities.every((e) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(e.value))).toBe(true); // no junk admitted
    expect(r.entities.some((e) => e.value === "not a domain!!")).toBe(false);
  });
  it("ipWhoIsLookup drops a junk connection domain", async () => {
    const impl = fetchJson({ success: true, connection: { asn: 15169, domain: "not a domain" } });
    const r = await ipWhoIsLookup(IP, { fetchImpl: impl, retries: 0 });
    expect(r.entities.some((e) => e.type === "domain")).toBe(false);
    expect(r.entities.some((e) => e.value === "AS15169")).toBe(true);
  });
  it("ripestatNetworkInfo caps a huge asns list", async () => {
    const asns = Array.from({ length: 400 }, (_, i) => String(1000 + i));
    const r = await ripestatNetworkInfo(IP, { fetchImpl: fetchJson({ data: { asns, prefix: "8.0.0.0/8" } }), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(100);
  });
});

describe("ripestatNetworkInfo (stat.ripe.net)", () => {
  it("emits announcing ASN(s) as asn pivots + prefix summary (T1)", async () => {
    const impl = fetchJson({ data: { asns: ["15169"], prefix: "8.8.8.0/24" } });
    const r = await ripestatNetworkInfo(IP, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("ripestat");
    expect(r.tier).toBe("T1");
    expect(r.entities[0]).toMatchObject({ type: "asn", value: "AS15169" });
    expect(r.summary).toContain("8.8.8.0/24");
  });
});

describe("ipGuideLookup (ip.guide)", () => {
  it("emits the ASN pivot + operator/geo summary (T1)", async () => {
    const impl = fetchJson({
      network: { cidr: "8.8.8.0/24", autonomous_system: { asn: 15169, name: "GOOGLE", organization: "Google LLC" } },
      location: { city: null, country: "United States" },
    });
    const r = await ipGuideLookup(IP, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("ip-guide");
    expect(r.entities[0]).toMatchObject({ type: "asn", value: "AS15169" });
    expect(r.summary).toContain("Google LLC");
  });
});

describe("ipWhoIsLookup (ipwho.is)", () => {
  it("emits ASN + connection-domain pivots and honors success:false (T1)", async () => {
    const impl = fetchJson({
      success: true,
      city: "Mountain View",
      country: "United States",
      connection: { asn: 15169, org: "Google LLC", isp: "Google", domain: "google.com" },
    });
    const r = await ipWhoIsLookup(IP, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("ipwho-is");
    expect(r.entities.map((e) => `${e.type}:${e.value}`)).toEqual(["asn:AS15169", "domain:google.com"]);
    await expect(ipWhoIsLookup(IP, { fetchImpl: fetchJson({ success: false, message: "reserved range" }), retries: 0 })).rejects.toThrow(
      /reserved range/,
    );
  });
});

describe("reputation feeds are T3 summary-only (no gate-inflating entities)", () => {
  it("stopForumSpam reports frequency as summary, emits no entity (T3)", async () => {
    const impl = fetchJson({ success: 1, ip: { value: IP, frequency: 0, appears: 0, country: "us" } });
    const r = await stopForumSpamLookup(IP, { fetchImpl: impl, retries: 0 });
    expect(r.tier).toBe("T3");
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("no spam reports");
  });
  it("sansIsc reports counts + threat feeds as summary, emits no entity (T3)", async () => {
    const impl = fetchJson({ ip: { count: 5, attacks: 2, comment: "scanner", threatfeeds: { miner: {}, myip: {} } } });
    const r = await sansIscLookup(IP, { fetchImpl: impl, retries: 0 });
    expect(r.tier).toBe("T3");
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("threat feeds: miner, myip");
  });
});
