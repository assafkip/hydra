import { describe, it, expect } from "vitest";
import { generateTyposquats, typosquatDomains } from "../../src/osint/typosquat.js";
import { dnsDeep } from "../../src/osint/dns-deep.js";
import { ensName } from "../../src/osint/ens.js";
import { otxPassiveDns } from "../../src/osint/otx.js";
import { perplexitySearch } from "../../src/osint/perplexity.js";
import { OSINT_TOOLS, runTool, validateTarget } from "../../src/agent/tools.js";
import { ENRICH_PROVIDERS } from "../../src/osint/enrich.js";
import type { FetchLike } from "../../src/osint/types.js";

// A6: the browser-callable OSINT adapters ported from the Python enrich/osint_mcp suite. Each is
// node-safe via an injected fetchImpl (no network). Reproducers assert the parity behaviors the
// inventory named as dropped.

// route a fake fetch by a substring of the URL (and, for POST, ok:true JSON).
function fetchByUrl(routes: { match: string; payload: unknown; status?: number }[]): FetchLike {
  return (async (url: string) => {
    const r = routes.find((x) => url.includes(x.match));
    if (!r) return { ok: true, status: 200, json: async () => ({}) };
    return { ok: (r.status ?? 200) < 400, status: r.status ?? 200, json: async () => r.payload };
  }) as unknown as FetchLike;
}
function fetchJson(payload: unknown): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => payload })) as unknown as FetchLike;
}
const txt = (records: string[]): unknown => ({ Status: 0, Answer: records.map((data) => ({ type: 16, data: `"${data}"` })) });
const aRec = (): unknown => ({ Status: 0, Answer: [{ type: 1, data: "1.2.3.4" }] });

describe("A6 typosquat — lookalike generation + liveness (parity typosquat.py)", () => {
  it("generates the expected fuzzer families, deterministically, excluding the original", () => {
    const cands = generateTyposquats("binance.com");
    const values = cands.map((c) => c.candidate);
    expect(values).not.toContain("binance.com"); // the original is excluded
    expect(values).toContain("binance.net"); // tld-swap
    expect(values).toContain("bnance.com"); // omission
    expect(values).toContain("binnance.com"); // repetition
    expect(values.some((v) => v.includes("-"))).toBe(true); // hyphenation
    // deterministic: same input → same output
    expect(generateTyposquats("binance.com").map((c) => c.candidate)).toEqual(values);
  });

  it("emits ONLY DNS-live candidates as domain entities (T3→T1 gate)", async () => {
    // every candidate 'resolves' in this fake → all live; assert they come back as domain entities.
    const res = await typosquatDomains("evil-brand.com", { fetchImpl: fetchByUrl([{ match: "dns.google", payload: aRec() }]) });
    expect(res.tier).toBe("T1");
    expect(res.entities.length).toBeGreaterThan(0);
    expect(res.entities.every((e) => e.type === "domain")).toBe(true);
  });

  it("rejects a non-domain input", async () => {
    await expect(typosquatDomains("not-a-domain")).rejects.toThrow();
  });
});

describe("A6 dns_deep — SPF/DMARC parse (parity infra.py:271)", () => {
  it("parses SPF includes/ip4 + DMARC report domain into typed entities", async () => {
    const impl = fetchByUrl([
      { match: "name=evil.com&type=TXT", payload: txt(["v=spf1 include:_spf.sender.net ip4:9.9.9.9 -all"]) },
      { match: "name=_dmarc.evil.com&type=TXT", payload: txt(["v=DMARC1; p=reject; rua=mailto:reports@dmarc-agg.io"]) },
    ]);
    const res = await dnsDeep("evil.com", { fetchImpl: impl });
    expect(res.tier).toBe("T1");
    const vals = res.entities.map((e) => `${e.type}:${e.value}`);
    expect(vals).toContain("domain:_spf.sender.net"); // SPF include
    expect(vals).toContain("ip:9.9.9.9"); // SPF ip4
    expect(vals).toContain("domain:dmarc-agg.io"); // DMARC report domain
    expect(res.query).toContain("AXFR N/A"); // AXFR signed-blocked, surfaced not faked
  });

  it("a domain with no SPF/DMARC yields no entities (not an error)", async () => {
    const res = await dnsDeep("bare.com", { fetchImpl: fetchByUrl([{ match: "TXT", payload: { Status: 0, Answer: [] } }]) });
    expect(res.entities).toEqual([]);
  });
});

describe("A6 ENS — bidirectional resolution (parity ens.py both-directions)", () => {
  it("forward: a .eth name resolves to its wallet with the crosslink note", async () => {
    const res = await ensName("vitalik.eth", { fetchImpl: fetchJson({ address: "0x" + "d".repeat(40), name: "vitalik.eth" }) });
    expect(res.entities[0].type).toBe("wallet");
    expect(res.entities[0].note).toContain("vitalik.eth");
    expect(res.entities[0].note).toContain("↔");
  });

  it("reverse: a 0x address resolves to its primary .eth name (the half the web lacked)", async () => {
    const addr = "0x" + "a".repeat(40);
    const res = await ensName(addr, { fetchImpl: fetchJson({ address: addr, name: "operator.eth" }) });
    expect(res.entities[0].value).toBe(addr);
    expect(res.entities[0].note).toContain("operator.eth"); // the reverse crosslink
  });

  it("rejects a non-name/non-address input", async () => {
    await expect(ensName("just text")).rejects.toThrow();
  });
});

describe("A6 OTX — campaign/malware context (parity otx.py)", () => {
  it("surfaces pulse campaign + malware context alongside passive DNS", async () => {
    const impl = fetchByUrl([
      { match: "/passive_dns", payload: { passive_dns: [{ hostname: "evil.example.com" }] } },
      {
        match: "/general",
        payload: { pulse_info: { count: 1, pulses: [{ name: "FIFA Phish Campaign", malware_families: [{ display_name: "AgentTesla" }], indicators: [{ type: "domain", indicator: "c2.evil.io" }] }] } },
      },
    ]);
    const res = await otxPassiveDns("evil.example.com", "fake-key", { fetchImpl: impl });
    expect(res.query).toContain("FIFA Phish Campaign"); // campaign name
    expect(res.query).toContain("AgentTesla"); // malware family
    const vals = res.entities.map((e) => e.value);
    expect(vals).toContain("evil.example.com"); // passive DNS preserved
    expect(vals).toContain("c2.evil.io"); // pulse indicator
  });

  it("a general-endpoint failure does not sink the passive-DNS result (best-effort context)", async () => {
    const impl = fetchByUrl([
      { match: "/passive_dns", payload: { passive_dns: [{ hostname: "x.example.com" }] } },
      { match: "/general", payload: {}, status: 500 },
    ]);
    const res = await otxPassiveDns("x.example.com", "fake-key", { fetchImpl: impl });
    expect(res.entities.map((e) => e.value)).toContain("x.example.com");
  });
});

describe("A6 Perplexity — web-search T3 leads (parity osint_mcp, case-031 D2)", () => {
  it("returns the answer + surfaces named domains/IPs as T3 LEAD entities", async () => {
    const payload = { choices: [{ message: { content: "The scam used scam-payout.io hosted on 5.5.5.5." } }] };
    const res = await perplexitySearch("who is behind scam-payout.io", "fake-key", { fetchImpl: fetchJson(payload) });
    expect(res.tier).toBe("T3"); // a search summary is never citable
    const vals = res.entities.map((e) => e.value);
    expect(vals).toContain("scam-payout.io");
    expect(vals).toContain("5.5.5.5");
    expect(res.entities[0].note).toContain("T3 lead");
  });

  it("rejects an empty query", async () => {
    await expect(perplexitySearch("", "k")).rejects.toThrow();
  });
});

describe("A6 wiring — the new tools are registered + dispatchable", () => {
  it("dns_deep + typosquat_domains are agent tools AND run through runTool", async () => {
    const names = OSINT_TOOLS.map((t) => t.name);
    expect(names).toContain("dns_deep");
    expect(names).toContain("typosquat_domains");
    const out = await runTool("dns_deep", { domain: "evil.com" }, { fetchImpl: fetchByUrl([{ match: "TXT", payload: txt(["v=spf1 ip4:1.1.1.1 -all"]) }]) });
    expect(out.is_error).toBe(false);
    expect(out.entities.some((e) => e.value === "1.1.1.1")).toBe(true);
  });

  it("perplexity is a registered enrich provider taking a free-text query", () => {
    const pplx = ENRICH_PROVIDERS.find((p) => p.id === "perplexity");
    expect(pplx).toBeDefined();
    expect(pplx!.targets).toEqual(["query"]);
    expect(pplx!.infra).toBe(false); // T3 search, never infra-corroborating
    expect(validateTarget("query", "who owns evil.com")).toBe(true);
    expect(validateTarget("query", "")).toBe(false);
  });
});
