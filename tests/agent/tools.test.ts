import { describe, it, expect } from "vitest";
import { OSINT_TOOLS, runTool } from "../../src/agent/tools.js";
import type { FetchLike } from "../../src/osint/types.js";

function fetchJson(payload: unknown): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => payload })) as unknown as FetchLike;
}
function fetchStatus(status: number): FetchLike {
  return (async () => ({ ok: false, status, json: async () => ({}) })) as unknown as FetchLike;
}

describe("OSINT_TOOLS definitions", () => {
  it("defines the domain + on-chain tools with prescriptive descriptions", () => {
    const names = OSINT_TOOLS.map((t) => t.name);
    // PRD-onchain: the 4 keyless domain/CT/BTC tools + the 4 cross-chain wallet tools.
    // A6: + dns_deep (SPF/DMARC) + typosquat_domains (lookalike generation), both keyless domain tools.
    expect(names).toEqual([
      "dns_lookup",
      "rdap_domain",
      "crtsh_subdomains",
      "btc_address",
      "tron_address",
      "solana_address",
      "ton_address",
      "ens_name",
      "dns_deep",
      "typosquat_domains",
      // restore-tool-belt (2026-06-24): keyless username presence sweep (GitHub + Keybase, CORS-verified).
      "username_sweep",
      // restore-tool-belt (2026-06-24): keyless analysis tools — email triage/headers, phone parse, OFAC screen.
      "email_triage",
      "email_headers",
      "phone_parse",
      "ofac_screen",
      "gravatar",
      // PRD-B agent-browser-forensics + tool-belt: the Worker-routed browser tools + the keyless/proxied belt.
      "page_navigate",
      "network_requests",
      "evaluate_script",
      // hydra-see-sites (2026-07-08): the light worker path — resolve a page's outbound destination link.
      "resolve_link",
      "reverse_dns",
      "asn_lookup",
      // hydra-reverse-ip (2026-07-09): keyless reverse-IP → co-hosted domains (companion to reverse_dns).
      "reverse_ip",
      "shodan_internetdb",
      "ripestat_network",
      "ip_guide",
      "ipwho_is",
      "stopforumspam_ip",
      "sans_isc_ip",
      "certspotter_issuances",
      "blockstream_address",
      "blockcypher_address",
      "blockscout_address",
      "github_user",
      "gitlab_user",
      "hackernews_user",
      "npm_user",
      "xposedornot_email",
      "hibp_breach_catalog",
      "disposable_email",
      "gleif_lei",
      "wikidata_entity",
      "vt_passive_dns",
      "greynoise_ip",
      "securitytrails_subdomains",
      "abuseipdb_ip",
      "pulsedive_indicator",
      "hunter_emails",
    ]);
    expect(names.length).toBeGreaterThanOrEqual(20); // PRD-B: the belt meets the parity floor
    for (const t of OSINT_TOOLS) {
      // every tool description carries a trigger condition (prescriptive — Opus 4.8 under-reaches without it)
      expect(t.description.toLowerCase()).toMatch(/call this (when|on|after|to|for)|resolve an ens name/);
    }
    // domain tools take `domain`, the chain tools take `address`, ENS takes `name`
    const domainTool = OSINT_TOOLS.find((t) => t.name === "dns_lookup")!;
    expect((domainTool.input_schema as { required: string[] }).required).toContain("domain");
    const btc = OSINT_TOOLS.find((t) => t.name === "btc_address")!;
    expect((btc.input_schema as { required: string[] }).required).toContain("address");
    const tron = OSINT_TOOLS.find((t) => t.name === "tron_address")!;
    expect((tron.input_schema as { required: string[] }).required).toContain("address");
    const ens = OSINT_TOOLS.find((t) => t.name === "ens_name")!;
    expect((ens.input_schema as { required: string[] }).required).toContain("name");
  });
});

describe("on-chain tool dispatch (tron/solana/ton/ens)", () => {
  it("ens_name dispatches on input.name and emits the resolved 0x wallet", async () => {
    const ensFetch = fetchJson({ address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", name: "vitalik.eth" });
    const out = await runTool("ens_name", { name: "vitalik.eth" }, { fetchImpl: ensFetch, retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.provider).toBe("ensideas");
    expect(out.entities[0]).toMatchObject({ type: "wallet", value: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" });
  });

  it("tron_address dispatches on input.address into a wallet tool_result", async () => {
    const tronFetch = fetchJson({ data: [{ balance: 5_000_000, assetV2: [], trc20: [] }] });
    const out = await runTool("tron_address", { address: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" }, { fetchImpl: tronFetch, retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.provider).toBe("trongrid");
    expect(out.entities[0].type).toBe("wallet");
  });

  it("a chain tool with a missing/empty param -> is_error (never fakes a wallet)", async () => {
    const out = await runTool("ton_address", { address: "" }, { retries: 0 });
    expect(out.is_error).toBe(true);
    expect(out.entities).toHaveLength(0);
  });
});

describe("btc_address on-chain tool dispatch (address param)", () => {
  const mempool = fetchJson({
    address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    chain_stats: { funded_txo_sum: 5_000_000_000, spent_txo_sum: 1_000_000_000, tx_count: 100 },
    mempool_stats: {},
  });

  it("dispatches on input.address into a wallet tool_result", async () => {
    const out = await runTool("btc_address", { address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" }, { fetchImpl: mempool, retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.provider).toBe("mempool.space");
    expect(out.entities[0]).toMatchObject({ type: "wallet" });
  });

  it("missing the address param -> is_error (wrong/empty param never fakes a wallet)", async () => {
    const out = await runTool("btc_address", { domain: "example.com" }, { fetchImpl: mempool, retries: 0 });
    expect(out.is_error).toBe(true);
    expect(JSON.parse(out.content).error).toContain("address");
  });

  it("a provider failure -> is_error (never an empty-success wallet)", async () => {
    const out = await runTool("btc_address", { address: "notanaddress" }, { fetchImpl: fetchStatus(400), retries: 0 });
    expect(out.is_error).toBe(true);
  });

  it("the domain tools still dispatch on input.domain (no regression)", async () => {
    const doh = fetchJson({ Status: 0, Answer: [{ name: "example.com", type: 1, data: "93.184.216.34" }] });
    const out = await runTool("dns_lookup", { domain: "example.com" }, { fetchImpl: doh, retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.provider).toBe("dns.google");
  });
});

describe("runTool dispatch", () => {
  it("dns_lookup returns typed entities + a non-error tool_result", async () => {
    const doh = fetchJson({ Status: 0, Answer: [{ name: "example.com", type: 1, data: "93.184.216.34" }] });
    const out = await runTool("dns_lookup", { domain: "example.com" }, { fetchImpl: doh, retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.provider).toBe("dns.google");
    expect(out.entities.some((e) => e.type === "ip" && e.value === "93.184.216.34")).toBe(true);
    expect(JSON.parse(out.content).entities.length).toBeGreaterThan(0);
  });

  it("rdap_domain returns registrar/registrant/nameserver entities", async () => {
    const rdap = fetchJson({
      ldhName: "EXAMPLE.COM",
      nameservers: [{ ldhName: "a.iana-servers.net" }],
      entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "ICANN"]]] }],
    });
    const out = await runTool("rdap_domain", { domain: "example.com" }, { fetchImpl: rdap, retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.entities.some((e) => e.type === "registrar" && e.value === "ICANN")).toBe(true);
  });
});

describe("runTool error handling (errors never masquerade as evidence)", () => {
  it("unknown tool -> is_error result, no throw", async () => {
    const out = await runTool("phonebook_lookup", { domain: "example.com" });
    expect(out.is_error).toBe(true);
    expect(JSON.parse(out.content).error).toContain("unknown tool");
    expect(out.entities).toEqual([]);
  });

  it("missing domain -> is_error result", async () => {
    const out = await runTool("dns_lookup", {});
    expect(out.is_error).toBe(true);
    expect(JSON.parse(out.content).error).toContain("domain");
  });

  it("a provider HTTP failure -> is_error result (bounded, no raw body)", async () => {
    const out = await runTool("crtsh_subdomains", { domain: "example.com" }, { fetchImpl: fetchStatus(502), retries: 0 });
    expect(out.is_error).toBe(true);
    expect(JSON.parse(out.content).error).toContain("502");
    expect(out.content.length).toBeLessThan(300);
  });
});

describe("runTool abort (the Stop button)", () => {
  it("an already-aborted signal stops before any attempt (AbortError propagates)", async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      runTool("rdap_domain", { domain: "example.com" }, { fetchImpl: fetchStatus(500), signal: ctrl.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });

  it("aborting during the retry backoff rejects cleanly (does not mask as is_error)", async () => {
    const ctrl = new AbortController();
    const failing = (async () => {
      throw new Error("network boom");
    }) as unknown as FetchLike;
    const p = runTool("rdap_domain", { domain: "example.com" }, { fetchImpl: failing, retries: 3, signal: ctrl.signal });
    ctrl.abort(); // fires while the first backoff sleep is pending
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
  });

  it("dns_lookup propagates abort instead of swallowing it per record type", async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      runTool("dns_lookup", { domain: "example.com" }, { fetchImpl: fetchStatus(500), signal: ctrl.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });
});

// PRD-B agent-browser-forensics + tool-belt: the Worker-routed + keyless pivots.
describe("PRD-B agent depth tools", () => {
  const WORKER = "https://kipi-proxy.example.workers.dev";

  it("page_navigate renders via the Worker and extracts IOCs from the evaluated page", async () => {
    const render = fetchJson({
      status: 200,
      finalUrl: "https://scam.example/claim",
      text: "Send to 0x1111111111111111111111111111111111111111 — payout host 9.9.9.9",
      html: "<html></html>",
      networkRequests: [],
    });
    const out = await runTool("page_navigate", { url: "https://scam.example/claim" }, { workerUrl: WORKER, fetchImpl: render });
    expect(out.is_error).toBe(false);
    const vals = out.entities.map((e) => e.value);
    expect(vals).toContain("0x1111111111111111111111111111111111111111"); // the wallet
    expect(vals).toContain("9.9.9.9"); // the payout host
    expect(out.infra).toBe(false); // page-scraped → a T2 lead, NOT infra-confirmed (gate corroborates)
  });

  it("network_requests returns the hosts the page contacted (the forensics)", async () => {
    const render = fetchJson({
      status: 200, finalUrl: "https://scam.example", text: "", html: "",
      networkRequests: ["https://drainer-backend.example/api", "https://cdn.kit.example/script.js"],
    });
    const out = await runTool("network_requests", { url: "https://scam.example" }, { workerUrl: WORKER, fetchImpl: render });
    const vals = out.entities.map((e) => e.value);
    expect(vals).toContain("drainer-backend.example");
    expect(vals).toContain("cdn.kit.example");
  });

  it("a browser/proxied tool errors GRACEFULLY (not throws) when no Worker URL is configured", async () => {
    const nav = await runTool("page_navigate", { url: "https://x.example" }, {}); // no workerUrl
    expect(nav.is_error).toBe(true);
    expect(nav.content.toLowerCase()).toContain("worker");
    const vt = await runTool("vt_passive_dns", { domain: "x.example" }, {});
    expect(vt.is_error).toBe(true);
  });

  it("codex C1: the browser render tools share ONE attribution source per page (no self-promotion)", async () => {
    const render = fetchJson({
      status: 200, finalUrl: "https://scam.example/a",
      text: "0x1111111111111111111111111111111111111111", html: "0x1111111111111111111111111111111111111111", networkRequests: [],
    });
    const nav = await runTool("page_navigate", { url: "https://scam.example/a" }, { workerUrl: WORKER, fetchImpl: render });
    const evalr = await runTool("evaluate_script", { url: "https://scam.example/a" }, { workerUrl: WORKER, fetchImpl: render });
    // same page rendered two ways = ONE source, not two corroborations (a fake wallet can't self-promote).
    expect(nav.provider).toBe(evalr.provider);
    expect(nav.provider).toContain("scam.example");
  });

  it("reverse_dns parses a DoH PTR answer (keyless, T1)", async () => {
    const doh = fetchJson({ Answer: [{ data: "host.example.com." }] });
    const out = await runTool("reverse_dns", { ip: "9.9.9.9" }, { fetchImpl: doh });
    expect(out.is_error).toBe(false);
    expect(out.entities.map((e) => e.value)).toContain("host.example.com");
    expect(out.infra).toBe(true); // a real published DNS record
    // NEGATIVE: a non-IP target is rejected before any fetch.
    const bad = await runTool("reverse_dns", { ip: "not-an-ip" }, { fetchImpl: doh });
    expect(bad.is_error).toBe(true);
  });
});
