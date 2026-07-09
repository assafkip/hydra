import { describe, it, expect } from "vitest";
import { certspotterIssuances } from "../../src/osint/certspotter.js";
import { blockstreamAddress } from "../../src/osint/blockstream.js";
import { blockcypherAddress } from "../../src/osint/blockcypher.js";
import { blockscoutAddress } from "../../src/osint/blockscout.js";
import type { FetchLike } from "../../src/osint/types.js";

// Shapes captured live 2026-07-09 from each provider's real response.
function fetchJson(payload: unknown, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, json: async () => payload })) as unknown as FetchLike;
}

describe("certspotterIssuances (api.certspotter.com)", () => {
  it("emits dns_names as subdomain/domain pivots + issuing CA in summary (T1)", async () => {
    const impl = fetchJson([
      { dns_names: ["example.com", "www.example.com", "*.mail.example.com"], issuer: { friendly_name: "Sectigo" } },
      { dns_names: ["example.com"], issuer: { friendly_name: "Let's Encrypt" } },
    ]);
    const r = await certspotterIssuances("example.com", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("certspotter");
    expect(r.tier).toBe("T1");
    const byKey = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(byKey).toContain("domain:example.com");
    expect(byKey).toContain("subdomain:www.example.com");
    expect(byKey).toContain("subdomain:mail.example.com"); // wildcard stripped
    expect(r.summary).toContain("Sectigo");
    expect(r.summary).toContain("Let's Encrypt");
  });
  it("treats a 404 as an empty answer, not an error", async () => {
    const r = await certspotterIssuances("nope.test", { fetchImpl: fetchJson([], 404), retries: 0 });
    expect(r.entities).toHaveLength(0);
  });
  it("rejects junk hostnames and caps a huge dns_names list (hostile-response hardening)", async () => {
    const dns_names = ["good.example.com", "not a domain!!", ...Array.from({ length: 500 }, (_, i) => `h${i}.example.com`)];
    const r = await certspotterIssuances("example.com", { fetchImpl: fetchJson([{ dns_names }]), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(100); // MAX_ENRICH_RESULTS cap
    expect(r.entities.some((e) => e.value === "not a domain!!")).toBe(false);
  });
  it("DROPS out-of-scope SANs — a hostile issuance cannot inject an unrelated pivot (finding-4)", async () => {
    const impl = fetchJson([{ dns_names: ["example.com", "www.example.com", "bank.com", "evil.attacker.test"] }]);
    const r = await certspotterIssuances("example.com", { fetchImpl: impl, retries: 0 });
    const values = r.entities.map((e) => e.value);
    expect(values).toContain("example.com");
    expect(values).toContain("www.example.com");
    expect(values).not.toContain("bank.com"); // out-of-scope, dropped
    expect(values).not.toContain("evil.attacker.test");
  });
  it("throws on a non-array 200 body instead of a silent empty-success (finding-5)", async () => {
    await expect(certspotterIssuances("example.com", { fetchImpl: fetchJson({ error: "rate limited" }), retries: 0 })).rejects.toThrow(
      /unexpected response shape/,
    );
  });
});

describe("blockstreamAddress (blockstream.info) — 2nd independent BTC source", () => {
  it("emits the wallet with received/balance/tx note (T1)", async () => {
    const impl = fetchJson({
      address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      chain_stats: { funded_txo_sum: 5722278291, spent_txo_sum: 0, tx_count: 63436 },
      mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 0 },
    });
    const r = await blockstreamAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("blockstream");
    expect(r.tier).toBe("T1");
    expect(r.entities).toHaveLength(1);
    expect(r.entities[0]).toMatchObject({ type: "wallet" });
    expect(r.entities[0].note).toContain("63436 txs");
    expect(r.entities[0].note).toContain("57.22278291 BTC");
  });
  it("throws on a shape without chain_stats (never a fake wallet)", async () => {
    await expect(blockstreamAddress("bad", { fetchImpl: fetchJson({ error: "invalid" }), retries: 0 })).rejects.toThrow(/unexpected response shape/);
  });
  it("rejects a response whose echoed address does not match the query (response-substitution, finding-1)", async () => {
    const impl = fetchJson({ address: "1SomeOtherWalletEntirely", chain_stats: { funded_txo_sum: 1, spent_txo_sum: 0, tx_count: 1 } });
    await expect(blockstreamAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", { fetchImpl: impl, retries: 0 })).rejects.toThrow(/does not match the query/);
  });
});

describe("blockcypherAddress (api.blockcypher.com) — 3rd independent BTC source", () => {
  it("emits the wallet with pre-summed balance/received/tx note (T1)", async () => {
    const impl = fetchJson({
      address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      total_received: 10723313025,
      total_sent: 0,
      final_balance: 10723313025,
      final_n_tx: 63452,
    });
    const r = await blockcypherAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("blockcypher");
    expect(r.tier).toBe("T1");
    expect(r.entities[0].note).toContain("63452 txs");
    expect(r.entities[0].note).toContain("107.23313025 BTC");
  });
  it("surfaces a 429 rate-limit as an error, not a fake wallet", async () => {
    await expect(blockcypherAddress("x", { fetchImpl: fetchJson({}, 429), retries: 0 })).rejects.toThrow(/rate-limited/);
  });
  it("rejects a response whose echoed address does not match the query (response-substitution, finding-2)", async () => {
    const impl = fetchJson({ address: "1DifferentWallet", total_received: 1, final_balance: 1, final_n_tx: 1 });
    await expect(blockcypherAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", { fetchImpl: impl, retries: 0 })).rejects.toThrow(/does not match the query/);
  });
});

describe("blockscoutAddress (eth.blockscout.com)", () => {
  it("emits the wallet with ENS + contract + balance labels (T1), BigInt-safe wei", async () => {
    const impl = fetchJson({
      hash: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      coin_balance: "6669114962512595915",
      ens_domain_name: "vitalik.eth",
      is_contract: true,
      is_verified: true,
      is_scam: false,
    });
    const r = await blockscoutAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("blockscout");
    expect(r.tier).toBe("T1");
    expect(r.entities[0]).toMatchObject({ type: "wallet", value: "0xd8da6bf26964af9d7eed9e03e53415d37aa96045" });
    expect(r.entities[0].note).toContain("6.669114 ETH");
    expect(r.entities[0].note).toContain("contract");
    // provider-asserted labels are explicitly attributed, not presented as on-chain fact (finding-6)
    expect(r.entities[0].note).toContain("blockscout-asserted: verified-source, ENS: vitalik.eth");
  });
  it("attributes a scam flag to blockscout, never as an on-chain fact (finding-6)", async () => {
    const impl = fetchJson({ hash: "0xABC", coin_balance: "0", is_scam: true });
    const r = await blockscoutAddress("0xabc", { fetchImpl: impl, retries: 0 });
    expect(r.entities[0].note).toContain("blockscout-asserted: is_scam");
  });
  it("rejects a response whose echoed hash does not match the query (response-substitution, finding-3)", async () => {
    const impl = fetchJson({ hash: "0x" + "9".repeat(40), coin_balance: "0" });
    await expect(blockscoutAddress("0x" + "1".repeat(40), { fetchImpl: impl, retries: 0 })).rejects.toThrow(/does not match the query/);
  });
  it("throws on a 404 (never a fake wallet)", async () => {
    await expect(blockscoutAddress("0xabc", { fetchImpl: fetchJson({}, 404), retries: 0 })).rejects.toThrow(/not found/);
  });
});
