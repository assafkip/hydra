import { describe, it, expect } from "vitest";
import { btcAddress } from "../../src/osint/mempool.js";
import { tronAddress } from "../../src/osint/tron.js";
import { solanaAddress } from "../../src/osint/solana.js";
import { tonAddress } from "../../src/osint/ton.js";
import { ensName } from "../../src/osint/ens.js";
import { promotionGate, type Finding } from "../../src/agent/gate.js";
import type { FetchLike } from "../../src/osint/types.js";

const ADDR = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";

// shape verified live 2026-06-17
function fetchJson(payload: unknown): FetchLike {
  return (async () => ({ ok: true, status: 200, json: async () => payload })) as unknown as FetchLike;
}
function fetchStatus(status: number): FetchLike {
  return (async () => ({ ok: false, status, json: async () => ({}) })) as unknown as FetchLike;
}
// Solana needs two RPC calls (getBalance, getSignaturesForAddress) — route the canned body by method.
function fetchByMethod(byMethod: Record<string, unknown>): FetchLike {
  return (async (_url: string, init?: { body?: string }) => {
    const method = init?.body ? (JSON.parse(init.body) as { method: string }).method : "";
    return { ok: true, status: 200, json: async () => byMethod[method] };
  }) as unknown as FetchLike;
}

describe("btcAddress (mempool.space)", () => {
  it("parses the verified shape into a single T1 wallet entity with stats", async () => {
    const impl = fetchJson({
      address: ADDR,
      chain_stats: { funded_txo_sum: 5_000_000_000, spent_txo_sum: 1_000_000_000, tx_count: 100 },
      mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0, tx_count: 2 },
    });
    const r = await btcAddress(ADDR, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("mempool.space");
    expect(r.tier).toBe("T1");
    expect(r.entities).toHaveLength(1);
    const w = r.entities[0];
    expect(w.type).toBe("wallet");
    expect(w.value).toBe(ADDR);
    expect(w.note).toContain("102 txs"); // 100 + 2
    expect(w.note).toContain("50.00000000 BTC"); // received 5e9 sats
    expect(w.note).toContain("balance 40.00000000 BTC"); // (5e9 - 1e9) sats
  });

  it("labels an UNSAFE satoshi value '(very large)' instead of rounding", async () => {
    const impl = fetchJson({
      address: ADDR,
      chain_stats: { funded_txo_sum: 9_007_199_254_740_993, spent_txo_sum: 0, tx_count: 1 },
      mempool_stats: {},
    });
    const r = await btcAddress(ADDR, { fetchImpl: impl, retries: 0 });
    expect(r.entities[0].note).toContain("(very large)");
  });

  it("THROWS (=> is_error upstream) on a non-OK status, a non-object body, or missing chain_stats", async () => {
    await expect(btcAddress(ADDR, { fetchImpl: fetchStatus(400), retries: 0 })).rejects.toThrow(/400/);
    await expect(btcAddress(ADDR, { fetchImpl: fetchJson("not json"), retries: 0 })).rejects.toThrow(/shape/);
    await expect(btcAddress(ADDR, { fetchImpl: fetchJson({ address: ADDR }), retries: 0 })).rejects.toThrow(/shape/);
  });

  it("propagates an abort (the Stop button)", async () => {
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(btcAddress(ADDR, { fetchImpl: fetchStatus(500), signal: ctrl.signal })).rejects.toMatchObject({
      name: "AbortError",
    });
  });
});

// ---- PRD-onchain: the 4 cross-chain keyless adapters (shapes verified live 2026-06-18) ----

const TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"; // 34-char base58 T-address
const SOL = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"; // base58 pubkey
const TON_ADDR = "EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N"; // EQ + 46

describe("tronAddress (TronGrid)", () => {
  it("parses an active account into a T1 wallet with a TRX + token note", async () => {
    const impl = fetchJson({ data: [{ balance: 1_075_891_320_085, assetV2: [{}, {}], trc20: [{}] }] });
    const r = await tronAddress(TRON, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("trongrid");
    expect(r.tier).toBe("T1");
    expect(r.entities[0]).toMatchObject({ type: "wallet", value: TRON });
    expect(r.entities[0].note).toContain("1075891.320085 TRX");
    expect(r.entities[0].note).toContain("2 TRC10 + 1 TRC20");
  });
  it("emits a no-account wallet (NOT an error) for a valid-but-inactive address (data: [])", async () => {
    const r = await tronAddress(TRON, { fetchImpl: fetchJson({ data: [] }), retries: 0 });
    expect(r.entities).toHaveLength(1);
    expect(r.entities[0].note).toContain("no on-chain account");
  });
  it("THROWS on a non-ok HTTP, an unexpected shape, or a non-T address", async () => {
    await expect(tronAddress(TRON, { fetchImpl: fetchStatus(429), retries: 0 })).rejects.toThrow(/429/);
    await expect(tronAddress(TRON, { fetchImpl: fetchJson({ nope: 1 }), retries: 0 })).rejects.toThrow(/shape/);
    await expect(tronAddress("example.com", { fetchImpl: fetchJson({ data: [] }), retries: 0 })).rejects.toThrow(/T-address/);
  });
});

describe("solanaAddress (publicnode JSON-RPC)", () => {
  it("parses getBalance + signatures into a T1 wallet note", async () => {
    const impl = fetchByMethod({
      getBalance: { jsonrpc: "2.0", result: { context: { slot: 1 }, value: 2_500_000_000 }, id: 1 },
      getSignaturesForAddress: { jsonrpc: "2.0", result: [{ signature: "a" }, { signature: "b" }], id: 1 },
    });
    const r = await solanaAddress(SOL, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("solana");
    expect(r.entities[0]).toMatchObject({ type: "wallet", value: SOL });
    expect(r.entities[0].note).toContain("2.500000000 SOL");
    expect(r.entities[0].note).toContain("2 recent signatures");
  });
  it("emits a zero-activity wallet (NOT an error) for an inactive address", async () => {
    const impl = fetchByMethod({
      getBalance: { jsonrpc: "2.0", result: { value: 0 }, id: 1 },
      getSignaturesForAddress: { jsonrpc: "2.0", result: [], id: 1 },
    });
    const r = await solanaAddress(SOL, { fetchImpl: impl, retries: 0 });
    expect(r.entities[0].note).toContain("0.000000000 SOL");
    expect(r.entities[0].note).toContain("0 recent signatures");
  });
  it("THROWS on a JSON-RPC error (invalid address) — never an empty-success wallet", async () => {
    const impl = fetchByMethod({ getBalance: { jsonrpc: "2.0", error: { message: "Invalid param" }, id: 1 } });
    await expect(solanaAddress(SOL, { fetchImpl: impl, retries: 0 })).rejects.toThrow(/Invalid param/);
  });
});

describe("tonAddress (toncenter)", () => {
  it("parses fullAccountState into a T1 wallet with a TON balance note", async () => {
    const impl = fetchJson({
      ok: true,
      result: { balance: "1592537943871182", last_transaction_id: { lt: "80195391000012" } },
    });
    const r = await tonAddress(TON_ADDR, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("toncenter");
    expect(r.entities[0]).toMatchObject({ type: "wallet", value: TON_ADDR });
    expect(r.entities[0].note).toContain("1592537.943871182 TON");
  });
  it("notes 'no transactions' for an inactive (lt 0) account", async () => {
    const impl = fetchJson({ ok: true, result: { balance: "0", last_transaction_id: { lt: "0" } } });
    const r = await tonAddress(TON_ADDR, { fetchImpl: impl, retries: 0 });
    expect(r.entities[0].note).toContain("no transactions");
  });
  it("THROWS on ok:false (invalid address) or a non-ok HTTP", async () => {
    await expect(tonAddress(TON_ADDR, { fetchImpl: fetchJson({ ok: false }), retries: 0 })).rejects.toThrow(/not ok/);
    await expect(tonAddress(TON_ADDR, { fetchImpl: fetchStatus(422), retries: 0 })).rejects.toThrow(/422/);
  });
});

describe("ensName (ensideas)", () => {
  it("emits the RESOLVED 0x address as the wallet (not the .eth name)", async () => {
    const ADDR0X = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
    const r = await ensName("vitalik.eth", { fetchImpl: fetchJson({ address: ADDR0X, name: "vitalik.eth" }), retries: 0 });
    expect(r.provider).toBe("ensideas");
    expect(r.entities[0]).toMatchObject({ type: "wallet", value: ADDR0X });
    // A6: the note is now the bidirectional crosslink "ENS crosslink <name> ↔ <addr>" (was "ENS <name> → <addr>").
    expect(r.entities[0].note).toContain("crosslink");
    expect(r.entities[0].note).toContain("vitalik.eth");
    expect(r.entities[0].note).toContain(ADDR0X);
  });
  it("THROWS on a non-.eth name, a missing/zero address, or a non-ok HTTP", async () => {
    await expect(ensName("notens.com", { fetchImpl: fetchJson({ address: "0x1" }), retries: 0 })).rejects.toThrow(/\.eth/);
    await expect(ensName("ghost.eth", { fetchImpl: fetchJson({ address: null }), retries: 0 })).rejects.toThrow(/resolve/);
    await expect(
      ensName("ghost.eth", { fetchImpl: fetchJson({ address: "0x0000000000000000000000000000000000000000" }), retries: 0 }),
    ).rejects.toThrow(/resolve/);
  });
});

describe("wallet gate behavior (single on-chain source promotes; uncorroborated is a lead)", () => {
  it("an on-chain-confirmed wallet PROMOTES (T1 non-fakeable, one authoritative source)", () => {
    const f: Finding = { entity: ADDR, entity_type: "wallet", source_count: 1, infra_source_count: 1 };
    expect(promotionGate(f).promote).toBe(true);
  });

  it("an uncorroborated wallet (no on-chain source) is a LEAD", () => {
    const f: Finding = { entity: ADDR, entity_type: "wallet", source_count: 0, infra_source_count: 0 };
    expect(promotionGate(f).promote).toBe(false);
  });
});
