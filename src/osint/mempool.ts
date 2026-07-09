// PRD-5a: keyless, browser-native BTC address lookup via mempool.space (CORS-open,
// verified 2026-06-17). A BTC on-chain record is T1 (non-fakeable). Unlocks the
// crypto-fraud wedge's primary seed: a scam payout address.
//
// Robustness (codex review): satoshi fields are JSON numbers, so they are
// Number.isSafeInteger-guarded before any sats->BTC math (an unsafe value is labeled
// "(very large)", never silently rounded). An invalid / empty / non-object / missing-
// stats response THROWS a sanitized error so the caller surfaces is_error, never an
// empty-success "wallet".
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://mempool.space/api/address/";
const SATS_PER_BTC = 100_000_000;

interface Stats {
  funded_txo_sum?: number;
  spent_txo_sum?: number;
  tx_count?: number;
}
interface AddrResponse {
  address?: string;
  chain_stats?: Stats;
  mempool_stats?: Stats;
}

export async function btcAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(address)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`mempool.space HTTP ${res.status}`); // 400 on a non-BTC address
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // A valid address response MUST carry chain_stats. Anything else is not evidence.
  if (!json || typeof json !== "object" || !(json as AddrResponse).chain_stats) {
    throw new Error("mempool.space: unexpected response shape");
  }
  const r = json as AddrResponse;
  const entity: OsintEntity = {
    type: "wallet",
    value: address,
    note: buildNote(r.chain_stats ?? {}, r.mempool_stats ?? {}),
  };
  return { provider: "mempool.space", query: address, tier: "T1", entities: [entity] };
}

/** Sum two satoshi fields, or null if either (or the sum) is not a safe integer. */
function safeSum(a?: number, b?: number): number | null {
  const x = a ?? 0;
  const y = b ?? 0;
  if (!Number.isSafeInteger(x) || !Number.isSafeInteger(y)) return null;
  const sum = x + y;
  return Number.isSafeInteger(sum) ? sum : null;
}

function btc(sats: number | null): string {
  return sats === null ? "(very large)" : `${(sats / SATS_PER_BTC).toFixed(8)} BTC`;
}

function buildNote(cs: Stats, ms: Stats): string {
  const txCount = safeSum(cs.tx_count, ms.tx_count);
  const received = safeSum(cs.funded_txo_sum, ms.funded_txo_sum);
  const spent = safeSum(cs.spent_txo_sum, ms.spent_txo_sum);
  const balance = received !== null && spent !== null ? received - spent : null;
  const tx = txCount === null ? "(very large)" : String(txCount);
  return `BTC: ${tx} txs, received ${btc(received)}, balance ${btc(balance)}`;
}
