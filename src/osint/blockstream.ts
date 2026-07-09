// blockstream — keyless BTC address stats via blockstream.info/api (CORS `*`, re-probed live from the hydra
// origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-2. A BTC on-chain record is non-fakeable — T1.
// This is a SECOND independent BTC source alongside mempool.space (btc_address): two independent T1 reads of
// the same address corroborate each other (per the q-investigation crosslink rules). Same funded/spent/tx
// shape as mempool; satoshi fields are Number.isSafeInteger-guarded before any sats→BTC math.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://blockstream.info/api/address/";
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

export async function blockstreamAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(address)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`blockstream.info HTTP ${res.status}`); // 400 on a non-BTC address
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // A valid address response MUST carry chain_stats. Anything else is not evidence (mirrors mempool.ts).
  if (!json || typeof json !== "object" || !(json as AddrResponse).chain_stats) {
    throw new Error("blockstream.info: unexpected response shape");
  }
  const r = json as AddrResponse;
  // Response-substitution guard (codex adversarial finding-1): a hostile provider must not attach ANOTHER
  // wallet's stats to the queried address as T1 evidence. The echoed address MUST match the query, else throw.
  if (typeof r.address !== "string" || r.address.trim() !== address.trim()) {
    throw new Error("blockstream.info: response address does not match the query");
  }
  const entity: OsintEntity = {
    type: "wallet",
    value: address,
    note: buildNote(r.chain_stats ?? {}, r.mempool_stats ?? {}),
  };
  return { provider: "blockstream", query: address, tier: "T1", entities: [entity] };
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
  return `BTC (blockstream): ${tx} txs, received ${btc(received)}, balance ${btc(balance)}`;
}
