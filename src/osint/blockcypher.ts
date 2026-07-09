// blockcypher — keyless BTC address balance via api.blockcypher.com (CORS `*`, re-probed live from the hydra
// origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-2. A BTC on-chain record is non-fakeable — T1.
// A THIRD independent BTC balance source (mempool + blockstream + blockcypher): balance is pre-summed by the
// API (already-satoshi total_received/total_sent/final_balance/n_tx), each Number.isSafeInteger-guarded before
// the sats→BTC render. Keyless works within blockcypher's free rate limit; no key path (BTC is a free tool).
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.blockcypher.com/v1/btc/main/addrs/";
const SATS_PER_BTC = 100_000_000;

interface BalanceResponse {
  address?: string;
  total_received?: number;
  total_sent?: number;
  final_balance?: number;
  final_n_tx?: number;
  n_tx?: number;
}

export async function blockcypherAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(address)}/balance`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (res.status === 429) throw new Error("blockcypher rate-limited (free tier)"); // surfaced as is_error, never a fake wallet
      if (!res.ok) throw new Error(`blockcypher HTTP ${res.status}`); // 400 on a non-BTC address
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // A valid balance response MUST carry the address it echoes. Anything else is not evidence.
  if (!json || typeof json !== "object" || typeof (json as BalanceResponse).address !== "string") {
    throw new Error("blockcypher: unexpected response shape");
  }
  const r = json as BalanceResponse;
  // Response-substitution guard (codex adversarial finding-2): the echoed address MUST match the query, else
  // a hostile provider could attach another wallet's balance to the queried address as T1 evidence.
  if ((r.address ?? "").trim() !== address.trim()) {
    throw new Error("blockcypher: response address does not match the query");
  }
  const entity: OsintEntity = { type: "wallet", value: address, note: buildNote(r) };
  return { provider: "blockcypher", query: address, tier: "T1", entities: [entity] };
}

function sats(v?: number): number | null {
  return Number.isSafeInteger(v ?? NaN) ? (v as number) : null;
}
function btc(v: number | null): string {
  return v === null ? "(very large)" : `${(v / SATS_PER_BTC).toFixed(8)} BTC`;
}

function buildNote(r: BalanceResponse): string {
  const nTx = sats(r.final_n_tx ?? r.n_tx);
  const tx = nTx === null ? "(very large)" : String(nTx);
  return `BTC (blockcypher): ${tx} txs, received ${btc(sats(r.total_received))}, balance ${btc(sats(r.final_balance))}`;
}
