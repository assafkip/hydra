// PRD-onchain: keyless, browser-native Tron address lookup via TronGrid (CORS-open,
// verified 2026-06-18: api.trongrid.io/v1/accounts/{addr} → 200, access-control-allow-origin:*).
// A Tron on-chain record is T1 (non-fakeable). Extends the crypto-fraud wedge across chains.
//
// throw-vs-emit (codex): a non-ok HTTP or a non-{data:[...]} body THROWS a sanitized error so the
// caller surfaces is_error (never an empty-success wallet). But `data: []` is a VALID inactive/unseen
// address, not an error — it emits a wallet with a "no on-chain account" note (the BTC adapter emits
// zero-activity wallets the same way). Sun amounts are Number.isSafeInteger-guarded before TRX math.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.trongrid.io/v1/accounts/";
const SUN_PER_TRX = 1_000_000;
// A Tron base58 address: 'T' + 33 base58 chars. A light guard so a domain/IP can't be mis-routed here.
const TRON_RE = /^T[1-9A-HJ-NP-Za-km-z]{33}$/;

interface TronAccount {
  balance?: number;
  assetV2?: unknown[];
  trc20?: unknown[];
}
interface TronResponse {
  data?: TronAccount[];
}

export async function tronAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  if (!TRON_RE.test(address)) throw new Error("Tron: not a base58 T-address");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(address)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`TronGrid HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object" || !Array.isArray((json as TronResponse).data)) {
    throw new Error("TronGrid: unexpected response shape");
  }
  const data = (json as TronResponse).data ?? [];
  const note = data.length === 0 ? "Tron: no on-chain account found" : buildNote(data[0]);
  const entity: OsintEntity = { type: "wallet", value: address, note };
  return { provider: "trongrid", query: address, tier: "T1", entities: [entity] };
}

function buildNote(a: TronAccount): string {
  const sun = a.balance ?? 0;
  const trx = Number.isSafeInteger(sun) ? `${(sun / SUN_PER_TRX).toFixed(6)} TRX` : "(very large)";
  const trc10 = Array.isArray(a.assetV2) ? a.assetV2.length : 0;
  const trc20 = Array.isArray(a.trc20) ? a.trc20.length : 0;
  return `Tron: balance ${trx}, ${trc10} TRC10 + ${trc20} TRC20 tokens`;
}
