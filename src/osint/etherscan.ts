// Chunk-5 enrich: keyed, browser-native Etherscan address lookup. Upgraded to the Etherscan V2 unified
// endpoint (api.etherscan.io/v2/api, CORS-open: a simple GET, the key in the ?apikey= query param, ACAO *
// re-verified 2026-07-09). V2 is multi-chain via the ?chainid= param on ONE key — chainid defaults to 1
// (Ethereum mainnet), so the existing keyed path is unchanged; a caller may pass another chainid (e.g. 56
// BSC, 137 Polygon, 8453 Base) to reach the same address history on that chain. An on-chain transaction
// record is non-fakeable — T1. One bounded txlist call (sort=desc, offset capped) surfaces the address's
// recent counterparties. The key appears in the URL by Etherscan's design (disclosed flow) and is NEVER
// echoed in a thrown error: an API error throws on the `message` field (e.g. "NOTOK"), never the `result`
// string or the key.
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  MAX_ENRICH_RESULTS,
  uniqueBy,
  withRetry,
} from "./types.js";

const ENDPOINT = "https://api.etherscan.io/v2/api";
const DEFAULT_CHAIN_ID = 1; // Ethereum mainnet — the pre-V2 behavior, kept as the default so no caller breaks

interface EtherscanTxResponse {
  status?: string;
  message?: string;
  result?: { from?: string; to?: string }[] | string;
}

export async function etherscanAddress(
  address: string,
  key: string,
  opts: OsintOpts = {},
  chainId: number = DEFAULT_CHAIN_ID,
): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const addr = address.trim().toLowerCase();
  // V2 requires chainid; a non-finite/negative value falls back to mainnet rather than forging a bad URL.
  const chain = Number.isInteger(chainId) && chainId > 0 ? chainId : DEFAULT_CHAIN_ID;
  const url =
    `${ENDPOINT}?chainid=${chain}&module=account&action=txlist&address=${encodeURIComponent(addr)}` +
    `&page=1&offset=${MAX_ENRICH_RESULTS}&sort=desc&apikey=${encodeURIComponent(key)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`Etherscan HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object") throw new Error("Etherscan: unexpected response shape");
  const r = json as EtherscanTxResponse;

  // status "1" -> result is the tx array. status "0" with an array-less result is either an empty
  // address ("No transactions found") or an API error ("NOTOK" / rate limit / invalid key). Only the
  // `message` is surfaced (never `result`, which on error is a free-form string).
  if (!Array.isArray(r.result)) {
    const msg = (r.message ?? "").toLowerCase();
    if (msg.includes("no transactions")) {
      return { provider: "etherscan", query: addr, tier: "T1", entities: [{ type: "wallet", value: addr, note: "Etherscan: no transactions" }] };
    }
    throw new Error(`Etherscan error (${r.message ?? "unknown"})`); // NEVER echo result/key
  }

  const txs = r.result.slice(0, MAX_ENRICH_RESULTS);
  const entities: OsintEntity[] = [{ type: "wallet", value: addr, note: `Etherscan: ${txs.length} recent tx(s)` }];
  for (const tx of txs) {
    for (const side of [tx.from, tx.to]) {
      if (side && typeof side === "string") {
        const cp = side.toLowerCase();
        if (cp !== addr && /^0x[0-9a-f]{40}$/.test(cp)) entities.push({ type: "wallet", value: cp, note: "Etherscan counterparty" });
      }
    }
  }

  return {
    provider: "etherscan",
    query: addr,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
