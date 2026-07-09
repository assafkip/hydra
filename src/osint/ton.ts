// PRD-onchain: keyless, browser-native TON address lookup via toncenter (CORS-open, verified
// 2026-06-18: toncenter.com/api/v2/getAddressInformation → 200, access-control-allow-origin:*).
// A TON on-chain record is T1 (non-fakeable).
//
// throw-vs-emit (codex): toncenter returns {ok:false} on an invalid address (HTTP 422) — that, a
// non-ok HTTP, or a missing result THROWS a sanitized error. A valid address with a zero balance / no
// last transaction EMITS a wallet with a no-transactions note (not an error). The balance string
// (nanoTON) is Number.isFinite-guarded before TON math.
import { type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://toncenter.com/api/v2/getAddressInformation";
const NANO_PER_TON = 1_000_000_000;
// A TON address: user-friendly base64url (EQ/UQ/kQ/0Q + 46 chars) OR a raw `workchain:hex` form.
const TON_FRIENDLY_RE = /^(?:EQ|UQ|kQ|0Q)[A-Za-z0-9_-]{46}$/;
const TON_RAW_RE = /^-?\d+:[0-9a-fA-F]{64}$/;

interface TonResponse {
  ok?: boolean;
  result?: {
    balance?: string;
    last_transaction_id?: { lt?: string };
  };
}

export async function tonAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  if (!TON_FRIENDLY_RE.test(address) && !TON_RAW_RE.test(address)) throw new Error("TON: not a TON address");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}?address=${encodeURIComponent(address)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`toncenter HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const r = json as TonResponse;
  if (!r || typeof r !== "object" || r.ok !== true || !r.result) {
    throw new Error("toncenter: not ok / no result");
  }
  const ton = tonBalance(r.result.balance);
  const lt = r.result.last_transaction_id?.lt;
  const hasTx = typeof lt === "string" && lt !== "0" && lt !== "";
  const note = `TON: balance ${ton}${hasTx ? "" : ", no transactions"}`;
  return { provider: "toncenter", query: address, tier: "T1", entities: [{ type: "wallet", value: address, note }] };
}

function tonBalance(raw?: string): string {
  if (typeof raw !== "string") return "(unknown)";
  const n = Number(raw);
  if (!Number.isFinite(n)) return "(very large)";
  return `${(n / NANO_PER_TON).toFixed(9)} TON`;
}
