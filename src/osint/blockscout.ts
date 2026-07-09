// blockscout — keyless ETH address info via eth.blockscout.com/api/v2 (CORS `*`, re-probed live from the
// hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-2. A blockscout address read is an
// on-chain record — non-fakeable T1. It complements the KEYED Etherscan enrich tool: keyless, and it carries
// blockscout's own labels — the resolved ENS name (a wallet↔name crosslink), a contract flag, and blockscout's
// is_scam / public_tags reputation. coin_balance is a wei string that can exceed Number.MAX_SAFE_INTEGER, so
// it is parsed with BigInt (never Number) before the wei→ETH render.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://eth.blockscout.com/api/v2/addresses/";
const WEI_PER_ETH = 10n ** 18n;

interface AddressResponse {
  hash?: string;
  coin_balance?: string;
  ens_domain_name?: string | null;
  is_contract?: boolean;
  is_scam?: boolean;
  is_verified?: boolean;
  name?: string | null;
  public_tags?: unknown[];
}

/** ETH address → balance + blockscout labels (ENS name, contract flag, scam flag). Keyless, T1 on-chain. */
export async function blockscoutAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const addr = address.trim();
  const url = `${ENDPOINT}${encodeURIComponent(addr)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (res.status === 404) throw new Error("blockscout: address not found"); // never a fake wallet
      if (!res.ok) throw new Error(`blockscout HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // A valid response echoes the address hash. Anything else is not evidence.
  if (!json || typeof json !== "object" || typeof (json as AddressResponse).hash !== "string") {
    throw new Error("blockscout: unexpected response shape");
  }
  const r = json as AddressResponse;
  // Response-substitution guard (codex adversarial finding-3): the echoed hash MUST match the queried address
  // (case-insensitive — 0x hex), else a hostile provider could attach another address's balance/labels to it.
  if ((r.hash ?? "").trim().toLowerCase() !== addr.toLowerCase()) {
    throw new Error("blockscout: response hash does not match the query");
  }
  // The on-chain FACT (T1): the ETH balance + whether it's a contract, read off-chain by blockscout. The
  // provider-ASSERTED labels (ENS name, editorial name, is_scam) are blockscout's own metadata, NOT
  // non-fakeable on-chain evidence (codex finding-6) — they are explicitly attributed as "blockscout:" in the
  // note so a scam/ENS label never reads as a T1 fact. The wallet node itself is a real on-chain address (T1).
  const onchain = [`balance ${weiToEth(r.coin_balance)}`, r.is_contract ? "contract" : "EOA"].filter(Boolean);
  const asserted = [
    r.is_verified ? "verified-source" : "",
    r.ens_domain_name ? `ENS: ${r.ens_domain_name}` : "",
    r.name ? `name: ${r.name}` : "",
    r.is_scam ? "is_scam" : "",
  ].filter(Boolean);
  const note = [onchain.join(" · "), asserted.length ? `blockscout-asserted: ${asserted.join(", ")}` : ""].filter(Boolean).join(" · ");
  const entity: OsintEntity = { type: "wallet", value: addr.toLowerCase(), note };
  return { provider: "blockscout", query: addr, tier: "T1", entities: [entity], summary: note };
}

/** Parse a wei string with BigInt (a wei value can exceed Number.MAX_SAFE_INTEGER) → a fixed ETH string. */
function weiToEth(wei?: string): string {
  if (typeof wei !== "string" || !/^\d+$/.test(wei)) return "(unknown)";
  const value = BigInt(wei);
  const whole = value / WEI_PER_ETH;
  const frac = (value % WEI_PER_ETH).toString().padStart(18, "0").slice(0, 6);
  return `${whole.toString()}.${frac} ETH`;
}
