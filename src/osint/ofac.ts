// OFAC sanctions screen (restore-osint-tool-belt 2026-06-24, port of investigations/enrich/ofac.py).
// Two checks by input shape:
//   0x EVM wallet -> the Chainalysis sanctions oracle isSanctioned(addr) via a keyless eth_call. An
//                    on-chain contract read = T1. ethereum-rpc.publicnode.com is CORS-open (ACAO:*,
//                    verified live 2026-06-24) so this runs DIRECT from the browser — no key, no proxy.
//   person / org  -> the OFAC SDN name list (treasury.gov/sdn.csv). treasury.gov returns NO CORS header
//                    (302, no ACAO — verified live 2026-06-24), so the browser cannot fetch it directly.
//                    The name path therefore needs the user-Worker PROXY tier (a later increment) and
//                    returns a clear "requires proxy" message rather than a fake clean result.
import type { OsintEntity, OsintOpts, OsintResult } from "./types.js";
import { withRetry } from "./types.js";

const ETH_RE = /^0x[a-fA-F0-9]{40}$/;
const ORACLE = "0x40C57923924B5c5c5455c48D93317139ADDaC8fb"; // Chainalysis sanctions oracle (mainnet)
const IS_SANCTIONED_SELECTOR = "0xdf592f7d"; // isSanctioned(address)
const ETH_RPC = "https://ethereum-rpc.publicnode.com"; // keyless, CORS-open (ACAO:*) — in CSP connect-src

interface RpcResp {
  result?: string;
  error?: { message?: string };
}

async function ethCallSanctioned(address: string, opts: OsintOpts): Promise<boolean> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const data = IS_SANCTIONED_SELECTOR + address.slice(2).toLowerCase().padStart(64, "0");
  const payload = JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "eth_call",
    params: [{ to: ORACLE, data }, "latest"],
  });
  const body = await withRetry(
    async () => {
      const res = await fetchImpl(ETH_RPC, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload,
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`OFAC oracle RPC HTTP ${res.status}`);
      return (await res.json()) as RpcResp;
    },
    opts.retries ?? 0,
    undefined,
    opts.signal,
  );
  if (body.error) throw new Error(`OFAC oracle RPC error: ${body.error.message ?? "unknown"}`);
  const result = body.result || "0x0";
  return BigInt(result) !== 0n;
}

async function screenWallet(address: string, opts: OsintOpts): Promise<OsintResult> {
  const sanctioned = await ethCallSanctioned(address, opts);
  if (!sanctioned) {
    return {
      provider: "ofac_screen",
      query: address,
      tier: "T1",
      entities: [],
      summary: `OFAC: ${address} — NOT sanctioned (Chainalysis sanctions oracle, on-chain read).`,
    };
  }
  const entities: OsintEntity[] = [{ type: "wallet", value: address, note: "OFAC-sanctioned wallet (Chainalysis oracle)" }];
  return {
    provider: "ofac_screen",
    query: address,
    tier: "T1",
    entities,
    summary: `OFAC SANCTIONED: ${address}\nChainalysis sanctions oracle flags this address as on an OFAC sanctions list (T1, on-chain contract read). Treat as a confirmed compliance finding.`,
  };
}

/** OFAC screen. A 0x wallet runs the Chainalysis oracle DIRECT (keyless, T1). A person/org name needs the
 *  treasury.gov SDN list, which is CORS-blocked — that path routes through the user-Worker proxy tier and is
 *  reported as pending until that increment ships (never a faked clean result). */
export async function ofacScreen(query: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const q = query.trim();
  if (!q) throw new Error("ofac_screen: empty query");
  if (ETH_RE.test(q)) return screenWallet(q, opts);
  return {
    provider: "ofac_screen",
    query: q,
    tier: "T1",
    entities: [],
    summary:
      `OFAC SDN name screen for "${q}" requires the Worker-proxy tier: treasury.gov serves the SDN list ` +
      `without a CORS header, so the browser cannot fetch it directly. The 0x-wallet sanctions oracle runs ` +
      `direct today; the name-list screen lands in the proxy increment. (Not a clean result — not yet checked.)`,
  };
}
