// PRD-onchain: keyless, browser-native Solana address lookup via the publicnode JSON-RPC
// (CORS-open, verified 2026-06-18: solana-rpc.publicnode.com getBalance → 200,
// access-control-allow-origin:*). The original api.mainnet-beta.solana.com now 403s unkeyed.
// A Solana on-chain record is T1 (non-fakeable).
//
// throw-vs-emit (codex): a JSON-RPC `error` field (HTTP 200) — e.g. an invalid address — THROWS a
// sanitized error BEFORE reading `result`; a non-ok HTTP or an unexpected getBalance shape also throws.
// A zero balance / zero signatures is a VALID inactive address and EMITS a wallet with a zero-activity
// note (not an error). Lamports are Number.isSafeInteger-guarded before SOL math.
import { type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://solana-rpc.publicnode.com";
const LAMPORTS_PER_SOL = 1_000_000_000;
const SIG_LIMIT = 10;
// Solana base58 pubkey: 32-44 base58 chars. Light guard so a domain/IP can't be mis-routed here.
const SOLANA_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

interface RpcResponse {
  result?: unknown;
  error?: { message?: string };
}

async function rpc(fetchImpl: typeof fetch, method: string, params: unknown[], opts: OsintOpts): Promise<unknown> {
  const res = await fetchImpl(ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: opts.signal,
  });
  if (!res.ok) throw new Error(`Solana RPC HTTP ${res.status}`);
  const json = (await res.json()) as RpcResponse;
  if (json && json.error) throw new Error(`Solana RPC: ${json.error.message ?? "error"}`); // codex: invalid addr → error
  return json?.result;
}

export async function solanaAddress(address: string, opts: OsintOpts = {}): Promise<OsintResult> {
  if (!SOLANA_RE.test(address)) throw new Error("Solana: not a base58 address");
  const fetchImpl = opts.fetchImpl ?? fetch;

  const bal = await withRetry(() => rpc(fetchImpl, "getBalance", [address], opts), opts.retries, undefined, opts.signal);
  if (!bal || typeof bal !== "object" || typeof (bal as { value?: unknown }).value !== "number") {
    throw new Error("Solana: unexpected getBalance shape");
  }
  const lamports = (bal as { value: number }).value;

  const sigs = await withRetry(
    () => rpc(fetchImpl, "getSignaturesForAddress", [address, { limit: SIG_LIMIT }], opts),
    opts.retries,
    undefined,
    opts.signal,
  );
  const sigCount = Array.isArray(sigs) ? sigs.length : 0;

  const sol = Number.isSafeInteger(lamports) ? `${(lamports / LAMPORTS_PER_SOL).toFixed(9)} SOL` : "(very large)";
  const more = sigCount >= SIG_LIMIT ? "+" : "";
  const note = `Solana: balance ${sol}, ${sigCount}${more} recent signatures`;
  return { provider: "solana", query: address, tier: "T1", entities: [{ type: "wallet", value: address, note }] };
}
