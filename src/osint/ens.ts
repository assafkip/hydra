// PRD-onchain: keyless, browser-native ENS resolution via ensideas (CORS-open, verified
// 2026-06-18: api.ensideas.com/ens/resolve/{name-or-address} → 200, access-control-allow-origin:*).
// ENS ties a `.eth` name to its owning Ethereum address — the real cross-identity pivot.
//
// A6 (parity ens.py "name <-> address, both directions"): the adapter now resolves BIDIRECTIONALLY —
// a `.eth` name → its 0x address, AND a 0x address → its primary `.eth` name. The first web port did
// forward only ("returns address string only"); reverse is the missing half the inventory flagged.
//
// Gate-faithful + ORPHAN-TRAP (D1, shared verbatim with ens.py): the adapter emits the 0x ADDRESS as a
// `wallet` (the gateable, pivot-able entity), and NEVER the `.eth` name as a standalone node — a bare
// `name.eth` is neither a wallet nor an @handle, so the gate would mis-route it to `domain`. The
// name↔wallet CROSSLINK rides in the entity `note` (the agent reads it + can pivot), exactly as ens.py
// keeps the `.eth` in the header/raw_json only. The resolved 0x is validated 0x-40-hex and rejected if
// it is the zero address (unregistered). ETH-address ACTIVITY stays the keyed etherscan enrich tool (D2).
import { type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.ensideas.com/ens/resolve/";
const ETH_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const ENS_NAME_RE = /^[a-z0-9-]+\.eth$/i; // ens.py:_ENS_NAME_RE
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

interface EnsResponse {
  address?: unknown;
  name?: unknown;
}

/** Resolve a `.eth` name OR a 0x address through the ensideas resolver (it accepts either term and
 *  returns {address, name}). Emits the 0x ADDRESS as the wallet node; the `.eth` name rides the note as
 *  the crosslink (orphan-trap: never a standalone node). Throws a sanitized error on a non-name/address
 *  input or an unregistered (zero-address / nameless) resolution, so no junk promotes. */
export async function ensName(term: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const q = term.trim();
  const isName = ENS_NAME_RE.test(q);
  const isAddr = ETH_ADDR_RE.test(q);
  if (!isName && !isAddr) throw new Error("ENS: pass a .eth name or a 0x Ethereum address");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(q)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`ENS resolve HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const resp = json as EnsResponse;
  const addr = typeof resp?.address === "string" ? resp.address : "";
  const ensLabel = typeof resp?.name === "string" && ENS_NAME_RE.test(resp.name) ? resp.name : "";
  if (!ETH_ADDR_RE.test(addr) || addr.toLowerCase() === ZERO_ADDR) {
    throw new Error("ENS: did not resolve to an Ethereum address");
  }
  // reverse: the resolver MUST echo back the SAME address we queried, else the {address,name} pair is
  // an inconsistent response and the crosslink would be false (codex Medium). For an address query, pin it.
  if (isAddr && addr.toLowerCase() !== q.toLowerCase()) {
    throw new Error("ENS: resolver returned a different address than queried (inconsistent reverse record)");
  }
  // forward (name→addr): the queried name is the crosslink; reverse (addr→name): the resolved name is.
  const crossName = isName ? q : ensLabel;
  if (isAddr && !crossName) throw new Error("ENS: address has no primary .eth name (no reverse record)");
  const note = `ENS crosslink ${crossName} ↔ ${addr}`; // the handle↔wallet tie the agent can pivot on
  return { provider: "ensideas", query: q, tier: "T1", entities: [{ type: "wallet", value: addr, note }] };
}
