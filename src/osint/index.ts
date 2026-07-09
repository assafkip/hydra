import { dnsLookup } from "./doh.js";
import { rdapDomain } from "./rdap.js";
import { crtshSubdomains } from "./crtsh.js";
import type { OsintOpts, OsintResult } from "./types.js";

export { dnsLookup } from "./doh.js";
export { rdapDomain } from "./rdap.js";
export { crtshSubdomains } from "./crtsh.js";
export { btcAddress } from "./mempool.js";
// PRD-onchain: keyless T1 cross-chain wallet lookups (Tron / Solana / TON / ENS).
export { tronAddress } from "./tron.js";
export { solanaAddress } from "./solana.js";
export { tonAddress } from "./ton.js";
export { ensName } from "./ens.js";
// A6: keyless deep-DNS (SPF/DMARC) + typosquat lookalike generation (browser-callable, dns.google DoH).
export { dnsDeep } from "./dns-deep.js";
export { typosquatDomains, generateTyposquats } from "./typosquat.js";
// a56ffd8e (founder 2026-06-25): keyless IP→ASN routing lookup via the CSP-allowed dns.google DoH (Team Cymru).
export { asnLookup } from "./asn.js";
// hydra-reverse-ip (founder 2026-07-09): keyless reverse-IP → co-hosted domains (shared-hosting neighbors)
// via HackerTarget (api.hackertarget.com, CORS *). The companion to reverse_dns/PTR; a T2 lead (infra:false).
export { reverseIpLookup } from "./reverse-ip.js";
// PRD prd-hydra-free-osint-providers finding-1: keyless browser-direct infra/IP providers. T1 routing/scan
// (shodan-internetdb, ripestat, ip.guide, ipwho.is) + T3 abuse-reputation leads (stopforumspam, sans-isc).
export { shodanInternetDb } from "./shodan-internetdb.js";
export { ripestatNetworkInfo } from "./ripestat.js";
export { ipGuideLookup } from "./ip-guide.js";
export { ipWhoIsLookup } from "./ipwho-is.js";
export { stopForumSpamLookup } from "./stopforumspam.js";
export { sansIscLookup } from "./sans-isc.js";
// PRD prd-hydra-free-osint-providers finding-2: keyless cert + on-chain providers. certspotter (a 2nd CT
// source alongside crt.sh), blockstream + blockcypher (2nd/3rd independent BTC sources alongside mempool),
// blockscout (keyless ETH address labels/ENS/scam-flag). All T1 (a CT/on-chain record is non-fakeable).
export { certspotterIssuances } from "./certspotter.js";
export { blockstreamAddress } from "./blockstream.js";
export { blockcypherAddress } from "./blockcypher.js";
export { blockscoutAddress } from "./blockscout.js";
// PRD prd-hydra-free-osint-providers finding-5/6: keyless identity providers. Profile lookups whose typed
// pivots (account/person/org/email) land as T3 leads. github/gitlab accept an optional BYO token (vault via
// the enrich auth slot) for higher rate limits; HN + npm are anonymous APIs (keyless only).
export { githubUser } from "./github-user.js";
export { gitlabUser } from "./gitlab-user.js";
export { hackernewsUser } from "./hackernews-user.js";
export { npmUser } from "./npm-user.js";
// PRD prd-hydra-free-osint-providers finding-3: keyless email/breach providers. All T3 summary-only leads
// (infra:false). xposedornot = a breach-DB match LEAD (never proof); hibp-catalog = domain site-breach
// context (keyless catalog only, per-email is keyed + out of scope); disposable-email = debounce+kickbox
// cross-checked throwaway flag.
export { xposedOrNotEmail } from "./xposedornot.js";
export { hibpBreachCatalog } from "./hibp-catalog.js";
export { disposableEmail } from "./disposable-email.js";
// PRD prd-hydra-free-osint-providers finding-5/6: keyless corporate + entity-resolution. gleif = T1 global
// LEI registry (diverges from keyed OpenCorporates); wikidata = T3 entity-resolution lead (aliases/handles,
// origin=* CORS). Both emit typed org/url pivots.
export { gleifLei } from "./gleif.js";
export { wikidataEntity } from "./wikidata.js";
// restore-tool-belt: keyless username presence sweep (GitHub + Keybase, both CORS-verified).
export { usernameSweep } from "./username-sweep.js";
// restore-tool-belt (2026-06-24): keyless analysis tools. email triage/headers (DoH + pure text), phone
// parse (offline libphonenumber-js), OFAC wallet screen (CORS-open Chainalysis oracle eth_call).
export { emailTriage, emailHeaders } from "./email-intel.js";
export { phoneParse } from "./phone.js";
export { ofacScreen } from "./ofac.js";
// a56ffd8e (founder 2026-06-25): keyless Gravatar email→profile pivot (CORS-open gravatar.com profile JSON).
export { gravatarLookup } from "./gravatar.js";
// chunk-5 enrich: keyed providers + the registry (called DIRECT from the browser with the user's key).
export { shodanHost } from "./shodan.js";
export { censysHost } from "./censys.js";
export { otxPassiveDns } from "./otx.js";
export { etherscanAddress } from "./etherscan.js";
export { urlscanSearch } from "./urlscan.js";
export { ipinfoIp } from "./ipinfo.js";
// restore-tool-belt (2026-06-24): Jina reader — keyed, CORS-open (real GET response reflects ACAO).
export { jinaRead } from "./jina.js";
export {
  ENRICH_PROVIDERS,
  BLOCKED_PROVIDERS,
  enrichProvider,
  isBlockedProvider,
  type EnrichProvider,
  type BlockedProvider,
  type ProviderId,
  type TargetKind,
} from "./enrich.js";
export type { OsintEntity, OsintResult } from "./types.js";

/** Run all three browser-native pivots on a domain. Each is independent; a
 *  single failing provider does not sink the others (settled, not all-or-nothing). */
export async function runPivot(
  domain: string,
  opts: OsintOpts = {},
): Promise<{ results: OsintResult[]; succeeded: number }> {
  const settled = await Promise.allSettled([
    dnsLookup(domain, opts),
    rdapDomain(domain, opts),
    crtshSubdomains(domain, opts),
  ]);
  const results: OsintResult[] = [];
  for (const s of settled) if (s.status === "fulfilled") results.push(s.value);
  return { results, succeeded: results.length };
}
