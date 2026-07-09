// PRD-2: the OSINT adapters as Anthropic tool definitions + a registry that runs
// them. Descriptions are PRESCRIPTIVE (they say WHEN to call), because Opus 4.8
// under-reaches for tools without trigger conditions (docs/17 section 4.6).
// A failed or unknown tool returns a tool_result with is_error:true and bounded,
// sanitized content — so an error never masquerades as successful OSINT evidence.

import { dnsLookup, rdapDomain, crtshSubdomains, btcAddress, tronAddress, solanaAddress, tonAddress, ensName, dnsDeep, typosquatDomains, asnLookup, reverseIpLookup, usernameSweep, emailTriage, emailHeaders, phoneParse, ofacScreen, gravatarLookup, shodanInternetDb, ripestatNetworkInfo, ipGuideLookup, ipWhoIsLookup, stopForumSpamLookup, sansIscLookup, certspotterIssuances, blockstreamAddress, blockcypherAddress, blockscoutAddress, githubUser, gitlabUser, hackernewsUser, npmUser, xposedOrNotEmail, hibpBreachCatalog, disposableEmail, gleifLei, wikidataEntity } from "../osint/index.js";
import type { EntityType, OsintEntity, OsintOpts, OsintResult } from "../osint/types.js";
import { enrichProvider, type EnrichProvider, type TargetKind } from "../osint/enrich.js";
import { renderViaProxy, runProxiedProvider } from "../osint/proxy.js";
import { resolveLink } from "../osint/linkresolve.js";
import type { ToolDef } from "../llm/client.js";

// ---- PRD-B agent-browser-forensics + tool-belt: the Worker-routed + keyless pivots ----

// Compact IOC extractor for a rendered page's text / DOM / network hosts — pulls the domains, IPs, and
// wallets a JS scam page reveals (the payout wallet, the script.js host, the kit's CDN). Page-scraped, so
// these are T2 leads (NOT infra-confirmed): the tools register infra:false and the gate corroborates.
const _DOMAIN_IOC = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const _IPV4_IOC = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const _BTC_IOC = /\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const _ETH_IOC = /\b0x[0-9a-fA-F]{40}\b/g;

function extractIocs(text: string, cap = 50): OsintEntity[] {
  const out: OsintEntity[] = [];
  const seen = new Set<string>();
  const add = (type: EntityType, value: string): void => {
    const v = value.trim().toLowerCase();
    const k = `${type}:${v}`;
    if (!v || seen.has(k) || out.length >= cap) return;
    seen.add(k);
    out.push({ type, value: v, note: "from rendered page" });
  };
  for (const m of text.matchAll(_IPV4_IOC)) if (isIpv4(m[0])) add("ip", m[0]);
  for (const m of text.matchAll(_ETH_IOC)) add("wallet", m[0]);
  for (const m of text.matchAll(_BTC_IOC)) add("wallet", m[0]);
  for (const m of text.matchAll(_DOMAIN_IOC)) add("domain", m[0]);
  return out;
}

function requireWorker(opts: OsintOpts, what: string): string {
  if (!opts.workerUrl) throw new Error(`${what} needs your Worker proxy URL — deploy the Worker + set it in Enrich`);
  return opts.workerUrl;
}

// ALL browser-render tools on the same PAGE share ONE attribution source `browser:<host>` (codex issue-5 C1):
// page_navigate + network_requests + evaluate_script reading the SAME page are not 3 independent corroborations
// — a single attacker-controlled page must NOT self-promote a fake wallet by being scraped 3 ways. Distinct
// pages are distinct sources (legitimate). On a bad URL the provider falls back to a stable per-tool label.
function browserSource(value: string): string {
  try {
    return `browser:${new URL(value).hostname}`;
  } catch {
    return "browser:invalid";
  }
}

/** browser forensics: render the page + extract the IOCs in its evaluated DOM text + final URL. */
async function pageNavigate(value: string, opts: OsintOpts): Promise<OsintResult> {
  const page = await renderViaProxy(requireWorker(opts, "browser forensics"), value, opts);
  return { provider: browserSource(value), query: value, tier: "T2", entities: extractIocs(`${page.text}\n${page.finalUrl}`) };
}

/** browser forensics: the HOSTS the page contacted (where the JS phones home — the network forensics). */
async function pageNetworkRequests(value: string, opts: OsintOpts): Promise<OsintResult> {
  const page = await renderViaProxy(requireWorker(opts, "browser forensics"), value, opts);
  const hosts = page.networkRequests
    .map((u) => {
      try {
        return new URL(u).hostname;
      } catch {
        return "";
      }
    })
    .filter(Boolean);
  return { provider: browserSource(value), query: value, tier: "T2", entities: extractIocs(hosts.join("\n")) };
}

/** browser forensics: the IOCs in the EVALUATED DOM html (reaches a wallet/script the static fetch misses). */
async function evaluateScript(value: string, opts: OsintOpts): Promise<OsintResult> {
  const page = await renderViaProxy(requireWorker(opts, "browser forensics"), value, opts);
  return { provider: browserSource(value), query: value, tier: "T2", entities: extractIocs(page.html) };
}

/** hydra-see-sites: resolve a link-aggregator page's OUTBOUND destination (a Pinterest pin → its real link).
 *  The LIGHT worker path — a keyless /page fetch, no Browser Rendering — because the destination is in the
 *  server HTML. Needs the worker only to get past the source's missing CORS. */
async function resolveLinkTool(value: string, opts: OsintOpts): Promise<OsintResult> {
  return resolveLink(value, requireWorker(opts, "link resolver"), opts);
}

/** keyless reverse-DNS (DoH PTR via dns.google — already CSP-allowed). A real T1 infra record. */
async function reverseDns(value: string, opts: OsintOpts): Promise<OsintResult> {
  const ip = value.trim();
  if (!isIpv4(ip)) throw new Error("reverse_dns needs an IPv4 address");
  const ptr = `${ip.split(".").reverse().join(".")}.in-addr.arpa`;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const res = await fetchImpl(`https://dns.google/resolve?name=${encodeURIComponent(ptr)}&type=PTR`, {
    headers: { accept: "application/dns-json" },
    signal: opts.signal,
  });
  if (!res.ok) throw new Error(`reverse_dns HTTP ${res.status}`);
  const j = (await res.json()) as { Answer?: { data?: string }[] };
  const entities: OsintEntity[] = [];
  for (const a of Array.isArray(j.Answer) ? j.Answer : []) {
    const host = String(a?.data ?? "").replace(/\.$/, "").trim().toLowerCase();
    if (host) entities.push({ type: "domain", value: host, note: `reverse DNS of ${ip}` });
  }
  return { provider: "reverse_dns", query: ip, tier: "T1", entities };
}

/** A CORS-blocked provider routed through the user's Worker (founder decision 2026-06-23). Needs a Worker
 *  URL + the provider's key configured IN the Worker; absent → a graceful error the agent recovers from. */
const proxiedTool = (id: string) => async (value: string, opts: OsintOpts): Promise<OsintResult> =>
  runProxiedProvider(id, value, requireWorker(opts, `the ${id} provider`), opts);

const DOMAIN_SCHEMA = {
  type: "object",
  properties: { domain: { type: "string", description: "the domain, e.g. example.com" } },
  required: ["domain"],
} as const;

const ADDRESS_SCHEMA = {
  type: "object",
  properties: { address: { type: "string", description: "the BTC address, e.g. 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" } },
  required: ["address"],
} as const;

// PRD-B agent-browser-forensics + tool-belt: a page URL (browser tools) + a bare IPv4 (reverse-DNS / IP providers).
const URL_SCHEMA = {
  type: "object",
  properties: { url: { type: "string", description: "the full page URL to render (the scam/phishing/claim page), including its scheme" } },
  required: ["url"],
} as const;

const IP_SCHEMA = {
  type: "object",
  properties: { ip: { type: "string", description: "an IPv4 address, e.g. 9.9.9.9" } },
  required: ["ip"],
} as const;

// PRD-onchain: the cross-chain address tools share a single-`address`-string schema, with the chain
// named in the property description so the model routes the right kind of address to the right tool.
const onchainSchema = (example: string) =>
  ({
    type: "object",
    properties: { address: { type: "string", description: example } },
    required: ["address"],
  }) as const;

// The tool names routed through the user's Cloudflare Worker (the CORS-blocked / proxied providers).
// Everything ELSE in OSINT_TOOLS runs keyless + browser-direct. Exported so the /tools inventory page
// derives its keyless-vs-pro split from this ONE source of truth — it can never drift from what DISPATCH
// actually wires (a proxied tool added below must be named here, asserted by the tool-inventory test).
export const PROXIED_TOOL_NAMES: ReadonlySet<string> = new Set([
  "vt_passive_dns",
  "greynoise_ip",
  "securitytrails_subdomains",
  "abuseipdb_ip",
  "pulsedive_indicator",
  "hunter_emails",
]);

export const OSINT_TOOLS: ToolDef[] = [
  {
    name: "dns_lookup",
    description:
      "Resolve a domain's live DNS records (A/AAAA/NS/MX). Call this when you have a domain and need " +
      "its IP addresses, nameservers, or mail servers — the first infra pivot on any domain.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "rdap_domain",
    description:
      "Fetch the domain registry (RDAP / whois) record. Call this when you have a domain and need its " +
      "registrar, registrant, nameservers, or registration dates — the authoritative ownership record.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "crtsh_subdomains",
    description:
      "Discover subdomains from certificate-transparency logs (crt.sh). Call this when you have a " +
      "domain and want to enumerate its subdomains / related hostnames to widen the pivot.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "btc_address",
    description:
      "Look up a Bitcoin address on-chain (mempool.space). Call this when you have a BTC address and " +
      "need its activity — total received, current balance, transaction count — e.g. to trace a scam " +
      "payout wallet. An on-chain record is non-fakeable (T1).",
    input_schema: { ...ADDRESS_SCHEMA },
  },
  {
    name: "tron_address",
    description:
      "Look up a Tron (TRX) address on-chain (TronGrid). Call this when you have a Tron base58 address " +
      "(starts with 'T', e.g. TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t) and need its TRX balance + TRC10/TRC20 " +
      "token activity — common for USDT-TRC20 scam payouts. On-chain record, non-fakeable (T1).",
    input_schema: onchainSchema("the Tron base58 address (starts with T), e.g. TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
  },
  {
    name: "solana_address",
    description:
      "Look up a Solana (SOL) address on-chain (publicnode RPC). Call this when you have a Solana base58 " +
      "address (32-44 chars, no leading 'T' or '0x') and need its SOL balance + recent signature activity. " +
      "On-chain record, non-fakeable (T1).",
    input_schema: onchainSchema("the Solana base58 address, e.g. 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"),
  },
  {
    name: "ton_address",
    description:
      "Look up a TON (Telegram Open Network) address on-chain (toncenter). Call this when you have a TON " +
      "address (user-friendly EQ.../UQ... base64url, or a raw workchain:hex) and need its TON balance + " +
      "account status. On-chain record, non-fakeable (T1).",
    input_schema: onchainSchema("the TON address, e.g. EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N"),
  },
  {
    name: "ens_name",
    description:
      "Resolve an ENS name OR an Ethereum address (ensideas, bidirectional). Call this with a *.eth name " +
      "(e.g. vitalik.eth) to get the 0x address that owns it, OR with a 0x address to get its primary .eth " +
      "name — the name↔wallet crosslink. Returns the resolved counterpart (T1); dig the address's activity " +
      "with the etherscan enrich tool if a key is configured.",
    input_schema: {
      type: "object",
      properties: { name: { type: "string", description: "the ENS name (vitalik.eth) or an 0x Ethereum address" } },
      required: ["name"],
    },
  },
  {
    name: "dns_deep",
    description:
      "Read a domain's SPF + DMARC mail-authentication records (DNS-over-HTTPS). Call this AFTER dns_lookup " +
      "when you want the mail infrastructure: the sending domains and IPs the SPF authorizes (include:/ip4:/ip6:) " +
      "and the DMARC report domains — real pivots a basic resolve misses. (AXFR zone transfer is not possible " +
      "from a browser.) T1 published DNS records.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "typosquat_domains",
    description:
      "Generate lookalike / typo-squat domains for a brand domain and DNS-check which are LIVE. Call this on a " +
      "phishing / brand-impersonation / crypto-scam case when you have the legitimate domain (e.g. binance.com) " +
      "and want to discover the operator's registered lookalikes. Only LIVE (DNS-resolving) candidates are " +
      "returned as domain nodes (T1); unconfirmed candidates are listed but not graphed.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    // restore-tool-belt (2026-06-24): keyless username presence sweep across CORS-verified platforms.
    name: "username_sweep",
    description:
      "Check whether a bare handle exists on GitHub + Keybase (keyless, browser-direct) and return each hit as a " +
      "profile URL to pivot on. Call this on a person/operator case when you have a username and want to find their " +
      "public footprint. T3 (a social presence is a LEAD, not proof of identity) — corroborate before attributing.",
    input_schema: { type: "object", properties: { handle: { type: "string", description: "a bare username / handle (no @)" } }, required: ["handle"] },
  },
  // restore-tool-belt (2026-06-24): keyless analysis tools — email triage/headers, phone parse, OFAC screen.
  {
    name: "email_triage",
    description:
      "Triage an email ADDRESS (user@domain): MX records, SPF posture, DMARC policy, mail provider, and a " +
      "disposable/throwaway-domain flag. Call this when you have an email and want its mail infrastructure + a " +
      "spoofability/disposability read. Keyless DNS (DoH). The domain + MX hosts come back as pivot nodes (T1).",
    input_schema: { type: "object", properties: { email: { type: "string", description: "an email address, user@domain" } }, required: ["email"] },
  },
  {
    name: "email_headers",
    description:
      "Parse a pasted raw email HEADER block into its Received hop chain + every public source IP as a pivot, with " +
      "the ORIGIN IP flagged. Call this when the user gives you full email headers and you need where the message " +
      "actually originated (feed the IPs into dns/RDAP/VT). Pure text, keyless. IPs are T3 leads (headers are forgeable).",
    input_schema: { type: "object", properties: { headers: { type: "string", description: "the full raw RFC-822 header block, pasted as text" } }, required: ["headers"] },
  },
  {
    name: "phone_parse",
    description:
      "Parse a PHONE number offline (libphonenumber): country, region, and line-type incl. VoIP (a fraud/disposable " +
      "signal). Call this when you have a phone number and want its origin + line-type. Keyless, deterministic, no " +
      "network. T2 — a phone as an identity anchor still needs an independent second source before attribution.",
    input_schema: { type: "object", properties: { phone: { type: "string", description: "a phone number in E.164 form (+<country code><number>)" } }, required: ["phone"] },
  },
  {
    name: "ofac_screen",
    description:
      "OFAC sanctions screen (T1). Call this on a compliance/crypto case with a 0x EVM wallet -> the Chainalysis " +
      "on-chain sanctions oracle (keyless, browser-direct) tells you if it is sanctioned. A person/org NAME needs the " +
      "treasury.gov SDN list, which is CORS-blocked, so the name path requires the Worker-proxy tier (reported, not faked).",
    input_schema: { type: "object", properties: { query: { type: "string", description: "a 0x EVM wallet address, or a person/org name" } }, required: ["query"] },
  },
  // a56ffd8e (founder 2026-06-25): keyless Gravatar email→profile pivot (CORS-open gravatar.com profile JSON).
  {
    name: "gravatar",
    description:
      "Look up a Gravatar profile for an email ADDRESS. Call this when you have an email and want the identity " +
      "behind it — display name, linked social accounts (X / LinkedIn / GitHub …), and employer — a fast email→person " +
      "pivot. Keyless, CORS-open. SELF-ASSERTED by the email owner, so the linked accounts are T3 LEADS to confirm, " +
      "not proof; the linked-account URLs come back as pivot nodes.",
    input_schema: { type: "object", properties: { email: { type: "string", description: "an email address, user@domain" } }, required: ["email"] },
  },
  // PRD-B agent-browser-forensics: render a JS page through the user's Worker proxy to see what a static
  // fetch cannot. PRESCRIPTIVE triggers (Opus under-reaches without them).
  {
    name: "page_navigate",
    description:
      "Render a JS-heavy page headlessly (via your Worker) and read its EVALUATED text + final URL. Call this on a " +
      "scam / phishing / crypto-drainer site when the static page is empty or JS-built and you need what it actually " +
      "shows a victim — the payout address, the claim flow, the brand it impersonates. Returns the domains/IPs/wallets " +
      "found in the rendered page (T2 leads; corroborate with an infra tool).",
    input_schema: { ...URL_SCHEMA },
  },
  {
    name: "network_requests",
    description:
      "Render a page and list the HOSTS it contacted (where its JS phones home). Call this to find a scam page's " +
      "backend / CDN / wallet-API / analytics — the infrastructure behind the front end, which the visible HTML hides. " +
      "Returns the requested hosts as domain/IP leads (T2).",
    input_schema: { ...URL_SCHEMA },
  },
  {
    name: "evaluate_script",
    description:
      "Render a page and read its EVALUATED DOM html. Call this when a wallet address, a script.js host, or a kit " +
      "fingerprint is injected by JavaScript and not in the static source — the deepest browser-forensic read. " +
      "Returns the IOCs in the rendered DOM (T2 leads).",
    input_schema: { ...URL_SCHEMA },
  },
  // hydra-see-sites: resolve a link-aggregator page's outbound destination link.
  {
    name: "resolve_link",
    description:
      "Resolve the OUTBOUND destination a link-aggregator page points to — e.g. a Pinterest pin's real link. " +
      "Call this when a URL is a Pinterest pin (or similar) and you need where it actually sends users; the " +
      "destination is in the page's server HTML, so this is fast (no full render). Needs your Worker (the source " +
      "is CORS-walled). Returns the destination domain/URL + external leads (T2).",
    input_schema: { ...URL_SCHEMA },
  },
  // PRD-B tool-belt: a keyless reverse-DNS pivot.
  {
    name: "reverse_dns",
    description:
      "Resolve an IP's PTR (reverse DNS) record. Call this when you have an IP and want the hostname it reverse-resolves " +
      "to — a fast pivot from an IP back to a domain / hosting tenant. Keyless, T1 published DNS.",
    input_schema: { ...IP_SCHEMA },
  },
  // a56ffd8e (founder 2026-06-25): keyless IP→ASN routing lookup (Team Cymru over the CSP-allowed DoH).
  {
    name: "asn_lookup",
    description:
      "Look up the Autonomous System (ASN) that announces an IP, via Team Cymru. Call this when you have an IP and " +
      "want the network operator behind it — the ASN, BGP prefix, country, and operator name — a pivot from an IP to " +
      "its hosting/transit AS (useful for clustering IPs under one operator). Keyless, T1 routing record.",
    input_schema: { ...IP_SCHEMA },
  },
  // hydra-reverse-ip (founder 2026-07-09): keyless reverse-IP → co-hosted domains (the companion to reverse_dns).
  {
    name: "reverse_ip",
    description:
      "Reverse-IP lookup: the OTHER domains hosted on the SAME IP (co-hosted / shared-hosting neighbors) via " +
      "HackerTarget (keyless). Call this when you have an IP and want the domain NEIGHBORS sharing it — the companion " +
      "to reverse_dns (which returns only the PTR). Useful to cluster an operator's other sites on a dedicated host. " +
      "A co-hosted domain is a T2 LEAD (a large shared host has unrelated tenants), NOT proof of a relationship — " +
      "corroborate before attributing. Returns the neighbor domains as pivots (capped for a busy host).",
    input_schema: { ...IP_SCHEMA },
  },
  // PRD prd-hydra-free-osint-providers finding-1: keyless browser-direct infra/IP providers.
  {
    name: "shodan_internetdb",
    description:
      "Look up an IP's exposed attack surface via Shodan InternetDB (keyless): open ports, known CVEs, hostnames, and " +
      "tags. Call this when you have an IP and want what it exposes to the internet — the ports/services it runs and " +
      "any CVEs — e.g. to fingerprint a scam host's stack. Keyless, browser-direct. The hostnames come back as domain " +
      "pivots (T1 scan record); the ports/CVEs ride the summary.",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "ripestat_network",
    description:
      "Look up the ASN(s) and BGP prefix that announce an IP via RIPEstat (keyless). Call this when you have an IP and " +
      "want the announcing network — a second routing source that cross-checks asn_lookup. Keyless, T1 routing record. " +
      "Returns the ASN(s) as pivots (cluster IPs under one operator).",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "ip_guide",
    description:
      "Geolocate an IP and get its ASN + operator + CIDR via ip.guide (keyless). Call this when you have an IP and want " +
      "its network operator, organization, and rough geo without a key (the keyless equivalent of the IPinfo enrich " +
      "tool). Keyless, T1 routing record. Returns the ASN as a pivot; operator/geo in the summary.",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "ipwho_is",
    description:
      "Geolocate an IP and get its ASN + ISP + connection domain via ipwho.is (keyless). Call this to cross-check " +
      "ip_guide as a second keyless geo/ASN source, or when you want the connection's ISP + reverse domain. Keyless, T1 " +
      "routing record. Returns the ASN + connection domain as pivots; ISP/geo in the summary.",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "stopforumspam_ip",
    description:
      "Check an IP's crowd-reported spam/abuse reputation via StopForumSpam (keyless). Call this on a fraud/abuse case " +
      "when you want to know if an IP has a history of spam/bot activity. Keyless, browser-direct. A reputation score " +
      "is a T3 LEAD (crowd-reported, not a hard record) — corroborate before attributing. Summary only, no pivot node.",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "sans_isc_ip",
    description:
      "Check an IP's attack-report history via SANS ISC / DShield (keyless): how many honeypots/firewalls reported it " +
      "and which threat feeds list it. Call this to grade whether an IP is a known attacker/scanner. Keyless, browser- " +
      "direct. Aggregated crowd reports are a T3 LEAD — corroborate before attributing. Summary only, no pivot node.",
    input_schema: { ...IP_SCHEMA },
  },
  // PRD prd-hydra-free-osint-providers finding-2: keyless cert + on-chain providers.
  {
    name: "certspotter_issuances",
    description:
      "Discover subdomains + issuing CAs from certificate-transparency issuances via certspotter (keyless). Call this " +
      "when you have a domain and want a SECOND CT source alongside crtsh_subdomains — certspotter's index is " +
      "independent, so it surfaces hostnames crt.sh misses. Keyless, T1 (a CT log entry is non-fakeable). The dns_names " +
      "come back as subdomain/domain pivots; the issuing CA rides the summary.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "blockstream_address",
    description:
      "Look up a Bitcoin address on-chain via Blockstream (keyless). Call this to CROSS-CHECK btc_address " +
      "(mempool.space) with a second independent BTC source — total received, balance, and tx count. Two " +
      "independent on-chain reads corroborate a scam payout wallet. On-chain record, non-fakeable (T1).",
    input_schema: { ...ADDRESS_SCHEMA },
  },
  {
    name: "blockcypher_address",
    description:
      "Look up a Bitcoin address balance on-chain via BlockCypher (keyless). Call this for a THIRD independent BTC " +
      "balance source (with btc_address + blockstream_address) — received, sent, balance, tx count. On-chain record, " +
      "non-fakeable (T1). May rate-limit on the free tier (surfaced as an error, not a fake result).",
    input_schema: { ...ADDRESS_SCHEMA },
  },
  {
    name: "blockscout_address",
    description:
      "Look up an ETHEREUM address on-chain via Blockscout (keyless). Call this when you have a 0x address and want its " +
      "ETH balance PLUS blockscout's labels — the resolved ENS name (a wallet↔name crosslink), whether it's a contract, " +
      "and blockscout's scam flag. Keyless equivalent of the keyed Etherscan enrich tool. On-chain record, non-fakeable (T1).",
    input_schema: onchainSchema("the Ethereum 0x address, e.g. 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"),
  },
  // PRD prd-hydra-free-osint-providers finding-5/6: keyless identity providers. Each takes a bare handle and
  // returns TYPED pivots (account/person/org/email), not summary text. All T3 LEADS — corroborate before
  // attributing (a profile field is self-asserted). github/gitlab accept an optional BYO token (Enrich) for
  // higher rate limits.
  {
    name: "github_user",
    description:
      "Look up a GitHub username's public profile (keyless). Call this on a person/operator case when you have a handle " +
      "and want their GitHub footprint — display name, company, blog, linked Twitter, and public email if set. Returns " +
      "TYPED pivots (account/person/org/url/email), not text. T3 LEAD (self-asserted profile) — corroborate before attributing.",
    input_schema: { type: "object", properties: { handle: { type: "string", description: "a bare GitHub username (no @)" } }, required: ["handle"] },
  },
  {
    name: "gitlab_user",
    description:
      "Look up a GitLab username's public profile (keyless). Call this to cross-check github_user on a person case, or when " +
      "the subject uses GitLab — returns the profile URL, display name, and public email (if set) as TYPED pivots. T3 LEAD " +
      "(self-asserted profile) — corroborate before attributing.",
    input_schema: { type: "object", properties: { handle: { type: "string", description: "a bare GitLab username (no @)" } }, required: ["handle"] },
  },
  {
    name: "hackernews_user",
    description:
      "Look up a Hacker News username's public profile (keyless, official HN API). Call this when you have an HN handle and " +
      "want the account + any site/email the user wrote in their bio, plus karma/join-date. Returns TYPED pivots " +
      "(account/url/email). T3 LEAD (free-text bio) — corroborate before attributing.",
    input_schema: { type: "object", properties: { handle: { type: "string", description: "a bare Hacker News username (no @)" } }, required: ["handle"] },
  },
  {
    name: "npm_user",
    description:
      "Look up the npm packages a username maintains (keyless registry search). Call this on a developer/operator case when " +
      "you have a handle and want their published packages, the source repos those packages point to, and the publisher " +
      "email the registry records. Returns TYPED pivots (account/url/email). T3 LEAD — corroborate before attributing.",
    input_schema: { type: "object", properties: { handle: { type: "string", description: "a bare npm username (no @)" } }, required: ["handle"] },
  },
  // PRD prd-hydra-free-osint-providers finding-3: keyless email/breach providers. All T3 summary LEADS.
  {
    name: "xposedornot_email",
    description:
      "Check whether an email appears in known breach records via XposedOrNot (keyless). Call this on a person case when " +
      "you have an email and want breach-exposure LEADS. CRITICAL: a breach-DB match is a T3 LEAD, NOT proof this address " +
      "was breached (name-collisions + stale dumps happen) — corroborate before attributing. The queried email is sent to " +
      "XposedOrNot. Returns breach-name leads in the summary, no graph pivot.",
    input_schema: { type: "object", properties: { email: { type: "string", description: "the email address to check, e.g. user@example.com" } }, required: ["email"] },
  },
  {
    name: "hibp_breach_catalog",
    description:
      "Look up the breaches recorded against a DOMAIN in the keyless HIBP catalog. Call this when you have a domain and want " +
      "site-breach CONTEXT — which known breaches hit that website. This is domain context ONLY, never a list of exposed " +
      "accounts and never proof any specific address was breached (the per-email HIBP lookup is keyed and out of this free " +
      "tool). T3 context, summary only, no graph pivot.",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "disposable_email",
    description:
      "Check whether an email is a disposable / throwaway address, CROSS-CHECKED across debounce AND Kickbox (keyless). Call " +
      "this when you have an email and want to know if it's a burner (mailinator-style) — useful for grading a signup/actor. " +
      "Both providers are queried and their agreement reported; a disagreement is inconclusive. T3 context, summary only.",
    input_schema: { type: "object", properties: { email: { type: "string", description: "the email address to check, e.g. user@example.com" } }, required: ["email"] },
  },
  // PRD prd-hydra-free-osint-providers finding-5/6: keyless corporate + entity-resolution providers.
  {
    name: "gleif_lei",
    description:
      "Look up a company's LEI registry record via GLEIF (keyless, T1 registry). Call this when you have a company/legal " +
      "name and want its non-fakeable registry facts — the Legal Entity Identifier, jurisdiction, registered address, " +
      "status, and whether it has parent/child ownership relationships. The keyless equivalent of a company-registry pull " +
      "(OpenCorporates without a key). Returns the legal name + trade names as typed org pivots.",
    input_schema: { type: "object", properties: { company: { type: "string", description: "a company / legal entity name, e.g. Apple Inc." } }, required: ["company"] },
  },
  {
    name: "wikidata_entity",
    description:
      "Resolve a company/person name to its Wikidata entity (keyless). Call this when you have an organization or person " +
      "name and want alternate names/aliases, the official website, and social handles to widen the pivot. T3 LEAD (a " +
      "crowd knowledge-graph name-match) — corroborate before attributing. Returns the label + aliases (org) and the " +
      "official website (url) as typed pivots; social handles ride the summary.",
    input_schema: { type: "object", properties: { company: { type: "string", description: "an organization or person name, e.g. OpenAI" } }, required: ["company"] },
  },
  // PRD-B tool-belt: the CORS-blocked providers as agent tools, routed through the user's Worker proxy. Each
  // needs the Worker URL + that provider's key configured IN the Worker; without it the tool errors gracefully.
  {
    name: "vt_passive_dns",
    description:
      "VirusTotal passive DNS for a domain (via your Worker). Call this to get the IPs a domain has historically " +
      "resolved to — passive DNS the live resolver no longer shows. Needs your Worker + VT key. Returns IP leads (T2).",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "greynoise_ip",
    description:
      "GreyNoise classification for an IP (via your Worker). Call this to tell internet-background-noise / known-scanner " +
      "IPs from a targeted one. Needs your Worker + GreyNoise key. Returns the IP with its classification (T2).",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "securitytrails_subdomains",
    description:
      "SecurityTrails subdomains for a domain (via your Worker) — a deeper subdomain set than CT logs alone. Call this " +
      "to widen the operator's infrastructure. Needs your Worker + SecurityTrails key. Returns subdomain leads (T2).",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "abuseipdb_ip",
    description:
      "AbuseIPDB report for an IP (via your Worker) — whether the IP is reported for abuse. Call this to grade a " +
      "suspicious host. Needs your Worker + AbuseIPDB key. Returns the IP (T2).",
    input_schema: { ...IP_SCHEMA },
  },
  {
    name: "pulsedive_indicator",
    description:
      "Pulsedive threat data for a domain or IP indicator (via your Worker). Call this for threat context / risk on an " +
      "indicator. Needs your Worker + Pulsedive key. Returns the indicator (T2).",
    input_schema: { ...DOMAIN_SCHEMA },
  },
  {
    name: "hunter_emails",
    description:
      "Hunter.io email discovery for a domain (via your Worker) — emails associated with the domain. Call this to find " +
      "an operator's contact / registrant identity anchors. Needs your Worker + Hunter key. Returns leads (T2).",
    input_schema: { ...DOMAIN_SCHEMA },
  },
];

export interface ToolOutcome {
  /** JSON-serializable content for the Anthropic tool_result block. */
  content: string;
  is_error: boolean;
  /** Typed entities for attribution + gating (empty on error). */
  entities: OsintEntity[];
  provider?: string;
  /** Whether this result is a non-fakeable infra observation (drives the gate's infra_source_count).
   *  Optional so the loop defaults missing to true (`outcome.infra ?? true`) — the 3 free tools are all
   *  T1 infra. An enrich result carries its provider's explicit flag (codex D5); an error is false. */
  infra?: boolean;
  /** The normalized queried target, when this was a single-target lookup (enrich). The loop marks the
   *  matching observed entity `self` so a provider echoing the query back can't self-confirm (codex D4). */
  queryEcho?: string;
}

interface ToolSpec {
  // PRD-onchain: ENS takes a `name`, the chain tools an `address`; PRD-B adds `url` (browser) + `ip` (reverse-DNS).
  // restore-tool-belt: `handle` (username_sweep) + `email` / `headers` / `phone` / `query` (analysis tools).
  param: "domain" | "address" | "name" | "url" | "ip" | "handle" | "email" | "headers" | "phone" | "query" | "company";
  fn: (value: string, opts: OsintOpts) => Promise<OsintResult>;
  // default true (the keyless DNS/RDAP/CT + on-chain tools are T1 infra). PRD-B: browser-rendered + proxied
  // results are page/provider data, NOT a non-fakeable infra record, so they set infra:false (gate corroborates).
  infra?: boolean;
}

const DISPATCH: Record<string, ToolSpec> = {
  dns_lookup: { param: "domain", fn: dnsLookup },
  rdap_domain: { param: "domain", fn: rdapDomain },
  crtsh_subdomains: { param: "domain", fn: crtshSubdomains },
  username_sweep: { param: "handle", fn: usernameSweep },
  // restore-tool-belt (2026-06-24): keyless analysis tools. email_triage is T1 infra (published DNS records).
  // email_headers (forgeable pasted headers -> T3 lead IPs) + phone_parse (offline parse) set infra:false so
  // the gate corroborates. ofac_screen is a T1 on-chain oracle read (infra true; name path self-reports pending).
  email_triage: { param: "email", fn: emailTriage },
  email_headers: { param: "headers", fn: emailHeaders, infra: false },
  phone_parse: { param: "phone", fn: phoneParse, infra: false },
  ofac_screen: { param: "query", fn: ofacScreen },
  gravatar: { param: "email", fn: gravatarLookup, infra: false }, // a56ffd8e: self-asserted profile → T3 leads
  btc_address: { param: "address", fn: btcAddress },
  // PRD-onchain: the keyless cross-chain wallet tools (all T1 infra).
  tron_address: { param: "address", fn: tronAddress },
  solana_address: { param: "address", fn: solanaAddress },
  ton_address: { param: "address", fn: tonAddress },
  ens_name: { param: "name", fn: ensName },
  // A6: keyless deep-DNS (SPF/DMARC) + typosquat generation (both via the already-CSP-allowed dns.google DoH).
  dns_deep: { param: "domain", fn: dnsDeep },
  typosquat_domains: { param: "domain", fn: typosquatDomains },
  // PRD-B agent-browser-forensics (RCA discipline-evaporation): render a JS scam page via the user's Worker
  // to reach the payout wallet / script.js host / kit fingerprint a static fetch can't see.
  page_navigate: { param: "url", fn: pageNavigate, infra: false },
  network_requests: { param: "url", fn: pageNetworkRequests, infra: false },
  evaluate_script: { param: "url", fn: evaluateScript, infra: false },
  // hydra-see-sites: the LIGHT worker path — resolve a page's outbound destination from its server HTML.
  resolve_link: { param: "url", fn: resolveLinkTool, infra: false },
  // PRD-B tool-belt: a keyless reverse-DNS pivot (DoH PTR — a real T1 infra record).
  reverse_dns: { param: "ip", fn: reverseDns },
  asn_lookup: { param: "ip", fn: asnLookup }, // a56ffd8e: keyless IP→ASN (Team Cymru via DoH)
  // hydra-reverse-ip (founder 2026-07-09): keyless reverse-IP → co-hosted domains. infra:false — a shared-hosting
  // neighbor is a T2 LEAD (a busy host has unrelated tenants), so it never inflates the gate's infra_source_count.
  reverse_ip: { param: "ip", fn: reverseIpLookup, infra: false },
  // PRD prd-hydra-free-osint-providers finding-1: keyless infra/IP. The routing/scan four are T1 infra
  // (default infra:true — a scan/routing record is non-fakeable); the two abuse-reputation feeds set
  // infra:false + tier T3 so a crowd-reported score never inflates the gate's infra_source_count.
  shodan_internetdb: { param: "ip", fn: shodanInternetDb },
  ripestat_network: { param: "ip", fn: ripestatNetworkInfo },
  ip_guide: { param: "ip", fn: ipGuideLookup },
  ipwho_is: { param: "ip", fn: ipWhoIsLookup },
  stopforumspam_ip: { param: "ip", fn: stopForumSpamLookup, infra: false },
  sans_isc_ip: { param: "ip", fn: sansIscLookup, infra: false },
  // PRD prd-hydra-free-osint-providers finding-2: keyless cert + on-chain. All T1 infra (default infra:true —
  // a CT log entry / on-chain read is a non-fakeable record). certspotter is a 2nd CT source; blockstream +
  // blockcypher are 2nd/3rd BTC sources; blockscout is keyless ETH address labels.
  certspotter_issuances: { param: "domain", fn: certspotterIssuances },
  blockstream_address: { param: "address", fn: blockstreamAddress },
  blockcypher_address: { param: "address", fn: blockcypherAddress },
  blockscout_address: { param: "address", fn: blockscoutAddress },
  // PRD prd-hydra-free-osint-providers finding-5/6: keyless identity providers. infra:false — an identity
  // profile is a T3 LEAD (self-asserted), so its typed pivots never inflate the gate's infra_source_count.
  // The free tools run keyless (no token here); the optional BYO token rides the KEYED enrich variant.
  github_user: { param: "handle", fn: githubUser, infra: false },
  gitlab_user: { param: "handle", fn: gitlabUser, infra: false },
  hackernews_user: { param: "handle", fn: hackernewsUser, infra: false },
  npm_user: { param: "handle", fn: npmUser, infra: false },
  // PRD prd-hydra-free-osint-providers finding-3: keyless email/breach. All infra:false + T3 — a breach-DB
  // match / site-breach context / disposable flag is a LEAD, never gate-admissible attribution.
  xposedornot_email: { param: "email", fn: xposedOrNotEmail, infra: false },
  hibp_breach_catalog: { param: "domain", fn: hibpBreachCatalog, infra: false },
  disposable_email: { param: "email", fn: disposableEmail, infra: false },
  // PRD prd-hydra-free-osint-providers finding-5/6: keyless corporate + entity-resolution. gleif is a T1
  // REGISTRY (its adapter returns tier T1 — a registry record is non-fakeable), but it emits org (non-infra)
  // entities, so infra:false removes any ambiguity that a corporate registry could inflate infra corroboration
  // (codex adversarial). wikidata is a T3 lead → infra:false.
  gleif_lei: { param: "company", fn: gleifLei, infra: false },
  wikidata_entity: { param: "company", fn: wikidataEntity, infra: false },
  // PRD-B tool-belt: the CORS-blocked providers, routed through the user's Worker (per [[enrich-most-providers-are-cors-open]]).
  vt_passive_dns: { param: "domain", fn: proxiedTool("virustotal"), infra: false },
  greynoise_ip: { param: "ip", fn: proxiedTool("greynoise"), infra: false },
  securitytrails_subdomains: { param: "domain", fn: proxiedTool("securitytrails"), infra: false },
  abuseipdb_ip: { param: "ip", fn: proxiedTool("abuseipdb"), infra: false },
  pulsedive_indicator: { param: "domain", fn: proxiedTool("pulsedive"), infra: false },
  hunter_emails: { param: "domain", fn: proxiedTool("hunter"), infra: false },
};

/** Run one tool call. Returns a tool_result outcome; an AbortError propagates (the
 *  loop is stopping), every other failure becomes an is_error outcome the agent can
 *  recover from. */
export async function runTool(
  name: string,
  input: Record<string, unknown>,
  opts: OsintOpts = {},
): Promise<ToolOutcome> {
  const spec = DISPATCH[name];
  if (!spec) return errorOutcome(`unknown tool "${name}"`);
  const raw = input?.[spec.param];
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value) return errorOutcome(`tool "${name}" requires a non-empty "${spec.param}"`);
  try {
    const result = await spec.fn(value, opts);
    return {
      // restore-tool-belt: include `summary` when the adapter set it (the analysis tools — phone/email/ofac —
      // carry their value as text, not typed entities). Omitted for the entity-only infra tools (undefined
      // keys drop out of JSON.stringify), so their content shape is unchanged.
      content: JSON.stringify({ provider: result.provider, tier: result.tier, entities: result.entities, summary: result.summary }),
      is_error: false,
      entities: result.entities,
      provider: result.provider,
      // the keyless DNS/RDAP/CT + on-chain tools are T1 infra (default true); PRD-B browser/proxied tools
      // set infra:false — page/provider data is a T2 lead the gate must corroborate, never auto-promoted.
      infra: spec.infra ?? true,
    };
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e; // stop the loop, don't mask it
    return errorOutcome(sanitize(e));
  }
}

function errorOutcome(message: string): ToolOutcome {
  return { content: JSON.stringify({ error: message }), is_error: true, entities: [], infra: false };
}

/** Bounded, secret-free error text. Adapter errors are shapes like "RDAP HTTP 404". */
function sanitize(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.replace(/\s+/g, " ").trim().slice(0, 200);
}

// ---- m3: the keyed enrich providers as agent tools (registered only when the user has a key) ----

const ENRICH_PREFIX = "enrich_"; // the tool-name prefix
export const ENRICH_SOURCE_PREFIX = "enrich:"; // the attribution source prefix (codex D6: registry-id namespaced)

// Strict per-kind validators run BEFORE any key lookup or fetch (codex D3), so the model cannot burn a
// user's quota — or self-confirm junk — by sending a domain to Shodan or a wallet to urlscan.
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_RE = /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}$/; // pragmatic colon-grouped hextets
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const ETH_WALLET_RE = /^0x[0-9a-fA-F]{40}$/; // the enrich wallet kind is an Etherscan ETH address (BTC is a free tool)
// finding-5: a bare handle for the keyed identity providers — github/gitlab username charset, 1-39 chars,
// no leading @ (the caller strips it). Bounded so a free-text blob can't be sent as a "username".
const USERNAME_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,38})$/;

function isIpv4(v: string): boolean {
  return IPV4_RE.test(v) && v.split(".").every((o) => Number(o) <= 255);
}

/** True when `value` is a valid target of `kind`. ip = strict IPv4 or colon-grouped IPv6; domain = a
 *  normalized FQDN; wallet = an ETH 0x-40-hex address. The closed set of provider target kinds. */
export function validateTarget(kind: TargetKind, value: string): boolean {
  const v = value.trim();
  if (kind === "ip") return isIpv4(v) || (v.includes(":") && IPV6_RE.test(v));
  if (kind === "domain") return DOMAIN_RE.test(v);
  if (kind === "wallet") return ETH_WALLET_RE.test(v);
  if (kind === "query") return v.length > 0 && v.length <= 500; // A6: a free-text search query (Perplexity), bounded
  if (kind === "username") return USERNAME_RE.test(v); // finding-5: a bare handle for the keyed identity providers
  return false;
}

export interface EnrichBudget {
  /** Reserve a slot for one (provider, target) enrich call. {ok:false} on a repeat of the same pair, the
   *  per-provider cap, or the run total — the caller MUST NOT fetch when !ok. Mutates on a passing call. */
  check(provider: string, target: string): { ok: boolean; reason: string };
}

/** A per-run enrich spend cap (codex D7): bounds total enrich calls, per-provider calls, and forbids a
 *  repeat (provider, normalized target) — so a model cannot spam the enrich tools within the turn cap.
 *  Stateful: `check` RESERVES a slot on a passing call (a later fetch failure still counts, which stops
 *  retry-spam on one target). The 4 free tools are NOT budgeted (they are keyless and already bounded). */
export function enrichBudget(opts?: { maxTotal?: number; maxPerProvider?: number }): EnrichBudget {
  const maxTotal = opts?.maxTotal ?? 12;
  const maxPerProvider = opts?.maxPerProvider ?? 4;
  let total = 0;
  const perProvider = new Map<string, number>();
  const seen = new Set<string>();
  return {
    check(provider, target) {
      const pair = `${provider} ${target.trim().toLowerCase()}`;
      if (seen.has(pair)) return { ok: false, reason: "already queried this provider for this target this run" };
      if (total >= maxTotal) return { ok: false, reason: "enrich budget exhausted (run total)" };
      const used = perProvider.get(provider) ?? 0;
      if (used >= maxPerProvider) return { ok: false, reason: `enrich budget exhausted for ${provider}` };
      seen.add(pair);
      total += 1;
      perProvider.set(provider, used + 1);
      return { ok: true, reason: "" };
    },
  };
}

/** The agent ToolDef for one keyed provider: `enrich_<id>` with a single `target` string param and a
 *  description that names the accepted target kinds. The id is constrained `/^[a-z0-9_]+$/` and asserted
 *  non-colliding with the free OSINT_TOOLS (codex D8), so a malformed id can never shadow a free tool. */
export function enrichToolDef(provider: EnrichProvider): ToolDef {
  if (!/^[a-z0-9_]+$/.test(provider.id)) throw new Error(`enrich provider id not [a-z0-9_]: ${provider.id}`);
  const name = `${ENRICH_PREFIX}${provider.id}`;
  if (OSINT_TOOLS.some((t) => t.name === name)) throw new Error(`enrich tool name collides with a free tool: ${name}`);
  const kinds = provider.targets.join(" or ");
  return {
    name,
    description:
      `${provider.label} — ${provider.blurb}. Call this with the user's ${provider.label} key to enrich ` +
      `a ${kinds}. Accepts ONLY a ${kinds} as the target; do not call it on any other kind.`,
    input_schema: {
      type: "object",
      properties: { target: { type: "string", description: `the ${kinds} to look up` } },
      required: ["target"],
    },
  };
}

/**
 * Run one `enrich_<id>` tool call. Closed-allowlist routed (codex D8): the id must resolve to a STATIC
 * registry provider, else it is an unknown tool — no prefix trust, no prototype keys. The target is
 * validated per the provider's kinds BEFORE any key lookup or fetch (codex D3). The key is resolved via
 * the INJECTED resolveKey (tools.ts imports NO vault). The source is namespaced `enrich:<id>` from the
 * registry id, NOT the adapter output (codex D6), so two calls to one provider count as one source and
 * an enrich source never collides with a free tool's. The key rides only in the adapter's auth slot —
 * the returned content is `{provider, entities}` and never the key (the loop additionally redacts the
 * content before it reaches the model or the UI — codex D9).
 */
export async function runEnrichTool(
  name: string,
  input: Record<string, unknown>,
  resolveKey: (id: string) => string | null,
  opts: OsintOpts = {},
): Promise<ToolOutcome> {
  if (!name.startsWith(ENRICH_PREFIX)) return errorOutcome(`unknown tool "${name}"`);
  const id = name.slice(ENRICH_PREFIX.length);
  const provider = enrichProvider(id); // closed allowlist: only a static registry provider (D8)
  if (!provider) return errorOutcome(`unknown tool "${name}"`);
  const raw = input?.target;
  const target = typeof raw === "string" ? raw.trim() : "";
  if (!target) return errorOutcome(`tool "${name}" requires a non-empty "target"`);
  if (!provider.targets.some((kind) => validateTarget(kind, target))) {
    return errorOutcome(`"${target}" is not a valid ${provider.targets.join("/")} for ${provider.label}`); // D3, no fetch
  }
  const key = resolveKey(id);
  if (!key) return errorOutcome(`no ${provider.label} key configured`); // belt: only keyed providers are registered
  try {
    const result = await provider.run(target, key, opts);
    const source = `${ENRICH_SOURCE_PREFIX}${id}`; // D6
    return {
      content: JSON.stringify({ provider: source, entities: result.entities }),
      is_error: false,
      entities: result.entities,
      provider: source,
      infra: provider.infra,
      queryEcho: target.toLowerCase(),
    };
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e; // stop the loop
    return errorOutcome(sanitize(e));
  }
}
