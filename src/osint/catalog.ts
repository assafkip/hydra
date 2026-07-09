// The OSINT capability catalog — the read-only "what Hydra can do" surface (/capabilities).
//
// WHY this file exists: the live app only ever surfaced the 8 CORS-open enrich providers
// (ENRICH_PROVIDERS in enrich.ts). The real toolkit is ~4x that: 39 backend enrichment
// adapters, a 55+ Apify social-scrape layer, and a multi-engine search tier — most of it
// wielded by the investigator agent and invisible to a user browsing the app. This catalog
// names every capability so a prospect/user KNOWS we have it, grouped by category, each
// tagged by how you reach it. It is a MANIFEST, not a runner — nothing here fetches. The
// runnable subset lives in enrich.ts; this is the full inventory a human reads.
//
// Sourced from the backend registry (investigations/enrich/registry.py — 39 adapters),
// the kipi-osint MCP server (investigations/agent/osint_mcp.py), and the OSINT skill
// (q-investigate/skills/osint/references/tools.md — the 55+ Apify actor catalog + 7 search
// APIs). Keep this in sync when adapters are added there; it is hand-maintained on purpose
// (the client is 100% browser-side and cannot read the backend registry at runtime).

/** How a user reaches a capability. Drives the badge on each catalog row. */
export type CapAccess =
  | "free" // keyless — runs now in the free browser tool, no key, no cost
  | "key" //  bring your own API key IN THE FREE APP, then it runs (a browser-native / CORS-open provider)
  | "pro"; // free/pro split (founder 2026-07-08): NOT browser-native (needs a proxy / Apify / MCP / runs
//           server-side), so it lives in the paid tool. Shown here as a locked upsell — the nudge.

export interface Capability {
  /** Human name shown on the row. */
  name: string;
  /** One line: what it does / what it enriches. */
  detail: string;
  /** How you reach it — sets the badge. */
  access: CapAccess;
  /** For `key` / `agent` rows that need a key: the env/key name, shown as a hint. */
  keyName?: string;
}

export interface CapabilityGroup {
  /** Section heading. */
  category: string;
  /** One line under the heading. */
  blurb: string;
  items: Capability[];
}

export const CAP_ACCESS_LABEL: Record<CapAccess, string> = {
  free: "Free",
  key: "Add key",
  pro: "Pro",
};

export const CAP_ACCESS_HINT: Record<CapAccess, string> = {
  free: "Keyless — runs now in the free browser tool, no token needed",
  key: "Turns on when you add your own API key in the app (you supply it, it stays in your vault) — a browser-native provider",
  pro: "In the pro tool — needs a proxy or runs server-side (not browser-native), so it isn't in this free app",
};

// The one-line promise at the top of the page: the FREE browser tool is bring-your-own-key for the
// browser-native providers; the Pro-tagged rows (a proxy / Apify / server-side) live in the paid tool.
// PRD prd-hydra-free-osint-providers finding-4 (privacy contract): the browser-side DISCLOSURE surface. Every
// free provider fetch goes DIRECT from your browser to that provider, so the provider sees the one target you
// ask about (and your IP, as with any web request) — never anything else, and never us. This states, per
// target kind, which provider receives what, so the disclosure is explicit before you run a lookup. It is
// CONCATENATED into CAP_BYO_NOTE below (the string pages.ts already renders on the capabilities page), so the
// disclosure is live without touching the renderer.
export const CAP_DISCLOSURE_NOTE =
  "Browser-side disclosure: each provider receives the single target you query, sent directly from your browser (not through us) — which means, as with any direct web request, that provider also sees your IP address and request metadata (browser, headers). An IP goes to the IP tools (Shodan InternetDB, RIPEstat, ip.guide, ipwho.is, StopForumSpam, SANS ISC); a domain to the DNS / certificate-transparency / breach-catalog tools (crt.sh, certspotter, HIBP catalog); a Bitcoin/Ethereum address to the on-chain explorers (mempool, Blockstream, BlockCypher, Blockscout); a handle to the identity tools (GitHub, GitLab, Hacker News, npm); an email to the breach/disposable tools (XposedOrNot, debounce, Kickbox) — a breach-DB match is a lead, never proof; a company name to the registry tools (GLEIF, Wikidata). No case data, keys, or other targets leave your browser, and nothing goes to us. Use your own proxy tier if you need to shield your IP from a provider.";

// Rendered on the capabilities page (pages.ts: elt("p", "cap-byo", CAP_BYO_NOTE)). The finding-4 disclosure is
// concatenated in so it ships as part of the already-rendered note.
export const CAP_BYO_NOTE =
  "The free browser tool is bring-your-own-key: add your own key and the browser-native providers run, nothing bundled. Rows tagged Pro aren't browser-native (they need a proxy or run server-side) — those live in the pro tool. " +
  CAP_DISCLOSURE_NOTE;

export const OSINT_CAPABILITIES: CapabilityGroup[] = [
  {
    category: "Infrastructure pivots",
    blurb: "Non-fakeable records off a domain or IP — the T1 backbone of attribution.",
    items: [
      { name: "crt.sh certificate transparency", detail: "Enumerate subdomains from public CT logs", access: "free" },
      { name: "certspotter CT", detail: "Second CT source — subdomains + issuing CA, keyless", access: "free" },
      { name: "WHOIS / DNS / reverse-DNS", detail: "Registrar, registrant, A/AAAA/MX/TXT/NS, PTR", access: "free" },
      { name: "Reverse-IP co-hosted domains", detail: "IP → other domains on the same host, keyless (HackerTarget)", access: "free" },
      { name: "Deep DNS (SPF / DMARC / AXFR)", detail: "Mail-provider fingerprint + zone-transfer attempt", access: "free" },
      { name: "ASN / netblock owner", detail: "IP → ASN → netblock owner (Team Cymru)", access: "free" },
      { name: "IP geolocation", detail: "Geo + ASN + netblock owner (ip-api / IPinfo)", access: "free" },
      { name: "IP geolocation (keyless)", detail: "Geo + ASN + operator, no key (ip.guide / ipwho.is)", access: "free" },
      { name: "Shodan InternetDB", detail: "Keyless IP → open ports, CVEs, hostnames, tags", access: "free" },
      { name: "RIPEstat routing", detail: "IP → announcing ASN + BGP prefix (RIPE collectors)", access: "free" },
      { name: "Typosquat / lookalike domains", detail: "dnstwist candidates, DNS-confirmed", access: "free" },
      { name: "urlscan.io", detail: "Related infrastructure urlscan already saw", access: "free" },
      { name: "Shodan", detail: "Open ports, services, CVEs on a host", access: "key", keyName: "SHODAN_API_KEY" },
      { name: "Censys", detail: "Host services, ports, TLS, ASN", access: "key", keyName: "CENSYS_PLATFORM_TOKEN" },
      { name: "WhoisXML", detail: "Reverse-WHOIS portfolio + historical passive DNS + reverse-NS", access: "pro", keyName: "WHOISXML_API_KEY" },
    ],
  },
  {
    category: "Threat & reputation",
    blurb: "Is this indicator known-bad? Reputation, IOC, and scanner classification.",
    items: [
      { name: "Crypto scam blocklists", detail: "Scam Sniffer known-scam wallets/domains", access: "free" },
      { name: "StopForumSpam", detail: "IP crowd-reported spam/abuse frequency (keyless)", access: "free" },
      { name: "SANS ISC / DShield", detail: "IP attack-report history + threat-feed membership (keyless)", access: "free" },
      { name: "VirusTotal", detail: "Reputation + detection stats for domain/IP/hash/URL", access: "pro", keyName: "VIRUSTOTAL_API_KEY" },
      { name: "abuse.ch (URLhaus + ThreatFox)", detail: "Malware URL + IOC feeds", access: "pro", keyName: "ABUSECH_AUTH_KEY" },
      { name: "AlienVault OTX", detail: "Threat pulses + passive DNS", access: "key", keyName: "OTX_API_KEY" },
      { name: "GreyNoise", detail: "Internet-scanner vs targeted classification", access: "pro", keyName: "GREYNOISE_API_KEY" },
      { name: "AbuseIPDB", detail: "IP abuse-confidence score + reports", access: "pro", keyName: "ABUSEIPDB_API_KEY" },
    ],
  },
  {
    category: "Breach & identity exposure",
    blurb: "What has leaked about an email, handle, or person.",
    items: [
      { name: "HudsonRock breach intel", detail: "Infostealer / breach exposure for an email or domain", access: "free" },
      { name: "XposedOrNot", detail: "Email → breach-DB match (keyless T3 lead, never proof)", access: "free" },
      { name: "HIBP breach catalog", detail: "Domain → site-breach context, keyless (per-email lookup is keyed)", access: "free" },
      { name: "Disposable-email check", detail: "Email → throwaway flag, cross-checked (debounce + Kickbox)", access: "free" },
      { name: "Email triage + holehe", detail: "MX/SPF/DMARC + which of ~120 sites the email registered on", access: "free" },
      { name: "Gravatar", detail: "Email → profile + linked social accounts", access: "free" },
      { name: "Username presence sweep", detail: "Handle presence across curated platforms", access: "free" },
      { name: "GitHub profile", detail: "Handle → name, company, blog, linked Twitter, public email (keyless)", access: "free" },
      { name: "GitHub (token)", detail: "Same, higher rate limit with your GitHub token", access: "key", keyName: "GITHUB_TOKEN" },
      { name: "GitLab profile", detail: "Handle → profile, name, public email (keyless)", access: "free" },
      { name: "GitLab (token)", detail: "Same, higher rate limit with your GitLab token", access: "key", keyName: "GITLAB_TOKEN" },
      { name: "Hacker News profile", detail: "Handle → account + any site/email in the bio (keyless)", access: "free" },
      { name: "npm maintainer", detail: "Handle → published packages, source repos, publisher email (keyless)", access: "free" },
      { name: "Git commit-author email mining", detail: "Emails from a repo's commit history", access: "free" },
      { name: "Identity lookups (Keybase / GitHub / Mastodon / LeakCheck)", detail: "Keyless cross-platform identity + leak checks", access: "pro" },
      { name: "Have I Been Pwned", detail: "Breach exposure for an email or domain", access: "pro", keyName: "HIBP_API_KEY" },
    ],
  },
  {
    category: "Blockchain / on-chain",
    blurb: "Wallet balances, transaction flow, clustering, and sanctions — 10 chains & rails.",
    items: [
      { name: "Bitcoin", detail: "Balance + transaction counterparties (keyless)", access: "free" },
      { name: "Bitcoin (Blockstream + BlockCypher)", detail: "2nd/3rd independent BTC sources to cross-check balance + tx count", access: "free" },
      { name: "Ethereum (Blockscout)", detail: "Keyless ETH balance + ENS name + scam flag", access: "free" },
      { name: "Tron (TRC-20)", detail: "USDT-rail transfers", access: "free" },
      { name: "Solana (SPL)", detail: "Transaction signatures + counterparties", access: "free" },
      { name: "Blockchair (BTC / LTC / BCH / DOGE)", detail: "Multi-chain balance + activity", access: "free" },
      { name: "TON", detail: "Balance + counterparties", access: "free" },
      { name: "WalletExplorer clustering", detail: "BTC exchange-cluster (subpoena target)", access: "free" },
      { name: "Etherscan public labels", detail: "Exchange / mixer / phish address labels", access: "free" },
      { name: "ENS resolution", detail: "Forward + reverse .eth ↔ address", access: "free" },
      { name: "OFAC sanctions screen", detail: "OFAC SDN + Chainalysis sanctions oracle", access: "free" },
      { name: "Ethereum + ERC-20", detail: "ETH tx + USDT/USDC token flow", access: "key", keyName: "ETHERSCAN_API_KEY" },
    ],
  },
  {
    category: "Corporate & entity resolution",
    blurb: "Who is this company / entity? Registry identity, ownership, aliases, and handles.",
    items: [
      { name: "GLEIF LEI registry", detail: "Company → LEI, jurisdiction, address, status, ownership (keyless, T1)", access: "free" },
      { name: "Wikidata entity resolution", detail: "Name → aliases, official site, social handles (keyless, T3 lead)", access: "free" },
    ],
  },
  {
    category: "Web search & research",
    blurb: "Cited, AI-grounded search across four engines plus keyless web search.",
    items: [
      { name: "Brave web search", detail: "General web discovery (free tier, no key)", access: "free" },
      { name: "Perplexity Sonar / Deep / Reasoning", detail: "Cited AI search, auto-escalates to reasoning", access: "key", keyName: "PERPLEXITY_API_KEY" },
      { name: "Exa AI", detail: "Neural / semantic search + company + people", access: "pro", keyName: "EXA_API_KEY" },
      { name: "Tavily", detail: "Agent web search + page extract", access: "key", keyName: "TAVILY_API_KEY" },
      { name: "Jina Reader", detail: "Any page → clean text for the agent", access: "key", keyName: "JINA_API_KEY" },
      { name: "Bright Data", detail: "Geo-targeted Google/Bing/Yandex + CAPTCHA / authwall bypass", access: "pro", keyName: "BRIGHTDATA_MCP_URL" },
    ],
  },
  {
    category: "Social media scraping",
    blurb: "55+ Apify actors across every major platform — profiles, posts, comments, followers. Run by the investigator agent with an Apify token.",
    items: [
      { name: "Instagram (12 actors)", detail: "Profiles, posts, comments, hashtags, reels, followers, tagged", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "Facebook (14 actors)", detail: "Pages, groups, marketplace, ads, events, reviews, contact info", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "TikTok (14 actors)", detail: "Profiles, videos, comments, followers, hashtags, trends", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "YouTube (5 actors)", detail: "Channels, comments, shorts, videos", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "Twitter / X", detail: "Profiles + tweets (curious_coder scraper)", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "LinkedIn", detail: "Public profile scrape", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "Telegram", detail: "Channel / group content via Apify", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "Google Maps (4 actors)", detail: "Places, reviews, business-email extraction", access: "pro", keyName: "APIFY_TOKEN" },
      { name: "Reddit", detail: "Search, users, posts, subreddits (keyless MCP)", access: "pro" },
      { name: "Apify store (2,000+ more)", detail: "Dynamic actor discovery when none of the above fit", access: "pro", keyName: "APIFY_TOKEN" },
    ],
  },
  {
    category: "Company, registry & forensics",
    blurb: "Corporate records, dark web, and file forensics.",
    items: [
      { name: "OpenCorporates", detail: "Company registry officers + filings", access: "free" },
      { name: "Ahmia dark web index", detail: "Search the .onion index (T3 leads)", access: "free" },
      { name: "EXIF forensics", detail: "GPS coordinates + device make/model/serial from an image", access: "free" },
      { name: "Security-stack recon", detail: "Profile a company's security tools from job posts + ATS + LinkedIn (~110-vendor dictionary)", access: "pro" },
    ],
  },
];

/** Flat counts for the page header — computed once from the catalog above. */
export function capabilityCounts(): { total: number; free: number; key: number; pro: number } {
  const all = OSINT_CAPABILITIES.flatMap((g) => g.items);
  return {
    total: all.length,
    free: all.filter((c) => c.access === "free").length,
    key: all.filter((c) => c.access === "key").length,
    pro: all.filter((c) => c.access === "pro").length,
  };
}
