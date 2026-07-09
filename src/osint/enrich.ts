// Chunk-5 enrich: the registry of keyed OSINT providers. The CORS-open providers are callable
// DIRECT from the browser with the user's key (no proxy, no founder infra — the Anthropic-key
// pattern); their fixed origins are in the CSP connect-src allowlist (en-csp). The blocked holdouts
// are shown in the UI as "needs the optional user-deployed Cloudflare-Worker proxy tier" — which IS
// built (proxy.ts + docs/cloudflare-worker-template.js + the User-proxy UI + tests); their origins are
// NOT in the CSP (proxy traffic goes to the user's *.workers.dev), and this file does not fetch them.
import type { OsintOpts, OsintResult } from "./types.js";
import { shodanHost } from "./shodan.js";
import { censysHost } from "./censys.js";
import { otxPassiveDns } from "./otx.js";
import { etherscanAddress } from "./etherscan.js";
import { urlscanSearch } from "./urlscan.js";
import { ipinfoIp } from "./ipinfo.js";
import { perplexitySearch } from "./perplexity.js";
// restore-tool-belt (2026-06-24): Jina reader — keyed, CORS-open (the ACTUAL GET response reflects ACAO,
// verified live in-browser 2026-06-24).
import { jinaRead } from "./jina.js";
// hydra-osint-provider-inputs (2026-07-08): Tavily — keyed, CORS-open. The OLD scar had it in the proxy
// tier ("its real POST response carries NO ACAO"); re-tested LIVE 2026-07-08 (Origin hydra) and Tavily now
// returns ACAO on BOTH the preflight AND the actual POST — they fixed their CORS. So it is DIRECT now (the
// scar discipline still holds: this decision was made off the ACTUAL response ACAO, not just OPTIONS).
import { tavilySearch } from "./tavily.js";
// finding-5: the keyed BYO-token variants of the free identity tools — same adapter, the vault token in the
// enrich auth slot lifts the rate limit (github 60→5000/hr, gitlab higher). The free keyless tools stay the
// default in OSINT_TOOLS; these register ONLY the higher-limit token path.
import { githubUser } from "./github-user.js";
import { gitlabUser } from "./gitlab-user.js";

export type ProviderId = "shodan" | "censys" | "otx" | "etherscan" | "urlscan" | "ipinfo" | "perplexity" | "jina" | "tavily" | "github" | "gitlab";
// A6: "query" is a free-text web-search target (Perplexity) — not an infra identifier. validateTarget
// accepts any non-empty string for it (a question, not a typed entity).
// finding-5: "username" is a bare handle target — the keyed BYO-token variant of the free identity tools.
export type TargetKind = "ip" | "domain" | "wallet" | "query" | "username";

export interface EnrichProvider {
  id: ProviderId;
  label: string;
  /** What target the provider takes — shown on the settings row (the card's description). */
  blurb: string;
  /** A short category chip shown on the enrich card (parity with the server provider catalog). */
  category: string;
  /** The provider's API-docs URL — the card's "docs ↗" link. */
  docsUrl: string;
  /** The CSP-allowlisted origin (en-csp). */
  origin: string;
  /** Where the key rides: a query param (in the URL by the provider's design) or a header. */
  auth: "query" | "header";
  /** The masked key input's placeholder. Censys needs the compound "API ID:Secret" (codex D5). */
  keyHint: string;
  /** The target kinds the provider accepts. */
  targets: TargetKind[];
  /** Whether a hit from this provider is a non-fakeable INFRA observation (a host/passive-DNS/on-chain/
   *  scan record) — it drives the gate's infra_source_count when the AGENT calls it as a tool (m3).
   *  Explicit per provider (codex D5: not a blanket true) so a later downgrade is one field; the gate
   *  still credits infra ONLY for infra-typed entities, so a provider's person/handle echo never inflates. */
  infra: boolean;
  /** A benign canonical target for the "Test" button's one live probe. */
  probe: string;
  /** Run the adapter: the user's key in the provider's auth slot, parse -> typed entities. */
  run(target: string, key: string, opts?: OsintOpts): Promise<OsintResult>;
}

export const ENRICH_PROVIDERS: EnrichProvider[] = [
  {
    id: "shodan",
    label: "Shodan",
    blurb: "IP host record — open ports, hostnames, ASN",
    category: "host-scan",
    docsUrl: "https://developer.shodan.io/",
    origin: "https://api.shodan.io",
    auth: "query",
    keyHint: "Shodan API key",
    targets: ["ip"],
    probe: "8.8.8.8",
    infra: true,
    run: (t, k, o) => shodanHost(t, k, o),
  },
  {
    id: "censys",
    label: "Censys",
    blurb: "IP host scan — DNS names, ASN",
    category: "host-scan",
    docsUrl: "https://search.censys.io/api",
    origin: "https://search.censys.io",
    auth: "header",
    keyHint: "API ID:Secret",
    targets: ["ip"],
    probe: "8.8.8.8",
    infra: true,
    run: (t, k, o) => censysHost(t, k, o),
  },
  {
    id: "otx",
    label: "AlienVault OTX",
    blurb: "Passive DNS for a domain or IP",
    category: "threat-intel",
    docsUrl: "https://otx.alienvault.com/api",
    origin: "https://otx.alienvault.com",
    auth: "header",
    keyHint: "OTX API key",
    targets: ["domain", "ip"],
    probe: "example.com",
    infra: true,
    run: (t, k, o) => otxPassiveDns(t, k, o),
  },
  {
    id: "etherscan",
    label: "Etherscan",
    blurb: "ETH address — recent on-chain counterparties",
    category: "blockchain",
    docsUrl: "https://docs.etherscan.io/",
    origin: "https://api.etherscan.io",
    auth: "query",
    keyHint: "Etherscan API key",
    targets: ["wallet"],
    probe: "0x0000000000000000000000000000000000000000",
    infra: true,
    run: (t, k, o) => etherscanAddress(t, k, o),
  },
  // finding-5: keyed BYO-token identity providers. The free github_user/gitlab_user tools run keyless; these
  // register the OPTIONAL token path (token in vault, rides the provider auth slot) for higher rate limits.
  // infra:false — a profile is a self-asserted T3 lead, so a keyed hit never inflates the gate's infra count.
  {
    id: "github",
    label: "GitHub",
    blurb: "GitHub username — profile, company, blog, email (higher rate limit)",
    category: "identity",
    docsUrl: "https://docs.github.com/en/rest/users",
    origin: "https://api.github.com",
    auth: "header",
    keyHint: "GitHub personal-access token",
    targets: ["username"],
    probe: "torvalds",
    infra: false,
    run: (t, k, o) => githubUser(t, o, k),
  },
  {
    id: "gitlab",
    label: "GitLab",
    blurb: "GitLab username — profile, name, public email (higher rate limit)",
    category: "identity",
    docsUrl: "https://docs.gitlab.com/ee/api/users.html",
    origin: "https://gitlab.com",
    auth: "header",
    keyHint: "GitLab personal-access token",
    targets: ["username"],
    probe: "gitlab-bot",
    infra: false,
    run: (t, k, o) => gitlabUser(t, o, k),
  },
  {
    id: "urlscan",
    label: "urlscan.io",
    blurb: "Scanned pages for a domain — domains, IPs, URLs",
    category: "web-scan",
    docsUrl: "https://urlscan.io/docs/api/",
    origin: "https://urlscan.io",
    auth: "header",
    keyHint: "urlscan API key",
    targets: ["domain"],
    probe: "example.com",
    infra: true,
    run: (t, k, o) => urlscanSearch(t, k, o),
  },
  {
    id: "ipinfo",
    label: "IPinfo",
    blurb: "IP record — hostname, ASN, geo",
    category: "ip-geo",
    docsUrl: "https://ipinfo.io/developers",
    origin: "https://ipinfo.io",
    auth: "query",
    keyHint: "IPinfo token",
    targets: ["ip"],
    probe: "8.8.8.8",
    infra: true,
    run: (t, k, o) => ipinfoIp(t, k, o),
  },
  {
    // A6 (parity osint_mcp perplexity, case-031 D2): web-search + reasoning-mode escalation. Target is a
    // free-text QUERY, not an infra id. infra:false + the adapter returns tier T3 — a search summary is
    // never citable, so its surfaced entities land as LEADS for an infra tool to confirm (q-investigation).
    id: "perplexity",
    label: "Perplexity",
    blurb: "Web search + reasoning for an attribution question (a free-text query, not an IP/domain)",
    category: "search",
    docsUrl: "https://docs.perplexity.ai/",
    origin: "https://api.perplexity.ai",
    auth: "header",
    keyHint: "Perplexity API key",
    targets: ["query"],
    probe: "what is example.com",
    infra: false, // a search summary is T3, NOT a non-fakeable infra observation
    run: (t, k, o) => perplexitySearch(t, k, o),
  },
  {
    // restore-tool-belt (2026-06-24): Jina Reader — read a URL into clean text. CORS-open with the user's
    // key (live preflight). Target is a URL passed as the query string; a fetched page read is T2, infra:false
    // (the entities in the page text are leads for a T1 infra tool to confirm).
    id: "jina",
    label: "Jina Reader",
    blurb: "Read a URL into clean text (pass the URL as the target)",
    category: "reader",
    docsUrl: "https://jina.ai/reader/",
    origin: "https://r.jina.ai",
    auth: "header",
    keyHint: "Jina API key (jina_…)",
    targets: ["query"],
    // Bare host (Jina resolves r.jina.ai/example.com to https://example.com). A literal "https://…" here
    // would be a string the leakgate scanner counts as an off-allowlist egress origin (it can't tell a
    // probe-target value from a fetch origin) — the other probes use bare hosts for the same reason.
    probe: "example.com",
    infra: false, // a page read is a T2 lead, NOT a non-fakeable infra observation
    run: (t, k, o) => jinaRead(t, k, o),
  },
  {
    // hydra-osint-provider-inputs (2026-07-08): Tavily agent web-search + page extract. CORS-open with the
    // user's Bearer key (live-verified — see tavily.ts). Target is a free-text QUERY (not an infra id). A
    // search summary is T3, so infra:false — the entities it names are LEADS a T1 infra tool must confirm.
    id: "tavily",
    label: "Tavily",
    blurb: "Agent web search + page extract for a question (a free-text query, not an IP/domain)",
    category: "search",
    docsUrl: "https://docs.tavily.com/",
    origin: "https://api.tavily.com",
    auth: "header",
    keyHint: "Tavily API key (tvly-…)",
    targets: ["query"],
    probe: "what is example.com",
    infra: false, // a search summary is T3, NOT a non-fakeable infra observation
    run: (t, k, o) => tavilySearch(t, k, o),
  },
];

export interface BlockedProvider {
  id: string;
  label: string;
}

/** CORS-BLOCKED keyed providers (no browser CORS as of 2026-06-17). Shown as a disabled
 *  "needs the optional proxy tier (not built)" section — a SEPARATE future chunk (PRD-5b, the
 *  user-deployed Cloudflare Worker). NOT fetched here; their origins are NOT in the CSP. */
export const BLOCKED_PROVIDERS: BlockedProvider[] = [
  { id: "virustotal", label: "VirusTotal" },
  { id: "greynoise", label: "GreyNoise" },
  { id: "securitytrails", label: "SecurityTrails" },
  { id: "abuseipdb", label: "AbuseIPDB" },
  { id: "pulsedive", label: "Pulsedive" },
  { id: "hunter", label: "Hunter.io" },
  // hydra-osint-provider-inputs (2026-07-08): Exa — CORS-blocked + POST-only, so it routes through the
  // user's worker (the POST branch). Shown in the proxy section like the six above.
  { id: "exa", label: "Exa" },
];

export interface KeyGuidance {
  /** false when the provider ALSO has a keyless free tool (github/gitlab) — the key only lifts the rate
   *  limit, it is not needed to run at all. true when the key is the only way to reach the provider. */
  required: boolean;
  /** Where to CREATE the key — the actual token page, distinct from docsUrl (the API reference). Rendered
   *  as the "Get a key ↗" anchor; a NAVIGATION target the user opens, never a browser fetch (its host is in
   *  leakgate ENRICH_DOC_HOSTS, not the CSP connect-src). */
  url: string;
  /** One line: how to get the key + any scope needed. Founder 2026-07-09 ("it's not clear what key I need
   *  from GitHub/GitLab"). */
  steps: string;
}

// Per-provider "how to get your key" — a typed Record<ProviderId,…> so TS forces an entry for EVERY
// provider (it can never silently miss one, the same no-drift discipline as the CSP parity test). The
// url is the token-CREATION page, not the API docs (docsUrl already covers those).
export const KEY_GUIDANCE: Record<ProviderId, KeyGuidance> = {
  shodan: { required: true, url: "https://account.shodan.io/", steps: "Create a free Shodan account — your API key is on the account overview." },
  censys: { required: true, url: "https://search.censys.io/account/api", steps: "Sign up → Account → API. Enter it here as ID:Secret (both halves, colon-separated)." },
  otx: { required: true, url: "https://otx.alienvault.com/api", steps: "Create a free OTX account — the OTX Key is under your API-integration settings." },
  etherscan: { required: true, url: "https://etherscan.io/myapikey", steps: "Register → API-KEYs → Add, then copy the key." },
  github: { required: false, url: "https://github.com/settings/tokens", steps: "Optional — GitHub already works keyless. To lift the rate limit: Developer settings → Personal access tokens (classic) → Generate. No scopes needed for public data." },
  gitlab: { required: false, url: "https://gitlab.com/-/user_settings/personal_access_tokens", steps: "Optional — GitLab already works keyless. To lift the rate limit: create a personal access token with the read_api scope." },
  urlscan: { required: true, url: "https://urlscan.io/user/apikey/", steps: "Register → Profile → API keys, then copy your key." },
  ipinfo: { required: true, url: "https://ipinfo.io/account/token", steps: "Sign up → Account → Token, then copy it." },
  perplexity: { required: true, url: "https://www.perplexity.ai/settings/api", steps: "Settings → API → generate a key (needs a small prepaid balance)." },
  jina: { required: true, url: "https://jina.ai/reader/", steps: "Grab a free key from the Jina Reader page (it starts with jina_)." },
  tavily: { required: true, url: "https://app.tavily.com/home", steps: "Sign up — the dashboard shows your tvly- key. Free tier available." },
};

export function keyGuidance(id: ProviderId): KeyGuidance {
  return KEY_GUIDANCE[id];
}

export function enrichProvider(id: string): EnrichProvider | undefined {
  return ENRICH_PROVIDERS.find((p) => p.id === id);
}

export function isBlockedProvider(id: string): boolean {
  return BLOCKED_PROVIDERS.some((p) => p.id === id);
}
