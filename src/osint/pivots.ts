// ip-pivot: per-entity OSINT pivot LINKS — a verbatim port of analyze.py:PIVOT_TEMPLATES +
// populate_enrichment_links. For an entity (value + type) it returns the external research URLs an
// analyst CLICKS to pivot (Shodan/VirusTotal/Etherscan/urlscan/PublicWWW/…).
//
// WHY this is browser-safe (and NOT blocked like the enrich ADAPTERS): these are LINKS the analyst
// opens in a new tab, not fetches. The CORS / BYO-key limits that gate the enrich adapters do not
// apply to a hyperlink — so the whole template set ports, unchanged, with no key and no network.

export interface PivotLink {
  label: string;
  url: string;
}

// Verbatim from analyze.py:PIVOT_TEMPLATES. {value} = the raw entity; {strip} = @ and scheme removed
// (the original's value_strip). The telegram first link resolved to t.me/{strip} in the original (its
// conditional evaluated the literal "{value}", which never starts with http — so the else branch always won).
const TEMPLATES: Record<string, [string, string][]> = {
  ip: [
    ["Shodan", "https://www.shodan.io/host/{value}"],
    ["AbuseIPDB", "https://www.abuseipdb.com/check/{value}"],
    ["Censys", "https://search.censys.io/hosts/{value}"],
    ["VirusTotal", "https://www.virustotal.com/gui/ip-address/{value}"],
  ],
  domain: [
    ["urlscan.io", "https://urlscan.io/domain/{value}"],
    ["VirusTotal", "https://www.virustotal.com/gui/domain/{value}"],
    ["DNSdumpster", "https://dnsdumpster.com/?domain={value}"],
  ],
  url: [["urlscan.io", "https://urlscan.io/search/#{value}"]],
  telegram_channel: [
    ["Open in Telegram", "https://t.me/{strip}"],
    ["TGStat", "https://tgstat.com/channel/@{strip}"],
  ],
  handle: [
    ["Sherlock search", "https://www.google.com/search?q=%22{value}%22"],
    ["X/Twitter", "https://x.com/search?q={strip}"],
  ],
  email: [
    ["Have I Been Pwned", "https://haveibeenpwned.com/account/{value}"],
    ["Hunter.io", "https://hunter.io/email-verifier/{value}"],
  ],
  phone: [
    ["Truecaller", "https://www.truecaller.com/search/in/{value}"],
    ["Google search", "https://www.google.com/search?q=%22{value}%22"],
  ],
  crypto_wallet: [
    ["Etherscan", "https://etherscan.io/address/{value}"],
    ["Chainabuse", "https://www.chainabuse.com/address/{value}"],
    ["Blockchair (multi-chain)", "https://blockchair.com/search?q={value}"],
    ["Arkham", "https://platform.arkhamintelligence.com/explorer/address/{value}"],
  ],
  tracking_tag: [
    ["PublicWWW (sites using this tag)", "https://publicwww.com/websites/%22{value}%22/"],
    ["DNSlytics reverse analytics", "https://dnslytics.com/reverse-analytics/{value}"],
    ["BuiltWith relationships", "https://builtwith.com/relationships/tag/{value}"],
  ],
  walletconnect_id: [
    ["WalletConnect Cloud (owner)", "https://cloud.walletconnect.com/"],
    ["PublicWWW (dApps using this id)", "https://publicwww.com/websites/%22{value}%22/"],
  ],
  saas_service_account: [["PublicWWW (sites with this id)", "https://publicwww.com/websites/%22{value}%22/"]],
  nameserver: [
    ["Domains on this nameserver", "https://securitytrails.com/list/ns/{value}"],
    ["HackerTarget reverse NS", "https://hackertarget.com/find-dns-records/?q={value}"],
  ],
  registrar: [["ICANN registrar lookup", "https://lookup.icann.org/en/lookup"]],
  hash_sha256: [["VirusTotal", "https://www.virustotal.com/gui/file/{value}"]],
  hash_md5: [["VirusTotal", "https://www.virustotal.com/gui/file/{value}"]],
};

// Web entity-type → template key (the original keyed on crypto_wallet/ip; the web extractor emits
// wallet/ip_address). Mirror cy-adapter's TYPE_ALIASES so the same entity resolves identically.
const TYPE_TO_TEMPLATE: Record<string, string> = {
  wallet: "crypto_wallet",
  crypto_wallet: "crypto_wallet",
  ip_address: "ip",
  ip: "ip",
};

/** value with @ and scheme stripped — the original's value_strip (used by t.me / handle templates). */
function strip(value: string): string {
  return value.replace(/^@+/, "").replace(/^https?:\/\//i, "");
}

/**
 * The clickable OSINT pivot links for one entity (analyze.py:populate_enrichment_links). Empty when the
 * type has no templates. The value is URL-encoded so a handle/value with spaces or `#` can't break the
 * link or inject query params (the original wrote raw DB rows; in the browser the value reaches an href,
 * so it must be encoded — a quote-pivot like PublicWWW %22{value}%22 keeps its surrounding quotes).
 */
export function pivotLinks(value: string, type: string): PivotLink[] {
  const key = TYPE_TO_TEMPLATE[(type || "").trim().toLowerCase()] ?? (type || "").trim().toLowerCase();
  const templates = TEMPLATES[key];
  if (!templates || !value) return [];
  const enc = encodeURIComponent(value);
  const encStrip = encodeURIComponent(strip(value));
  return templates.map(([label, tpl]) => ({
    label,
    url: tpl.replace(/\{value\}/g, enc).replace(/\{strip\}/g, encStrip),
  }));
}
