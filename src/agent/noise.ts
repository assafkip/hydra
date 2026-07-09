// Deterministic graph-noise rules — a verbatim TS port of investigations/noise.py
// (the canonical source). It carries the type-specific checks that admission.is_admissible
// composes: phone shape (is_real_phone), registry/reference domain lists (is_noise_domain),
// and registry switchboard numbers (is_boilerplate_phone).
//
// WHY a separate module (not inline in gate.ts): the original splits noise.py from
// admission.py so the LISTS live in ONE place and every creation path inherits a new rule by
// editing here (RCA rca-recurring-graph-noise-2026-06-11; memory graph-noise-needs-one-admission-gate).
// The first web port folded a WEAKER copy inline into gate.ts and 9 junk classes the original
// rejects leaked onto the graph (bare-id "phones", registrar/reference domains, whois/nameserver
// boilerplate) — proven 9/9 over-admissions 2026-06-22. This restores parity at the single source.

// Registry / WHOIS / registrar boilerplate — present in essentially every whois/RDAP response,
// never the target. Matched on host + registrable domain (noise.py:_BOILERPLATE_DOMAINS).
const BOILERPLATE_DOMAINS = new Set<string>([
  "iana.org", "icann.org", "verisign-grs.com", "verisign.com", "pir.org",
  "publicinterestregistry.org", "internic.net", "afilias.net", "identitydigital.com",
  "centralnic.com", "markmonitor.com", "cscglobal.com", "csc.com", "registry.google",
  "gandi.net", "namecheap.com", "godaddy.com", "publicdomainregistry.com",
  "tucows.com", "enom.com", "key-systems.net", "namesilo.com", "dynadot.com",
  // ccTLD registry NICs: a whois of any .is domain returns ISNIC's own contacts.
  "isnic.is",
  "globaldomaingroup.com", "name-services.com", "registrar-servers.com",
]);
// Lookup / tooling services the AGENT ITSELF uses — their hostnames appear in tool output
// (the crt.sh query URL, an ip-api lookup link, a pydantic traceback's docs URL) and are
// parser exhaust, never target infrastructure (noise.py:_LOOKUP_TOOL_DOMAINS).
const LOOKUP_TOOL_DOMAINS = new Set<string>(["crt.sh", "ip-api.com", "pydantic.dev"]);
// Security-news / threat-reporting outlets — they cover scams, they are not the scam infra
// (noise.py:_REFERENCE_DOMAINS).
const REFERENCE_DOMAINS = new Set<string>([
  "krebsonsecurity.com", "bleepingcomputer.com", "thehackernews.com", "therecord.media",
  "scamadviser.com", "scamwatch.gov.au", "ic3.gov", "ftc.gov", "securityweek.com",
  "darkreading.com", "welivesecurity.com", "malwarebytes.com", "trendmicro.com",
  "kaspersky.com", "sophos.com", "wikipedia.org",
  // Phishing/abuse blocklists + research feeds: they REPORT ON scams, not the scam's own infra.
  "phishdestroy.io", "phishtank.com", "phishtank.org", "openphish.com",
  "abuse.ch", "urlhaus.abuse.ch", "threatfox.abuse.ch", "urlscan.io",
  "virustotal.com", "spamhaus.org",
  // Writeups reporting ON a phishing kit / scam — sources, not infrastructure.
  "thereallo.dev", "fullcoll.edu",
]);
const NOISE_DOMAINS = new Set<string>([
  ...BOILERPLATE_DOMAINS, ...REFERENCE_DOMAINS, ...LOOKUP_TOOL_DOMAINS,
]);

// Registry contact phone numbers (normalized digits) — published in every whois answer for
// that registry's TLD, the registry's switchboard, never the target (noise.py:_BOILERPLATE_PHONE_DIGITS).
const BOILERPLATE_PHONE_DIGITS = new Set<string>([
  "3545782030", // ISNIC (.is registry), +354 578 2030
]);

// Shared DNS-provider nameservers — boilerplate like CDN IPs. Matched as a host substring
// (noise.py:_NAMESERVER_MARKERS).
const NAMESERVER_MARKERS = [
  "ns.cloudflare.com", "awsdns", "nsone.net", "dnsmadeeasy.com", "googledomains.com",
  "azure-dns.", "domaincontrol.com", "registrar-servers.com", "name-services.com",
  "dns.he.net", "ns.namecheap.com",
];

/** Bare host from a domain or URL value (strip scheme, path, query, userinfo, port, www., and
 *  surrounding dots). Verbatim port of noise.py:_host — note it strips userinfo, so an email
 *  value resolves to its domain part. */
function host(value: string): string {
  let s = (value || "").trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.\-]*:\/\//, ""); // scheme
  s = s.split("/")[0].split("?")[0].split("#")[0];
  s = s.split("@").pop() as string; // userinfo
  s = s.split(":")[0]; // port
  s = s.replace(/^\.+/, "").replace(/\.+$/, ""); // surrounding dots
  return s.replace(/^www\./, "");
}

/** Crude registrable domain (last two labels) — noise.py:_registrable. The denylist holds no
 *  multi-part TLDs, so the simple two-label form is safe for matching. */
function registrable(h: string): string {
  const parts = h.split(".").filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join(".") : h;
}

/** A registry/WHOIS/registrar boilerplate domain, a WHOIS-server host, a shared-nameserver host,
 *  or a known threat-reporting outlet — graph noise, not target infrastructure. Port of
 *  noise.py:is_noise_domain. */
export function isNoiseDomain(value: string): boolean {
  const h = host(value);
  if (!h) return false;
  if (h.startsWith("whois.") || h.includes(".whois-servers.")) return true;
  if (NAMESERVER_MARKERS.some((m) => h.includes(m))) return true;
  const reg = registrable(h);
  return NOISE_DOMAINS.has(h) || NOISE_DOMAINS.has(reg);
}

/** True only for a value shaped like a real phone number. A bare digit run with no '+' prefix
 *  and no formatting separators (164736471) is an ID / tracking number, NOT a phone. Port of
 *  noise.py:is_real_phone — including the NANP rule (a '+1...' must be exactly 11 digits; a
 *  shorter '+1703925' is a truncated id wearing a plus, not a phone). */
export function isRealPhone(value: string): boolean {
  const s = (value || "").trim();
  const digits = s.replace(/[\s().+\-]/g, "");
  // \p{Nd} (any Unicode decimal digit), NOT /^\d+$/ (ASCII only): Python's str.isdigit() accepts
  // Arabic-Indic / Farsi decimals, and kipi's target cases are Iranian/Arabic — an ASCII-only test
  // would drop a real Farsi phone the original keeps (codex review, 2026-06-22).
  if (!/^\p{Nd}+$/u.test(digits) || digits.length < 7 || digits.length > 15) return false;
  // NANP (+1) numbers are exactly 11 digits (1 + 10). A shorter '+1...' run is a truncated id.
  if (s.startsWith("+1") && digits.length !== 11) return false;
  return s.startsWith("+") || /[\s().\-]/.test(s);
}

/** A registry's own published contact number (whois boilerplate) — a real phone, but never the
 *  target's. Matched on normalized digits, with or without country '+'. Port of
 *  noise.py:is_boilerplate_phone. */
export function isBoilerplatePhone(value: string): boolean {
  const digits = (value || "").replace(/[\s().+\-]/g, "");
  return BOILERPLATE_PHONE_DIGITS.has(digits);
}
