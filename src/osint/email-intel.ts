// Email intel (restore-osint-tool-belt 2026-06-24, port of investigations/enrich/email_intel.py).
// Two keyless modes, both browser-direct — no new origin, no key:
//   triage   user@domain  -> MX records, SPF posture, DMARC policy, provider id, disposable-domain flag.
//            All over the dns.google DoH endpoint already in the CSP connect-src (same as dns-deep.ts).
//   headers  raw RFC-822 header block -> the Received hop chain + every public source IP as a pivot.
//            PURE text parsing — NO network at all.
// Tier: triage is T1 (published DNS records, like dns-deep). headers is T3 — a pasted header block is
// user-supplied and forgeable, so its IPs are LEADS to pivot on (dns/RDAP/VT), never a finding by themselves.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const DOH = "https://dns.google/resolve"; // already in CSP connect-src (dns-deep.ts precedent)

const MAX_HEADER_BYTES = 256_000; // hostile-input cap (a header block is KBs; a body is not headers)
const MAX_HOPS = 50; // Received hops beyond this are noise or abuse

// Curated disposable / throwaway mail domains (in-repo set — a curated core beats a rotting list,
// same stance as the Python adapter). Byte-faithful to email_intel.py DISPOSABLE_DOMAINS.
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com",
  "10minutemail.com", "temp-mail.org", "tempmail.com", "tempmail.dev",
  "yopmail.com", "trashmail.com", "dispostable.com", "getnada.com",
  "maildrop.cc", "mohmal.com", "mintemail.com", "throwawaymail.com",
  "fakeinbox.com", "spamgourmet.com", "mailnesia.com", "tempinbox.com",
  "emailondeck.com", "burnermail.io", "33mail.com", "anonaddy.me",
]);

// MX host suffix -> mail provider. Checked longest-suffix-first (olc.protection.outlook.com beats
// protection.outlook.com regardless of array order).
const MX_PROVIDERS: [string, string][] = [
  ["aspmx.l.google.com", "Google Workspace"],
  ["googlemail.com", "Google Workspace"],
  ["google.com", "Google Workspace"],
  ["protection.outlook.com", "Microsoft 365"],
  ["olc.protection.outlook.com", "Microsoft 365 (consumer)"],
  ["zoho.com", "Zoho Mail"],
  ["zoho.eu", "Zoho Mail"],
  ["protonmail.ch", "Proton Mail"],
  ["proton.me", "Proton Mail"],
  ["yandex.net", "Yandex Mail"],
  ["yandex.ru", "Yandex Mail"],
  ["mail.ru", "Mail.ru"],
  ["icloud.com", "Apple iCloud Mail"],
  ["pphosted.com", "Proofpoint (corporate filter)"],
  ["mimecast.com", "Mimecast (corporate filter)"],
  ["barracudanetworks.com", "Barracuda (corporate filter)"],
  ["mailgun.org", "Mailgun"],
  ["sendgrid.net", "SendGrid"],
  ["secureserver.net", "GoDaddy email"],
  ["emailsrvr.com", "Rackspace email"],
  ["ovh.net", "OVH email"],
];

const IPV4_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;
const IPV6_RE = /\b((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{1,40})\b/g;

interface DohResp {
  Status: number;
  Answer?: { type: number; data: string }[];
}

/** Mail provider from MX host suffixes; null when unrecognized. Longest suffix wins. */
export function identifyProvider(mxHosts: string[]): string | null {
  const byLength = [...MX_PROVIDERS].sort((a, b) => b[0].length - a[0].length);
  for (const host of mxHosts) {
    for (const [suffix, provider] of byLength) {
      if (host === suffix || host.endsWith("." + suffix)) return provider;
    }
  }
  return null;
}

/** Public (non-private, non-reserved) IPv4 in a header line, original order, deduped. IPv6 is collected
 *  permissively (the syntactic candidates) — a forged header's IPs are leads, validated downstream. */
export function publicIps(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(IPV4_RE)) {
    const ip = m[1];
    if (isPublicIpv4(ip) && !out.includes(ip)) out.push(ip);
  }
  for (const m of text.matchAll(IPV6_RE)) {
    const ip = m[1];
    // skip bare "::" loopbacks and link-local; keep routable-looking candidates as leads
    if (ip.includes(":") && ip.length > 4 && !/^(::1|fe80|fc|fd)/i.test(ip) && !out.includes(ip)) out.push(ip);
  }
  return out;
}

function isPublicIpv4(ip: string): boolean {
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n) || n > 255)) return false;
  if (o[0] === 10 || o[0] === 127 || o[0] === 0) return false;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
  if (o[0] === 192 && o[1] === 168) return false;
  if (o[0] === 169 && o[1] === 254) return false; // link-local
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false; // CGNAT
  if (o[0] >= 224) return false; // multicast / reserved
  return true;
}

async function dohRecords(name: string, type: "MX" | "TXT", opts: OsintOpts): Promise<string[]> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { accept: "application/dns-json" },
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`DoH ${type} HTTP ${res.status}`);
      return (await res.json()) as DohResp;
    },
    opts.retries ?? 0,
    undefined,
    opts.signal,
  );
  const wanted = type === "MX" ? 15 : 16;
  return (json.Answer ?? []).filter((a) => a.type === wanted).map((a) => a.data);
}

/** MX exchange hosts (preference-sorted, trailing dot stripped, lowercased). DoH MX data is "<pref> <host>". */
async function mxHosts(domain: string, opts: OsintOpts): Promise<string[]> {
  const raw = await dohRecords(domain, "MX", opts);
  const pairs: [number, string][] = [];
  for (const r of raw) {
    const parts = r.trim().split(/\s+/);
    const pref = Number(parts[0]);
    const host = (parts[1] ?? "").replace(/\.$/, "").toLowerCase();
    if (host) pairs.push([Number.isNaN(pref) ? 0 : pref, host]);
  }
  pairs.sort((a, b) => a[0] - b[0]);
  return pairs.map(([, h]) => h);
}

async function txtRecords(name: string, opts: OsintOpts): Promise<string[]> {
  // DoH TXT data is a quoted string (possibly multiple concatenated chunks) — strip the quotes.
  return (await dohRecords(name, "TXT", opts)).map((d) => d.replace(/^"|"$/g, "").replace(/" "/g, ""));
}

// ---------- mode: triage ----------

async function triage(email: string, opts: OsintOpts): Promise<OsintResult> {
  const addr = email.trim().toLowerCase();
  if (!addr.includes("@")) throw new Error("email_triage: pass user@domain");
  const domain = addr.slice(addr.lastIndexOf("@") + 1);
  if (!domain || !domain.includes(".")) throw new Error("email_triage: invalid domain in address");

  const mx = await mxHosts(domain, opts);
  const provider = identifyProvider(mx);

  const spfAll = (await txtRecords(domain, opts)).filter((t) => /^v=spf1\b/i.test(t.trim()));
  const spfPermerror = spfAll.length > 1; // >1 v=spf1 = RFC 7208 permerror (broken SPF) — itself intel

  // DMARC: exact domain, then fall back toward the org domain (parent labels down to 2; no PSL in keyless posture).
  let dmarc: string | null = null;
  let dmarcAt: string | null = null;
  const labels = domain.split(".");
  for (let i = 0; i < Math.max(1, labels.length - 1); i++) {
    const cand = labels.slice(i).join(".");
    if (cand.split(".").length < 2) break;
    const found = (await txtRecords(`_dmarc.${cand}`, opts)).find((t) => /^v=DMARC1\b/i.test(t.trim()));
    if (found) { dmarc = found; dmarcAt = cand; break; }
  }
  const dmarcPolicy = dmarc ? (dmarc.match(/\bp=([a-z]+)/i)?.[1]?.toLowerCase() ?? null) : null;
  const disposable = DISPOSABLE_DOMAINS.has(domain);

  const spfLine = spfPermerror
    ? "PERMERROR — multiple v=spf1 records (SPF is broken for receivers)"
    : spfAll.length ? spfAll[0].slice(0, 120) : "NONE (spoofable)";
  const dmarcLine = dmarc
    ? dmarc.slice(0, 120)
      + (dmarcPolicy ? ` — policy ${dmarcPolicy}` : "")
      + (dmarcAt && dmarcAt !== domain ? ` (inherited from ${dmarcAt})` : "")
    : "NONE (no policy)";
  const summary = [
    `domain: ${domain}`,
    `MX: ${mx.length ? mx.join(", ") : "NONE (no MX — implicit A-record fallback possible)"}`,
    `provider: ${provider ?? "unrecognized"}`,
    `SPF: ${spfLine}`,
    `DMARC: ${dmarcLine}`,
    `disposable: ${disposable ? "YES — throwaway domain" : "no"}`,
  ].join("\n");

  // The queried domain + each MX host are pivotable domain nodes (feed into dns/RDAP/crtsh).
  const entities: OsintEntity[] = [
    { type: "domain", value: domain, note: `email domain${provider ? ` (${provider})` : ""}${disposable ? " [DISPOSABLE]" : ""}` },
    ...mx.slice(0, 5).map((h) => ({ type: "mailserver" as const, value: h, note: `MX host for ${domain}` })),
  ];
  return { provider: "email_triage", query: addr, tier: "T1", entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`), summary };
}

// ---------- mode: headers ----------

interface Hop { hop: number; line: string; ips: string[] }

/** Received hop chain from raw headers. Hops keep header order (top = nearest, bottom = origin). The
 *  ORIGIN is the bottom-most hop carrying a public IP — the sender's exit point. */
export function parseReceivedChain(rawHeaders: string): {
  hops: Hop[]; originIp: string | null; xOriginatingIp: string | null;
  from: string | null; returnPath: string | null; authResults: string | null;
} {
  if (rawHeaders.length > MAX_HEADER_BYTES) {
    throw new Error(`email_headers: header block too large (> ${MAX_HEADER_BYTES} bytes) — paste headers only, not the body`);
  }
  // Headers end at the first blank line — drop any pasted body before parsing.
  const headerBlock = rawHeaders.split("\n\n", 1)[0].split("\r\n\r\n", 1)[0];
  const headers = unfoldHeaders(headerBlock);
  const received = headers.filter((h) => h.name === "received").slice(0, MAX_HOPS);
  const hops: Hop[] = received.map((h, i) => {
    const flat = h.value.split(/\s+/).join(" ");
    return { hop: i + 1, line: flat.slice(0, 300), ips: publicIps(flat) };
  });
  let originIp: string | null = null;
  for (let i = hops.length - 1; i >= 0; i--) {
    if (hops[i].ips.length) { originIp = hops[i].ips[0]; break; }
  }
  const get = (n: string) => headers.find((h) => h.name === n)?.value ?? null;
  const xo = get("x-originating-ip");
  const xOriginatingIp = xo ? (publicIps(xo)[0] ?? null) : null;
  const auth = get("authentication-results");
  return {
    hops, originIp, xOriginatingIp,
    from: get("from"), returnPath: get("return-path"),
    authResults: auth ? auth.split(/\s+/).join(" ").slice(0, 300) : null,
  };
}

/** Parse an RFC-822 header block into {name, value} pairs, unfolding continuation lines (leading
 *  whitespace) into their parent header. name is lowercased; value keeps original case. */
function unfoldHeaders(block: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  for (const rawLine of block.split(/\r?\n/)) {
    if (/^\s/.test(rawLine) && out.length) {
      out[out.length - 1].value += " " + rawLine.trim();
      continue;
    }
    const idx = rawLine.indexOf(":");
    if (idx <= 0) continue;
    out.push({ name: rawLine.slice(0, idx).trim().toLowerCase(), value: rawLine.slice(idx + 1).trim() });
  }
  return out;
}

async function headers(rawHeaders: string): Promise<OsintResult> {
  const raw = rawHeaders.trim();
  if (!raw || !raw.includes(":")) throw new Error("email_headers: paste raw RFC-822 headers as the input");
  const chain = parseReceivedChain(raw);
  if (!chain.hops.length) throw new Error("email_headers: no Received headers found in the pasted text");

  const hopLines = chain.hops.map((h) => `hop ${h.hop}: ${h.line.slice(0, 160)}${h.ips.length ? `  [IPs: ${h.ips.join(", ")}]` : ""}`);
  const meta = [
    `origin IP: ${chain.originIp ?? "not found"}`,
    `X-Originating-IP: ${chain.xOriginatingIp ?? "—"}`,
    `From: ${chain.from ?? "—"}`,
    `Return-Path: ${chain.returnPath ?? "—"}`,
    `Authentication-Results: ${chain.authResults ?? "—"}`,
  ];
  const summary = [...meta, "", ...hopLines].join("\n");

  // Each distinct source IP is a pivot lead (dns/RDAP/VT). The origin is flagged in its note.
  const ips: OsintEntity[] = [];
  const seen = new Set<string>();
  for (const h of chain.hops) {
    for (const ip of h.ips) {
      if (seen.has(ip)) continue;
      seen.add(ip);
      const isOrigin = ip === chain.originIp;
      ips.push({ type: "ip", value: ip, note: `${isOrigin ? "ORIGIN source IP" : "relay source IP"} (Received hop ${h.hop}) — pivot: dns/RDAP/VT` });
    }
  }
  return { provider: "email_headers", query: `${chain.hops.length} hops${chain.originIp ? ` — origin ${chain.originIp}` : ""}`, tier: "T3", entities: ips, summary };
}

/** Email triage (default) or, when the input looks like a pasted header block, the Received-chain pivot.
 *  Keyless; triage uses the dns.google DoH (CSP-allowed), headers is pure text (no network). */
export async function emailTriage(email: string, opts: OsintOpts = {}): Promise<OsintResult> {
  // Pasted headers self-identify even if the agent calls the triage tool by mistake.
  if (/received:/i.test(email)) return headers(email);
  return triage(email, opts);
}

/** Header-only pivot: raw RFC-822 headers -> the Received hop chain + source IPs. Pure text, no network. */
export async function emailHeaders(rawHeaders: string, _opts: OsintOpts = {}): Promise<OsintResult> {
  return headers(rawHeaders);
}
