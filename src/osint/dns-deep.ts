// A6 DNS-deep: SPF + DMARC mail-policy records, ported from investigations/enrich/infra.py:271
// (the deep-DNS sweep). doh.ts already resolves A/AAAA/NS/MX; this adds the mail-authentication
// TXT records that reveal a domain's mail infrastructure — the included sending domains and IP
// authorizations (SPF) and the report-collection addresses (DMARC). Those `include:`/`ip4:`/`ip6:`
// mechanisms are real pivots: a scam domain's SPF that includes a shared sender, or a DMARC rua that
// points at an operator's mailbox, crosslinks infrastructure the basic resolve misses.
//
// AXFR (zone transfer) is part of the original's deep sweep but needs a RAW TCP connection to port 53
// — a browser cannot open it (same class as the port-43 WHOIS limit, docs/17). It is SIGNED-BLOCKED
// here, not faked: the adapter does SPF + DMARC (both plain TXT over DoH) and notes AXFR is N/A.
//
// T1: a TXT/SPF/DMARC record is a non-fakeable published DNS record (same tier as doh.ts).
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const DOH = "https://dns.google/resolve";
// STRICT shapes (codex High): an SPF/DMARC TXT is attacker-influenceable, so a parsed pivot is only
// emitted (as T1 infra) when it is a real domain / IPv4 / IPv6 — never anything that merely contains a dot.
// The label char class allows a LEADING underscore (SPF/DMARC hostnames legitimately use `_spf.`,
// `_dmarc.` labels per RFC) but the TLD stays strict alpha.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const IPV6_RE = /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const isDomain = (v: string): boolean => DOMAIN_RE.test(v);

interface DohResp {
  Status: number;
  Answer?: { type: number; data: string }[];
}

async function txtRecords(name: string, opts: OsintOpts): Promise<string[]> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${DOH}?name=${encodeURIComponent(name)}&type=TXT`, {
        headers: { accept: "application/dns-json" },
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`DoH TXT HTTP ${res.status}`);
      return (await res.json()) as DohResp;
    },
    opts.retries ?? 0,
    undefined,
    opts.signal,
  );
  // DoH returns TXT data as a quoted string (possibly multiple concatenated chunks) — strip the quotes.
  return (json.Answer ?? []).filter((a) => a.type === 16).map((a) => a.data.replace(/^"|"$/g, "").replace(/" "/g, ""));
}

/** Parse an SPF record's mechanisms into typed entities: include:/redirect= domains, a:/mx: hostnames,
 *  ip4:/ip6: addresses. The bare `a`/`mx` (no host) reference the domain itself — skipped (not a pivot). */
function parseSpf(spf: string, domain: string): OsintEntity[] {
  const out: OsintEntity[] = [];
  for (const tok of spf.split(/\s+/)) {
    const m = tok.match(/^(?:\+|-|~|\?)?(include|redirect|a|mx|ip4|ip6|exists|ptr)[:=]?(.*)$/i);
    if (!m) continue;
    const mech = m[1].toLowerCase();
    const arg = m[2].trim().toLowerCase().replace(/\.$/, "");
    if (["include", "redirect", "exists", "ptr", "a", "mx"].includes(mech) && isDomain(arg)) {
      out.push({ type: "domain", value: arg, note: `SPF ${mech} of ${domain}` });
    } else if (mech === "ip4") {
      const ip = arg.split("/")[0];
      if (IPV4_RE.test(ip)) out.push({ type: "ip", value: ip, note: `SPF ip4 of ${domain}` });
    } else if (mech === "ip6") {
      const ip = m[2].trim().split("/")[0]; // ipv6 is case-bearing hex; don't lowercase-mangle the mask split
      if (IPV6_RE.test(ip)) out.push({ type: "ip", value: ip, note: `SPF ip6 of ${domain}` });
    }
  }
  return out;
}

/** Parse a DMARC record's report URIs (rua/ruf mailto:) into the report-collection DOMAINS — a real
 *  crosslink (a third-party DMARC aggregator, or the operator's own mailbox domain). EntityType has no
 *  email, so the mailbox DOMAIN is the emitted pivot; the policy (p=) rides in the note. */
function parseDmarc(dmarc: string, domain: string): OsintEntity[] {
  const out: OsintEntity[] = [];
  const policy = dmarc.match(/\bp=([a-z]+)/i)?.[1] ?? "none";
  for (const m of dmarc.matchAll(/\b(?:rua|ruf)=([^;]+)/gi)) {
    for (const uri of m[1].split(",")) {
      const addr = uri.trim().replace(/^mailto:/i, "");
      const at = addr.lastIndexOf("@");
      if (at >= 0) {
        const host = addr.slice(at + 1).toLowerCase().replace(/\.$/, "");
        if (isDomain(host)) out.push({ type: "domain", value: host, note: `DMARC report domain (p=${policy}) of ${domain}` });
      }
    }
  }
  return out;
}

/**
 * Deep DNS: the SPF (on the domain) + DMARC (on _dmarc.<domain>) TXT records, parsed into the mail-infra
 * pivots they authorize. Returns the included sending domains + authorized IPs + DMARC report domains.
 * AXFR is browser-blocked (signed) and noted in `query`, never faked. A domain with no SPF/DMARC yields
 * an empty entity set (not an error) — many domains publish neither.
 */
export async function dnsDeep(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const bare = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  if (!bare || !bare.includes(".")) throw new Error("dns_deep: pass a bare domain (e.g. example.com)");
  const entities: OsintEntity[] = [];
  let found: string[] = [];

  const spfTxts = await txtRecords(bare, opts);
  const spf = spfTxts.find((t) => /^v=spf1\b/i.test(t.trim()));
  if (spf) { entities.push(...parseSpf(spf, bare)); found.push("SPF"); }

  const dmarcTxts = await txtRecords(`_dmarc.${bare}`, opts);
  const dmarc = dmarcTxts.find((t) => /^v=DMARC1\b/i.test(t.trim()));
  if (dmarc) { entities.push(...parseDmarc(dmarc, bare)); found.push("DMARC"); }

  return {
    provider: "dns-deep",
    query: `${bare} — ${found.length ? found.join("+") + " parsed" : "no SPF/DMARC published"}; AXFR N/A in-browser (raw TCP, signed-blocked)`,
    tier: "T1",
    // every entity is already shape-validated at parse time (isDomain/isIp); this is the dedup pass.
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
