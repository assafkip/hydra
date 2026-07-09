// Team Cymru IP-to-ASN, over the dns.google DoH endpoint already in the CSP connect-src (dns-deep.ts
// precedent) — NO new egress origin (a56ffd8e tool-belt restore, founder 2026-06-25). Cymru publishes
// IP→ASN as DNS TXT: a reversed-octet query under origin.asn.cymru.com returns
// "ASN | BGP prefix | CC | registry | date" (an IP may be announced by >1 ASN), and AS<n>.asn.cymru.com
// returns the AS operator name. T1: the routing-table record (which AS announces an IP) is a non-fakeable
// infra signal, the same tier as a DNS or RDAP record.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://dns.google/resolve"; // already in CSP connect-src (dns-deep.ts / doh.ts precedent)

interface DohAnswer { name: string; type: number; data: string; }
interface DohResponse { Status: number; Answer?: DohAnswer[]; }

/** One TXT lookup via the CSP-allowed DoH resolver. Returns the unquoted TXT strings (cymru sends one). */
async function txt(name: string, opts: OsintOpts): Promise<string[]> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}?name=${encodeURIComponent(name)}&type=TXT`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/dns-json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`DoH TXT HTTP ${res.status}`);
      return (await res.json()) as DohResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  return (json.Answer ?? []).map((a) => a.data.replace(/^"|"$/g, "").trim()).filter(Boolean);
}

/** Reverse the octets of an IPv4 address for the cymru origin zone, or null if not a valid IPv4. */
function reverseV4(ip: string): string | null {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = m.slice(1).map(Number);
  if (octets.some((o) => o > 255)) return null;
  return octets.reverse().join(".");
}

export async function asnLookup(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const rev = reverseV4(ip); // IPv4 only — cymru's IPv6 zone uses a different nibble format (out of scope here)
  const entities: OsintEntity[] = [];
  if (rev) {
    let origin: string[] = [];
    try {
      origin = await txt(`${rev}.origin.asn.cymru.com`, opts);
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e; // abort must propagate
    }
    for (const rec of origin) {
      // "13335 | 1.1.1.0/24 | US | arin | 2010-07-14" — asnField may hold several ASNs (multi-origin announce)
      const [asnField, prefix, cc] = rec.split("|").map((s) => s.trim());
      for (const asn of (asnField ?? "").split(/\s+/).filter(Boolean)) {
        let org = "";
        try {
          // AS13335.asn.cymru.com TXT -> "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US" — name is the tail
          const named = await txt(`AS${asn}.asn.cymru.com`, opts);
          org = named[0]?.split("|").pop()?.trim() ?? "";
        } catch (e) {
          if (e instanceof DOMException && e.name === "AbortError") throw e;
        }
        const detail = [prefix && `prefix ${prefix}`, cc, org].filter(Boolean).join(", ");
        entities.push({ type: "asn", value: `AS${asn}`, note: `announces ${ip}${detail ? ` — ${detail}` : ""}` });
      }
    }
  }
  return {
    provider: "team-cymru",
    query: ip,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
