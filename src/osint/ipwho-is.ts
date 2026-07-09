// ipwho.is — keyless IP → ASN + ISP/org + geo (ipwho.is, CORS `*`, PRD prd-hydra-free-osint-providers
// finding-1). A second keyless geo/ASN source (cross-checks ip.guide). T1 routing: the ASN pivots as an
// entity; the connection domain pivots as a domain; ISP/org/geo ride the summary. `success:false` -> error.
import { type OsintEntity, type OsintOpts, type OsintResult, normalizeAsn, uniqueBy, validDomainOrNull, withRetry } from "./types.js";

const ENDPOINT = "https://ipwho.is";

interface IpWhoIsResponse {
  success?: boolean;
  message?: string;
  city?: string | null;
  country?: string | null;
  connection?: { asn?: number; org?: string; isp?: string; domain?: string };
}

/** IP → the announcing ASN (asn pivot) + connection domain (domain pivot) + ISP/geo (summary). Keyless, T1. */
export async function ipWhoIsLookup(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}/${encodeURIComponent(ip)}`, { signal: opts.signal });
      if (!res.ok) throw new Error(`ipwho.is HTTP ${res.status}`);
      const body = (await res.json()) as IpWhoIsResponse;
      if (body.success === false) throw new Error(`ipwho.is: ${body.message ?? "lookup failed"}`);
      return body;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const conn = json.connection;
  const entities: OsintEntity[] = [];
  const asn = normalizeAsn(conn?.asn);
  if (asn) entities.push({ type: "asn", value: asn, note: `announces ${ip}${conn?.org ? ` — ${conn.org}` : ""}` });
  // Validate the provider-controlled connection domain is a real FQDN before it becomes a gate-admissible
  // pivot (codex adv finding-2) — a hostile ipwho.is response cannot inject junk as an infra domain.
  const domain = conn?.domain ? validDomainOrNull(conn.domain) : null;
  if (domain) entities.push({ type: "domain", value: domain, note: `connection domain of ${ip}` });
  const geo = [json.city, json.country].filter(Boolean).join(", ");
  const parts = [conn?.isp && `ISP ${conn.isp}`, conn?.org && `org ${conn.org}`, geo && `geo ${geo}`].filter(Boolean);
  return {
    provider: "ipwho-is",
    query: ip,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
    summary: parts.length ? parts.join(" · ") : undefined,
  };
}
