// ip.guide — keyless IP → ASN + operator + geo (ip.guide, CORS `*`, PRD prd-hydra-free-osint-providers
// finding-1). Keyless equivalent of the keyed IPinfo tool (ipinfo.ts). T1: the AS/prefix routing record;
// the ASN pivots as an entity, the operator/geo ride the summary.
import { type OsintEntity, type OsintOpts, type OsintResult, normalizeAsn, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://ip.guide";

interface IpGuideResponse {
  network?: {
    cidr?: string;
    autonomous_system?: { asn?: number; name?: string; organization?: string; country?: string };
  };
  location?: { city?: string | null; country?: string | null };
}

/** IP → the announcing ASN (asn pivot) + operator name, CIDR, and geo (summary). Keyless, T1 routing. */
export async function ipGuideLookup(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}/${encodeURIComponent(ip)}`, { signal: opts.signal });
      if (!res.ok) throw new Error(`ip.guide HTTP ${res.status}`);
      return (await res.json()) as IpGuideResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const as = json.network?.autonomous_system;
  const entities: OsintEntity[] = [];
  const asn = normalizeAsn(as?.asn);
  if (asn) {
    const org = as?.name ?? as?.organization ?? "";
    entities.push({ type: "asn", value: asn, note: `announces ${ip}${org ? ` — ${org}` : ""}` });
  }
  const geo = [json.location?.city, json.location?.country].filter(Boolean).join(", ");
  const parts = [
    json.network?.cidr && `CIDR ${json.network.cidr}`,
    as?.organization && `org ${as.organization}`,
    geo && `geo ${geo}`,
  ].filter(Boolean);
  return {
    provider: "ip-guide",
    query: ip,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
    summary: parts.length ? parts.join(" · ") : undefined,
  };
}
