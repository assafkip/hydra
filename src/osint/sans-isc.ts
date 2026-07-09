// SANS ISC / DShield — keyless IP attack-report feed (isc.sans.edu, CORS `*`, PRD
// prd-hydra-free-osint-providers finding-1). Aggregated honeypot/firewall attack reports are a crowd feed,
// NOT a non-fakeable infra record, so this is a T3 LEAD: the value is the report summary, no typed entity,
// infra:false — abuse-feed hits never inflate the promotion gate's infra count.
import { type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://isc.sans.edu/api/ip";

interface SansIscResponse {
  ip?: {
    count?: number | null;
    attacks?: number | null;
    comment?: string | null;
    asname?: string | null;
    network?: string | null;
    threatfeeds?: Record<string, unknown>;
  };
}

/** IP → its DShield attack-report counts + threat-feed memberships (summary only). Keyless, T3 lead. */
export async function sansIscLookup(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}/${encodeURIComponent(ip)}?json`, { signal: opts.signal });
      if (!res.ok) throw new Error(`SANS ISC HTTP ${res.status}`);
      return (await res.json()) as SansIscResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const rec = json.ip;
  const feeds = Object.keys(rec?.threatfeeds ?? {});
  const parts = [
    rec?.count != null && `${rec.count} report(s)`,
    rec?.attacks != null && `${rec.attacks} target(s)`,
    feeds.length && `on threat feeds: ${feeds.join(", ")}`,
    rec?.comment && `note: ${rec.comment}`,
  ].filter(Boolean);
  return {
    provider: "sans-isc",
    query: ip,
    tier: "T3",
    entities: [],
    summary: parts.length ? parts.join(" · ") : "no DShield reports on record",
  };
}
