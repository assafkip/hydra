// RIPEstat Data API — keyless IP → announcing ASN(s) + BGP prefix (stat.ripe.net, CORS `*`, PRD
// prd-hydra-free-osint-providers finding-1). T1: the routing record (which AS announces a prefix) is the
// same non-fakeable infra signal as Team Cymru in asn.ts, sourced from RIPE's routing collectors.
import { MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, normalizeAsn, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://stat.ripe.net/data/network-info/data.json";

interface RipeStatResponse {
  data?: { asns?: string[]; prefix?: string };
}

/** IP → the ASN(s) that announce it (asn pivots) + the covering BGP prefix (summary). Keyless, T1 routing. */
export async function ripestatNetworkInfo(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}?resource=${encodeURIComponent(ip)}`, { signal: opts.signal });
      if (!res.ok) throw new Error(`RIPEstat HTTP ${res.status}`);
      return (await res.json()) as RipeStatResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const prefix = json.data?.prefix?.trim();
  const entities: OsintEntity[] = [];
  // Cap BEFORE parsing so a hostile/huge response can never materialize an unbounded ASN array (codex adv finding-4).
  for (const raw of (json.data?.asns ?? []).slice(0, MAX_ENRICH_RESULTS)) {
    const asn = normalizeAsn(raw);
    if (asn) entities.push({ type: "asn", value: asn, note: `announces ${ip}${prefix ? ` (prefix ${prefix})` : ""}` });
  }
  return {
    provider: "ripestat",
    query: ip,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
    summary: prefix ? `BGP prefix ${prefix}` : undefined,
  };
}
