// Shodan InternetDB — keyless IP → open ports, CVEs, hostnames, tags (internetdb.shodan.io, CORS `*`,
// PRD prd-hydra-free-osint-providers finding-1). This is the KEYLESS "Shodan-lite" endpoint, distinct from
// the keyed api.shodan.io host lookup in shodan.ts. T1: the port/hostname observations are a non-fakeable
// scan record; hostnames pivot as domains, ports/CVEs/tags ride the summary (no typed entity for a CVE).
import { MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, validDomainOrNull, withRetry } from "./types.js";

const ENDPOINT = "https://internetdb.shodan.io";

interface InternetDbResponse {
  hostnames?: string[];
  ports?: number[];
  vulns?: string[];
  tags?: string[];
  cpes?: string[];
}

/** IP → the hostnames Shodan resolves for it (domain pivots) + a ports/CVEs/tags summary. Keyless, T1 infra. */
export async function shodanInternetDb(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}/${encodeURIComponent(ip)}`, { signal: opts.signal });
      if (res.status === 404) return {} as InternetDbResponse; // no scan data for this IP is a valid empty answer
      if (!res.ok) throw new Error(`Shodan InternetDB HTTP ${res.status}`);
      return (await res.json()) as InternetDbResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const entities: OsintEntity[] = [];
  // Cap BEFORE parsing (a hostile/huge response can never materialize an unbounded array — codex adv finding-3)
  // and validate each hostname is a real FQDN before it becomes a gate-admissible domain pivot (finding-1).
  for (const host of (json.hostnames ?? []).slice(0, MAX_ENRICH_RESULTS)) {
    const value = validDomainOrNull(host);
    if (value) entities.push({ type: "domain", value, note: `hostname of ${ip} (Shodan InternetDB)` });
  }
  const parts = [
    (json.ports ?? []).length ? `open ports: ${(json.ports ?? []).join(", ")}` : "",
    (json.vulns ?? []).length ? `CVEs: ${(json.vulns ?? []).join(", ")}` : "",
    (json.tags ?? []).length ? `tags: ${(json.tags ?? []).join(", ")}` : "",
  ].filter(Boolean);
  return {
    provider: "shodan-internetdb",
    query: ip,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
    summary: parts.length ? parts.join(" · ") : undefined,
  };
}
