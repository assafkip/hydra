// Chunk-5 enrich: keyed, browser-native Shodan host lookup (api.shodan.io, CORS-open: a simple
// GET, the key in the ?key= query param, ACAO * verified 2026-06-17). A Shodan host record is a
// live infra scan crosslinked to the queried IP — T2. The key appears in the request URL by
// Shodan's design (a disclosed flow: the user's key to the user's chosen provider over HTTPS); it
// is NEVER echoed in a thrown error (provider + HTTP status only) and the session layer redacts it
// out of any stored record.
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  MAX_ENRICH_RESULTS,
  normalizeAsn,
  uniqueBy,
  withRetry,
} from "./types.js";

const ENDPOINT = "https://api.shodan.io/shodan/host/";

interface ShodanHost {
  ip_str?: string;
  hostnames?: string[];
  domains?: string[];
  asn?: string;
  org?: string;
  ports?: number[];
}

export async function shodanHost(ip: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(ip)}?key=${encodeURIComponent(key)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`Shodan HTTP ${res.status}`); // 401 bad key, 404 no data — NEVER echo url/key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object") throw new Error("Shodan: unexpected response shape");
  const h = json as ShodanHost;

  const entities: OsintEntity[] = [];
  const ports = Array.isArray(h.ports) ? h.ports.slice(0, MAX_ENRICH_RESULTS) : [];
  const noteBits = [ports.length ? `open ports ${ports.join(", ")}` : "", h.org ? `org ${h.org}` : ""].filter(Boolean);
  entities.push({ type: "ip", value: ip, note: `Shodan: ${noteBits.join("; ") || "host record"}` });

  for (const host of (h.hostnames ?? []).slice(0, MAX_ENRICH_RESULTS)) {
    if (host && typeof host === "string") entities.push({ type: "domain", value: host.toLowerCase(), note: "Shodan hostname" });
  }
  for (const d of (h.domains ?? []).slice(0, MAX_ENRICH_RESULTS)) {
    if (d && typeof d === "string") entities.push({ type: "domain", value: d.toLowerCase(), note: "Shodan domain" });
  }
  const asn = normalizeAsn(h.asn);
  if (asn) entities.push({ type: "asn", value: asn, note: h.org ? `Shodan: ${h.org}` : "Shodan ASN" });

  return {
    provider: "shodan",
    query: ip,
    tier: "T2",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
