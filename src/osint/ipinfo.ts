// Chunk-5 enrich: keyed, browser-native IPinfo lookup (ipinfo.io, CORS-open: a simple GET).
// IPinfo's hostname/ASN is a live infra record crosslinked to the queried IP — T2. Auth uses a
// Bearer header so the token never enters the URL or thrown errors. The `org` field is "AS<n>
// <name>"; the leading ASN is parsed out to a canonical `asn` entity (codex D8).
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  normalizeAsn,
  uniqueBy,
  withRetry,
} from "./types.js";

const ENDPOINT = "https://ipinfo.io/";

interface IpinfoResponse {
  ip?: string;
  hostname?: string;
  org?: string;
  city?: string;
  country?: string;
}

export async function ipinfoIp(ip: string, token: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(ip)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json", authorization: `Bearer ${token}` }, signal: opts.signal });
      if (!res.ok) throw new Error(`IPinfo HTTP ${res.status}`); // 403/401 bad token — NEVER echo the token
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object") throw new Error("IPinfo: unexpected response shape");
  const r = json as IpinfoResponse;

  const entities: OsintEntity[] = [];
  const loc = [r.city, r.country].filter(Boolean).join(", ");
  entities.push({ type: "ip", value: ip, note: `IPinfo: ${loc || "ip record"}` });
  if (r.hostname && typeof r.hostname === "string") {
    entities.push({ type: "domain", value: r.hostname.toLowerCase().replace(/\.$/, ""), note: "IPinfo hostname" });
  }
  if (r.org && typeof r.org === "string") {
    // org = "AS15169 Google LLC" -> asn AS15169 (note carries the org name).
    const asn = normalizeAsn(r.org.split(/\s+/)[0]);
    if (asn) entities.push({ type: "asn", value: asn, note: `IPinfo: ${r.org}` });
  }

  return {
    provider: "ipinfo",
    query: ip,
    tier: "T2",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
