// Chunk-5 enrich: keyed, browser-native urlscan.io search (urlscan.io, CORS-open: the OPTIONS
// preflight allows the API-Key header, verified 2026-06-17). A urlscan result is a real scanned
// page crosslinked to the queried domain — T2. The key rides the API-Key header, never the URL,
// and is never echoed in a thrown error. Each result row is mapped to canonical types EXPLICITLY
// (codex D8): page.domain -> domain, page.ip -> ip (validated), page.url -> url (scheme/host
// validated; a junk/hostless string is never emitted as a url).
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  MAX_ENRICH_RESULTS,
  httpUrlOrNull,
  uniqueBy,
  withRetry,
} from "./types.js";

const ENDPOINT = "https://urlscan.io/api/v1/search/";
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

interface UrlscanSearch {
  results?: { page?: { domain?: string; ip?: string; url?: string } }[];
}

export async function urlscanSearch(domain: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}?q=${encodeURIComponent(`domain:${domain}`)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, {
        headers: { accept: "application/json", "api-key": key },
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`urlscan HTTP ${res.status}`); // 401 bad key, 429 rate — NEVER echo the key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object") throw new Error("urlscan: unexpected response shape");
  const rows = Array.isArray((json as UrlscanSearch).results) ? (json as UrlscanSearch).results! : [];

  const entities: OsintEntity[] = [];
  for (const row of rows.slice(0, MAX_ENRICH_RESULTS)) {
    const page = row.page ?? {};
    if (page.domain && typeof page.domain === "string") {
      entities.push({ type: "domain", value: page.domain.toLowerCase(), note: "urlscan page" });
    }
    if (page.ip && typeof page.ip === "string" && IPV4_RE.test(page.ip)) {
      entities.push({ type: "ip", value: page.ip, note: "urlscan page" });
    }
    if (page.url && typeof page.url === "string") {
      const u = httpUrlOrNull(page.url);
      if (u) entities.push({ type: "url", value: u, note: "urlscan page" });
    }
  }

  return {
    provider: "urlscan",
    query: domain,
    tier: "T2",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
