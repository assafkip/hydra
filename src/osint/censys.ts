// Chunk-5 enrich: keyed, browser-native Censys host lookup (search.censys.io v2, CORS-open: the
// OPTIONS preflight allows the Authorization header, verified 2026-06-17). Auth is Basic
// base64(API_ID:SECRET) — the key field is documented "API ID:Secret" (codex D5). A Censys host
// record is a live infra scan crosslinked to the queried IP — T2. The credential is NEVER echoed
// in a thrown error: a malformed "id:secret" throws a fixed message, and an HTTP failure carries
// only the status.
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  base64,
  normalizeAsn,
  uniqueBy,
  withRetry,
} from "./types.js";

const ENDPOINT = "https://search.censys.io/api/v2/hosts/";

interface CensysHost {
  result?: {
    ip?: string;
    names?: string[];
    autonomous_system?: { asn?: number; name?: string; description?: string };
    services?: { port?: number }[];
  };
}

export async function censysHost(ip: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  // Split on the FIRST colon: API_ID:SECRET (the secret may itself contain colons).
  const colon = key.indexOf(":");
  if (colon < 1 || colon === key.length - 1) throw new Error('Censys key must be "API ID:Secret"');
  const basic = base64(key); // base64(id:secret) — NEVER logged/echoed

  const url = `${ENDPOINT}${encodeURIComponent(ip)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, {
        headers: { accept: "application/json", authorization: `Basic ${basic}` },
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`Censys HTTP ${res.status}`); // 401/403 bad cred — NEVER echo the cred
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object" || !(json as CensysHost).result) {
    throw new Error("Censys: unexpected response shape");
  }
  const r = (json as CensysHost).result!;

  const entities: OsintEntity[] = [];
  const services = Array.isArray(r.services) ? r.services : [];
  entities.push({ type: "ip", value: ip, note: `Censys: ${services.length} service(s)` });
  for (const name of r.names ?? []) {
    if (name && typeof name === "string") entities.push({ type: "domain", value: name.toLowerCase(), note: "Censys name" });
  }
  const asn = normalizeAsn(r.autonomous_system?.asn);
  if (asn) {
    const org = r.autonomous_system?.name ?? r.autonomous_system?.description;
    entities.push({ type: "asn", value: asn, note: org ? `Censys: ${org}` : "Censys ASN" });
  }

  return {
    provider: "censys",
    query: ip,
    tier: "T2",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
