// DNS-over-HTTPS via Google's public resolver (CORS-open). Replaces the `dig`
// CLI the Python webapp shelled out to (docs/17: the binary was the blocker, not
// the capability). T1: a DNS record is a non-fakeable infra signal.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://dns.google/resolve";
const RECORD_TYPES = ["A", "AAAA", "NS", "MX"] as const;

const TYPE_TO_ENTITY: Record<string, OsintEntity["type"]> = {
  A: "ip",
  AAAA: "ip",
  NS: "nameserver",
  MX: "mailserver",
};

interface DohAnswer {
  name: string;
  type: number;
  data: string;
}
interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
}

export async function dnsLookup(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const entities: OsintEntity[] = [];
  for (const rtype of RECORD_TYPES) {
    const url = `${ENDPOINT}?name=${encodeURIComponent(domain)}&type=${rtype}`;
    let json: DohResponse;
    try {
      json = await withRetry(
        async () => {
          const res = await fetchImpl(url, {
            headers: { accept: "application/dns-json" },
            signal: opts.signal,
          });
          if (!res.ok) throw new Error(`DoH ${rtype} HTTP ${res.status}`);
          return (await res.json()) as DohResponse;
        },
        opts.retries,
        undefined,
        opts.signal,
      );
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e; // abort must propagate
      continue; // one record type failing should not sink the whole lookup
    }
    for (const ans of json.Answer ?? []) {
      const etype = TYPE_TO_ENTITY[rtype];
      if (!etype) continue;
      const value = rtype === "MX" ? ans.data.replace(/^\d+\s+/, "") : ans.data;
      entities.push({ type: etype, value: value.replace(/\.$/, ""), note: `${rtype} of ${domain}` });
    }
  }
  return {
    provider: "dns.google",
    query: domain,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
