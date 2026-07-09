// Certificate transparency via crt.sh (CORS-open, keyless). Surfaces subdomains
// from issued certs. crt.sh occasionally 502s (known flake), hence the retry.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://crt.sh/";

interface CrtRow {
  name_value?: string;
  common_name?: string;
}

export async function crtshSubdomains(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}?q=${encodeURIComponent(domain)}&output=json`;
  const rows = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
      return (await res.json()) as CrtRow[];
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const names: string[] = [];
  // Defensive: crt.sh normally returns an array; tolerate any other shape rather
  // than throwing (validate external input — never crash a pivot on a bad body).
  for (const row of Array.isArray(rows) ? rows : []) {
    const raw = `${row.name_value ?? ""}\n${row.common_name ?? ""}`;
    for (const n of raw.split(/\s+/)) {
      const host = n.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (host && host.endsWith(domain.toLowerCase()) && !host.includes(" ")) names.push(host);
    }
  }
  const entities: OsintEntity[] = uniqueBy(
    names.map((h) => ({ type: (h === domain.toLowerCase() ? "domain" : "subdomain") as OsintEntity["type"], value: h })),
    (e) => e.value,
  );
  return { provider: "crt.sh", query: domain, tier: "T1", entities };
}
