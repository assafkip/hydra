// certspotter — keyless certificate-transparency issuances via api.certspotter.com (CORS `*`, re-probed
// live from the hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-2. A CT log entry is a
// non-fakeable record (a CA published it) — T1. This is a SECOND CT source alongside crt.sh: certspotter's
// index is independent, so it surfaces subdomains crt.sh misses (and vice-versa). The dns_names ride back
// as subdomain/domain pivots; the issuing CA rides the summary.
import { MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, validDomainOrNull, withRetry } from "./types.js";

const ENDPOINT = "https://api.certspotter.com/v1/issuances";

interface Issuance {
  dns_names?: string[];
  issuer?: { friendly_name?: string; name?: string };
}

/** domain → the hostnames on its recent CT issuances (subdomain/domain pivots) + the issuing CA(s). Keyless, T1. */
export async function certspotterIssuances(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const target = domain.trim().toLowerCase();
  const url = `${ENDPOINT}?domain=${encodeURIComponent(target)}&include_subdomains=true&expand=dns_names&expand=issuer`;
  const rows = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      // 404 = certspotter has no issuances indexed for this domain; a valid empty answer, not an error.
      if (res.status === 404) return [] as Issuance[];
      if (!res.ok) throw new Error(`certspotter HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // The real success shape is a top-level ARRAY (404 already returned []). A 200 with any other shape
  // (e.g. {error:...}) is an unexpected/hostile response, NOT "0 issuances" — throw so the caller surfaces
  // is_error, never a silent empty-success T1 (codex finding-5).
  if (!Array.isArray(rows)) throw new Error("certspotter: unexpected response shape");
  // Cap the issuance list BEFORE materializing entities so a hostile/huge response can never produce an
  // unbounded array (mirrors the shodan-internetdb hardening — codex adv finding).
  const issuances = rows.slice(0, MAX_ENRICH_RESULTS);
  const entities: OsintEntity[] = [];
  const issuers = new Set<string>();
  for (const row of issuances) {
    for (const raw of (row.dns_names ?? []).slice(0, MAX_ENRICH_RESULTS)) {
      const host = validDomainOrNull(String(raw).replace(/^\*\./, "")); // validate BEFORE it becomes a gate-admissible pivot
      if (!host) continue;
      // SCOPE GUARD (codex adversarial finding-4): only the queried domain OR a subdomain of it may become a
      // pivot. A hostile issuance listing an unrelated SAN (e.g. bank.com under a query for example.com) is
      // DROPPED — it must never inject an out-of-scope graph pivot under this T1 result.
      const isTarget = host === target;
      const isSubdomain = host.endsWith(`.${target}`);
      if (!isTarget && !isSubdomain) continue;
      entities.push({ type: isTarget ? "domain" : "subdomain", value: host, note: `certspotter CT issuance for ${target}` });
    }
    const issuer = row.issuer?.friendly_name ?? row.issuer?.name;
    if (issuer) issuers.add(issuer);
  }
  const capped = uniqueBy(entities, (e) => `${e.type}:${e.value}`).slice(0, MAX_ENRICH_RESULTS);
  const summaryParts = [`${issuances.length} CT issuance(s)`, issuers.size ? `CA: ${[...issuers].slice(0, 10).join(", ")}` : ""].filter(Boolean);
  return {
    provider: "certspotter",
    query: target,
    tier: "T1",
    entities: capped,
    summary: summaryParts.join(" · "),
  };
}
