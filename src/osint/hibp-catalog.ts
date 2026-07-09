// hibp-catalog — keyless HIBP breach CATALOG filtered by domain via haveibeenpwned.com/api/v3/breaches
// (CORS `*`, re-probed live from the hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-3.
//
// finding-6 divergence from investigations/enrich/hibp.py: hibp.py has TWO modes — a KEYED per-email
// breachedaccount mode (which breaches an account appears in) and a KEYLESS domain-catalog mode. This browser
// port implements ONLY the keyless DOMAIN mode. It returns the breaches recorded AGAINST that website as
// site-breach CONTEXT — NOT a list of exposed accounts at the domain, and NEVER evidence that the queried
// address was breached (finding-3). The per-email mode is keyed and out of free scope. A breach name is not a
// graph entity (hibp.py), so this emits NO typed pivot — summary only, T3, infra:false.
import { capString, MAX_ENRICH_RESULTS, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://haveibeenpwned.com/api/v3/breaches";

interface Breach {
  Name?: string;
  Title?: string;
  BreachDate?: string;
  PwnCount?: number;
}

/** domain → the breaches recorded against that SITE, as context (never per-email). Keyless, T3, summary-only. */
export async function hibpBreachCatalog(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const d = domain.trim().toLowerCase();
  const rows = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}?Domain=${encodeURIComponent(d)}`, { headers: { accept: "application/json" }, signal: opts.signal });
      // HIBP returns 404 for "no breaches recorded for this domain" — a clean answer, not an error.
      if (res.status === 404) return [] as Breach[];
      if (res.status === 429) throw new Error("HIBP rate-limited");
      if (!res.ok) throw new Error(`HIBP HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!Array.isArray(rows)) throw new Error("HIBP: unexpected response shape");
  const breaches = rows.slice(0, MAX_ENRICH_RESULTS); // cap before materializing the summary
  // Length-cap each provider-controlled field (codex adversarial): a count cap can't stop giant Title/Name/
  // BreachDate strings. capString also drops non-string fields to "".
  const names = breaches
    .map((b) => {
      const bb = (b ?? {}) as Breach;
      const name = capString(bb.Title ?? bb.Name, 80);
      if (!name) return "";
      const date = capString(bb.BreachDate, 20);
      return date ? `${name} (${date})` : name;
    })
    .filter(Boolean);
  const summary = names.length
    ? `site-breach CONTEXT for ${d} (T3 — breaches recorded against this SITE, NOT proof any specific address was exposed): ${names.join(", ")}`
    : `no breaches recorded against ${d} in the HIBP catalog (T3)`;
  return { provider: "hibp-catalog", query: d, tier: "T3", entities: [], summary };
}
