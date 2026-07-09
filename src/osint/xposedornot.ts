// xposedornot — keyless breach-exposure LEAD via api.xposedornot.com (CORS `*`, re-probed live from the
// hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-3. A breach-DB match is a T3 LEAD, NOT
// proof: a name-collision, a shared/rotated address, or a stale/erroneous dump can all produce a match, so a
// hit is NEVER emitted as a confirmed "this address was breached" — it is a corroborate-first lead in the
// SUMMARY, with no typed graph entity (a breach name is not a pivotable entity, per investigations/enrich/
// hibp.py). infra:false so it can never touch the promotion gate.
//
// Privacy: this DOES send the queried email to XposedOrNot (inherent to any per-email breach check) — that
// disclosure is surfaced on the capabilities page (finding-4). HIBP's per-email mode, by contrast, is keyed
// and out of free scope (see hibp-catalog.ts — the free HIBP path is domain-context only).
import { capString, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.xposedornot.com/v1/check-email/";
const MAX_NAMES = 100; // cap the breach-name list a hostile/huge response can list

interface CheckEmailResponse {
  breaches?: string[][]; // the API nests the name list one level: [["Adobe","Dropbox",...]]
  Error?: string;
}

/** email → the breach names it appears in, as a T3 LEAD summary (NOT proof; corroborate). No typed entity. */
export async function xposedOrNotEmail(email: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const addr = email.trim().toLowerCase();
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}${encodeURIComponent(addr)}`, { headers: { accept: "application/json" }, signal: opts.signal });
      // 404 = the address is in no indexed breach (a clean, valid answer — not an error).
      if (res.status === 404) return { breaches: [] } as CheckEmailResponse;
      if (!res.ok) throw new Error(`XposedOrNot HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object") throw new Error("XposedOrNot: unexpected response shape");
  const r = json as CheckEmailResponse;
  const hasBreaches = Array.isArray(r.breaches) && Array.isArray(r.breaches[0]);
  // Distinguish a CLEAN address from a provider FAILURE masquerading as a clean 200 (codex adversarial): a
  // clean address returns {Error:"Not found"}; ANY other Error value (rate limit, service error) with no
  // breaches array MUST throw, never read as "no breaches". Only breaches-present or the documented clean
  // shape are valid answers.
  if (!hasBreaches) {
    const err = (r.Error ?? "").toLowerCase();
    if (err && err !== "not found") throw new Error(`XposedOrNot error (${capString(r.Error, 60)})`);
  }
  // Length-cap each provider-controlled breach name (codex): a count cap alone can't stop 100 giant strings.
  const names = hasBreaches ? r.breaches![0].filter((n) => typeof n === "string").slice(0, MAX_NAMES).map((n) => capString(n, 80)).filter(Boolean) : [];
  const summary = names.length
    ? `breach-DB match (T3 LEAD — NOT proof this address was breached; corroborate): appears in ${names.length} breach record(s): ${names.join(", ")}`
    : "no breach-DB records for this address (T3)";
  // No typed entity: a breach name is not a graph pivot, and the match must never become promotable evidence.
  return { provider: "xposedornot", query: addr, tier: "T3", entities: [], summary };
}
