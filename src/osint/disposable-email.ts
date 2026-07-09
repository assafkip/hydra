// disposable-email — keyless throwaway/disposable-email check, CROSS-CHECKED across TWO independent providers:
// debounce (disposable.debounce.io) and Kickbox (open.kickbox.com), both CORS-open, re-probed live from the
// hydra origin 2026-07-09. PRD prd-hydra-free-osint-providers finding-3. Whether an address is disposable is a
// property of its DOMAIN (mailinator.com etc.), a T3 context signal — infra:false, no typed graph entity.
// Querying BOTH and reporting agreement is the "2 providers, cross-checked" requirement: one provider's miss
// or false-positive is caught by the other. A single provider's answer alone is a weak lead.
import { type OsintOpts, type OsintResult, withRetry } from "./types.js";

const DEBOUNCE = "https://disposable.debounce.io/?email=";
const KICKBOX = "https://open.kickbox.com/v1/disposable/";

// debounce returns {"disposable":"true"} (STRING), kickbox returns {"disposable":true} (BOOLEAN). Normalize both.
function asBool(v: unknown): boolean | null {
  if (typeof v === "boolean") return v;
  if (v === "true") return true;
  if (v === "false") return false;
  return null;
}

async function probeOne(fetchImpl: typeof fetch, url: string, opts: OsintOpts): Promise<boolean | null> {
  return withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`disposable check HTTP ${res.status}`);
      const j = (await res.json()) as { disposable?: unknown };
      return asBool(j?.disposable);
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

/** email → cross-checked disposable/throwaway verdict from debounce + kickbox. Keyless, T3, summary-only. */
export async function disposableEmail(email: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const addr = email.trim().toLowerCase();
  const settled = await Promise.allSettled([
    probeOne(fetchImpl, `${DEBOUNCE}${encodeURIComponent(addr)}`, opts),
    probeOne(fetchImpl, `${KICKBOX}${encodeURIComponent(addr)}`, opts),
  ]);
  // Re-raise an AbortError (the loop is stopping) rather than masking it as "both providers failed".
  for (const s of settled) if (s.status === "rejected" && s.reason instanceof DOMException && s.reason.name === "AbortError") throw s.reason;
  const debounce = settled[0].status === "fulfilled" ? settled[0].value : null;
  const kickbox = settled[1].status === "fulfilled" ? settled[1].value : null;
  if (debounce === null && kickbox === null) throw new Error("disposable check: both providers failed or returned no verdict");

  const label = (v: boolean | null): string => (v === null ? "unknown" : v ? "disposable" : "not disposable");
  const both = debounce !== null && kickbox !== null;
  const agree = both && debounce === kickbox;
  const verdict = both
    ? agree
      ? `both agree: ${label(debounce)}`
      : `DISAGREE — debounce=${label(debounce)}, kickbox=${label(kickbox)} (treat as inconclusive)`
    : `single source only — debounce=${label(debounce)}, kickbox=${label(kickbox)}`;
  return { provider: "disposable-email", query: addr, tier: "T3", entities: [], summary: `disposable/throwaway check (T3, cross-checked): ${verdict}` };
}
