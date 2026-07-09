// HackerTarget reverse-IP — keyless IP → the OTHER domains hosted on the SAME IP (co-hosted /
// shared-hosting neighbors). api.hackertarget.com, CORS `*` (probed live from the hydra origin
// 2026-07-09). Fills the reverse-IP gap the free tier lacked: reverse_dns gives only the PTR of the
// IP; this gives the domain NEIGHBORS sharing it.
//
// TIER: a co-hosted domain is a WEAK shared-hosting signal, NOT a non-fakeable record and NOT proof of
// a relationship — a big shared host has hundreds of unrelated tenants. So this is a T2 LEAD with
// infra:false: the neighbor domains land as leads the analyst corroborates, never auto-promoted infra.
// The neighbor list is CAPPED (a shared host returns hundreds; 8.8.8.8 returns ~500) and each line is
// validated as a real FQDN before it is emitted (a hostile/garbled body cannot inject junk pivots).
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  MAX_ENRICH_RESULTS,
  uniqueBy,
  validDomainOrNull,
  withRetry,
} from "./types.js";

const ENDPOINT = "https://api.hackertarget.com/reverseiplookup";
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

function isIpv4(v: string): boolean {
  return IPV4_RE.test(v) && v.split(".").every((o) => Number(o) <= 255);
}

/** IP → the co-hosted domains on the same IP (shared-hosting neighbors). Keyless, T2 lead. The body is
 *  plaintext, one domain per line; HackerTarget signals EVERY failure (bad IP, reserved range, quota) as
 *  an `error …` / `API count exceeded …` plaintext body with a 200 — surfaced as a thrown error so it can
 *  never masquerade as an empty-success result. */
export async function reverseIpLookup(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const target = ip.trim();
  if (!isIpv4(target)) throw new Error("reverse_ip needs an IPv4 address");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const body = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}/?q=${encodeURIComponent(target)}`, { signal: opts.signal });
      if (!res.ok) throw new Error(`HackerTarget HTTP ${res.status}`);
      return await res.text();
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const text = typeof body === "string" ? body.trim() : "";
  const low = text.toLowerCase();
  if (!text || low.startsWith("error") || low.includes("api count exceeded")) {
    throw new Error(`HackerTarget: ${text.slice(0, 80) || "empty response"}`);
  }
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const entities: OsintEntity[] = [];
  for (const line of lines) {
    if (entities.length >= MAX_ENRICH_RESULTS) break; // a shared host returns hundreds — cap the neighbor list
    const domain = validDomainOrNull(line);
    if (domain) entities.push({ type: "domain", value: domain, note: `co-hosted on ${target}` });
  }
  const deduped = uniqueBy(entities, (e) => e.value);
  const shown = lines.length > deduped.length ? ` (showing ${deduped.length} of ${lines.length})` : "";
  return {
    provider: "hackertarget",
    query: target,
    tier: "T2",
    entities: deduped,
    summary: `${deduped.length} co-hosted domain(s) on ${target}${shown} — shared-hosting neighbors (a lead, not proof of a relationship)`,
  };
}
