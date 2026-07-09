// Gravatar email→profile pivot (a56ffd8e tool-belt restore, founder 2026-06-25). The keyless
// gravatar.com/<hash>.json endpoint is CORS-open (verified live 2026-06-25: a GET returns 200 +
// access-control-allow-origin:*). A Gravatar profile is SELF-ASSERTED by the email owner, so it is a
// T3 LEAD source: the linked social accounts + display name it surfaces are pivots for an infra/identity
// tool to CONFIRM, never citable on their own (q-investigation evidence tiers). In-browser hashing uses
// SHA-256 (SubtleCrypto has no MD5); modern Gravatar accepts a SHA-256 hash of the lowercased email
// (verified live 2026-06-25). Only the profile JSON is fetched — the account URLs ride back as data
// (leads), never fetched here, so `gravatar.com` is the single new connect-src origin.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://gravatar.com"; // CSP connect-src origin — keyless profile JSON

/** SHA-256 hex of a string via SubtleCrypto (no MD5 in the browser; modern Gravatar accepts SHA-256). */
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface GravAccount { url?: string; display?: string; shortname?: string; verified?: boolean; }
interface GravEntry {
  displayName?: string;
  preferredUsername?: string;
  profileUrl?: string;
  currentLocation?: string;
  company?: string;
  job_title?: string;
  accounts?: GravAccount[];
}
interface GravResponse { entry?: GravEntry[] }

export async function gravatarLookup(email: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const addr = email.trim().toLowerCase();
  const entities: OsintEntity[] = [];
  let summary: string;

  const hash = await sha256Hex(addr);
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}/${hash}.json`, { headers: { accept: "application/json" }, signal: opts.signal });
      if (res.status === 404) return { entry: [] } as GravResponse; // no gravatar registered for this email
      if (!res.ok) throw new Error(`Gravatar HTTP ${res.status}`);
      return (await res.json()) as GravResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const entry = json.entry?.[0];
  if (!entry) {
    return { provider: "gravatar", query: addr, tier: "T3", entities, summary: `No Gravatar profile registered for ${addr}.` };
  }

  // The profile URL + each linked account URL are real, fetchable leads — a `url` is the only infra-typed
  // entity Gravatar yields; the identity text rides in `summary` (the email_triage pattern).
  if (entry.profileUrl) entities.push({ type: "url", value: entry.profileUrl, note: "gravatar profile" });
  for (const a of entry.accounts ?? []) {
    if (a.url) entities.push({ type: "url", value: a.url, note: `linked ${a.shortname ?? a.display ?? "account"}${a.verified ? " (verified)" : ""}` });
  }

  const ident = [
    entry.displayName && `name: ${entry.displayName}`,
    entry.preferredUsername && `username: ${entry.preferredUsername}`,
    entry.job_title && entry.company ? `${entry.job_title} at ${entry.company}` : entry.company,
    entry.currentLocation && `location: ${entry.currentLocation}`,
  ].filter(Boolean).join(" · ");
  const links = (entry.accounts ?? []).map((a) => a.url).filter(Boolean).join(", ");
  summary = `Gravatar profile for ${addr} (self-asserted, T3 lead): ${ident || "(no identity fields)"}${links ? ` — linked accounts: ${links}` : ""}`;

  return { provider: "gravatar", query: addr, tier: "T3", entities, summary };
}
