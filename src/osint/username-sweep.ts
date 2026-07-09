// Username presence sweep (restore-osint-tool-belt 2026-06-24, port of osint_mcp.py username_sweep).
// Checks whether a bare handle exists on a curated set of CORS-OPEN, keyless platforms and returns each
// hit as a profile URL the agent can pivot on. T3 (a social presence is a lead, never a non-fakeable
// record). Only platforms whose APIs are LIVE-VERIFIED CORS-open (ACAO) are included — GitHub + Keybase
// confirmed `access-control-allow-origin: *` (2026-06-24 preflight). Bot-walled sites (Reddit 403, X/IG/
// TikTok) and no-ACAO redirectors (Gravatar/Ahmia) are omitted here; they belong to the Worker-proxy tier.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy } from "./types.js";

interface Platform {
  name: string;
  // returns the public profile URL if the handle exists, else null. Never throws (a dead platform is skipped).
  check: (handle: string, fetchImpl: typeof fetch, signal?: AbortSignal) => Promise<string | null>;
}

const PLATFORMS: Platform[] = [
  {
    name: "github",
    check: async (h, fetchImpl, signal) => {
      const res = await fetchImpl(`https://api.github.com/users/${encodeURIComponent(h)}`, { headers: { accept: "application/vnd.github+json" }, signal });
      if (!res.ok) return null; // 404 = absent
      // Use the API's own html_url (RUNTIME data) — never a source literal "github.com" (that bare host is
      // not in connect-src; a literal would trip the leak gate. api.github.com — the fetch host — is allowed).
      const body = (await res.json()) as { html_url?: string };
      return typeof body.html_url === "string" ? body.html_url : null;
    },
  },
  {
    name: "keybase",
    check: async (h, fetchImpl, signal) => {
      const res = await fetchImpl(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(h)}`, { signal });
      if (!res.ok) return null;
      const body = (await res.json()) as { status?: { code?: number }; them?: unknown[] };
      const found = body.status?.code === 0 && Array.isArray(body.them) && body.them.length > 0 && body.them[0] != null;
      return found ? `https://keybase.io/${h}` : null;
    },
  },
];

export async function usernameSweep(handle: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const h = handle.trim().replace(/^@/, "");
  // Each platform runs independently; one failing/timing-out never sinks the sweep (Promise.allSettled).
  const settled = await Promise.allSettled(PLATFORMS.map((p) => p.check(h, fetchImpl, opts.signal)));
  const urls: string[] = [];
  settled.forEach((r) => { if (r.status === "fulfilled" && r.value) urls.push(r.value); });
  const entities: OsintEntity[] = uniqueBy(urls.map((u) => ({ type: "url" as const, value: u })), (e) => e.value);
  return { provider: "username_sweep", query: h, tier: "T3", entities };
}
