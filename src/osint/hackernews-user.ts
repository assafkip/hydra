// hackernews-user — keyless Hacker News profile via the official Firebase API (CORS echoes the hydra origin,
// re-probed live 2026-07-09). PRD prd-hydra-free-osint-providers finding-5/6. An HN profile is a T3 LEAD
// (the `about` field is free-text the user wrote), so infra:false.
//
// finding-6 divergence: the legacy identity-lookup.sh / holehe sweep across many sites; this is browser-CORS-
// limited to the ONE HN endpoint. The `about` bio often carries a linked site/email — those are parsed out as
// typed pivots (url/email), the rest rides the summary. NO token exists for this anonymous API — keyless only.
import { httpUrlOrNull, isBareHandle, MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://hacker-news.firebaseio.com/v0/user/";
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const URL_RE = /https?:\/\/[^\s"'<>)]+/gi;

interface HnUser {
  id?: string;
  about?: string;
  karma?: number;
  created?: number;
  submitted?: number[];
}

/** handle → the HN profile pivot + any site/email in the bio. Keyless T3 lead (anonymous API, no token). */
export async function hackernewsUser(handle: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const id = handle.trim().replace(/^@/, "");
  if (!isBareHandle(id)) throw new Error("hacker news: not a valid username"); // codex: bound what we fetch
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}${encodeURIComponent(id)}.json`, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`hacker news HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // The API returns `null` (not 404) for a nonexistent user.
  if (json === null) throw new Error("hacker news: no such user");
  if (typeof json !== "object" || typeof (json as HnUser).id !== "string") throw new Error("hacker news: unexpected response shape");
  const u = json as HnUser;

  // isBareHandle(id) already guarantees id is URL-safe; encode defensively anyway (codex).
  const entities: OsintEntity[] = [{ type: "account", value: `https://news.ycombinator.com/user?id=${encodeURIComponent(id)}`, note: `Hacker News profile of ${id}` }];
  const about = typeof u.about === "string" ? u.about : "";
  // Cap the bio matches BEFORE materializing entities so a hostile about-string can never produce an
  // unbounded array (codex adversarial). Slice each match iterator to MAX_ENRICH_RESULTS.
  for (const m of [...about.matchAll(URL_RE)].slice(0, MAX_ENRICH_RESULTS)) {
    const url = httpUrlOrNull(m[0]);
    if (url) entities.push({ type: "url", value: url, note: `link in HN bio of ${id}` });
  }
  for (const m of [...about.matchAll(EMAIL_RE)].slice(0, MAX_ENRICH_RESULTS)) {
    entities.push({ type: "email", value: m[0].toLowerCase(), note: `email in HN bio of ${id}` });
  }
  const summary = [
    typeof u.karma === "number" ? `${u.karma} karma` : "",
    typeof u.created === "number" ? `joined ${new Date(u.created * 1000).toISOString().slice(0, 10)}` : "",
    Array.isArray(u.submitted) ? `${u.submitted.length} submissions` : "",
  ].filter(Boolean).join(" · ");
  return { provider: "hackernews", query: id, tier: "T3", entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`), summary: summary || undefined };
}
