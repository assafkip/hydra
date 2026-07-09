// gitlab-user — keyless GitLab profile lookup via gitlab.com/api/v4/users?username= (CORS `*`, re-probed
// live from the hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-5/6. A public GitLab
// profile is a T3 LEAD (self-asserted account metadata), so infra:false and its typed pivots go to the lead
// queue, never the promotion gate.
//
// finding-6 divergence: same family as identity-lookup.sh / osint_mcp holehe — but browser-CORS-limited to
// the ONE keyless public-user JSON endpoint (no multi-site sweep). Emits typed pivots (account/person/email),
// not summary text (finding-5).
//
// keyless by default; an OPTIONAL personal-access token (BYO, vault via the enrich auth slot) rides the
// PRIVATE-TOKEN header for higher limits and is NEVER echoed in an error.
import { httpUrlOrNull, isBareHandle, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://gitlab.com/api/v4/users";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface GitlabUser {
  id?: number;
  username?: string;
  name?: string;
  state?: string;
  public_email?: string;
  web_url?: string;
}

/** handle → the public GitLab profile's typed pivots (account/person/email). Keyless T3 lead; an optional
 *  token (enrich auth slot) only raises the rate limit. */
export async function gitlabUser(handle: string, opts: OsintOpts = {}, token?: string): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const username = handle.trim().replace(/^@/, "");
  if (!isBareHandle(username)) throw new Error("gitlab: not a valid username"); // codex: bound what we fetch
  const headers: Record<string, string> = { accept: "application/json" };
  if (token) headers["private-token"] = token; // BYO token: header only, never echoed
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}?username=${encodeURIComponent(username)}`, { headers, signal: opts.signal });
      if (!res.ok) throw new Error(`gitlab HTTP ${res.status}`); // 401/403 surfaced, token never in msg
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  // The public-user endpoint returns an ARRAY (0 or 1 match). An empty array = no such public user.
  if (!Array.isArray(json)) throw new Error("gitlab: unexpected response shape");
  // Username-match guard (codex adversarial): a hostile response must not attribute another account to the
  // query. Require the matched object's username to EQUAL the queried handle (case-insensitive), not just
  // "the first object with any username".
  const u = json.find((x): x is GitlabUser => !!x && typeof x === "object" && typeof (x as GitlabUser).username === "string" && (x as GitlabUser).username!.toLowerCase() === username.toLowerCase());
  if (!u) throw new Error("gitlab: no public user matching that username");

  const entities: OsintEntity[] = [];
  const webUrl = u.web_url ? httpUrlOrNull(u.web_url) : null; // scheme-check the provider-controlled URL (codex)
  if (webUrl) entities.push({ type: "account", value: webUrl, note: `GitLab profile of ${username}` });
  if (u.name) entities.push({ type: "person", value: u.name, note: `GitLab display name of ${username}` });
  if (u.public_email && EMAIL_RE.test(u.public_email)) {
    entities.push({ type: "email", value: u.public_email.toLowerCase(), note: `public email on GitLab profile of ${username}` });
  }
  const summary = u.state ? `account state: ${u.state}` : undefined;
  return { provider: "gitlab", query: username, tier: "T3", entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`), summary };
}
