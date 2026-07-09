// github-user — keyless GitHub profile lookup via api.github.com (CORS `*`, re-probed live from the hydra
// origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-5/6. A public GitHub profile is a T3 LEAD
// (self-asserted account metadata — a name/company field is claimed by the account owner, not proven), so
// infra:false and its typed pivots go to the lead queue, never the promotion gate.
//
// finding-6 divergence: this ports the "GitHub identity" slice of q-investigate/skills/osint/scripts/
// identity-lookup.sh + investigations/agent/osint_mcp.py's git_emails/holehe, but DIVERGES: the legacy tools
// are server-side (holehe sweeps ~120 sites; git_emails mines a repo's commit history for author emails).
// The browser is CORS-limited to the ONE keyless JSON profile endpoint — no 120-site sweep, no git-clone
// commit mining. It emits the profile's typed pivots (finding-5: account/org/url/email), not summary text.
//
// keyless by default; an OPTIONAL personal-access token (BYO, from the vault via the enrich auth slot) lifts
// the rate limit 60→5000/hr. The token rides ONLY the Authorization header and is NEVER echoed in an error.
import { httpUrlOrNull, isBareHandle, isTwitterHandle, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://api.github.com/users/";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface GithubUser {
  login?: string;
  name?: string | null;
  company?: string | null;
  blog?: string | null;
  email?: string | null;
  twitter_username?: string | null;
  location?: string | null;
  html_url?: string | null;
  public_repos?: number;
  followers?: number;
}

/** handle → the profile's typed pivots (account/org/url/email) + a stats summary. Keyless T3 lead;
 *  an optional token (enrich auth slot) only raises the rate limit. */
export async function githubUser(handle: string, opts: OsintOpts = {}, token?: string): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const login = handle.trim().replace(/^@/, "");
  if (!isBareHandle(login)) throw new Error("github: not a valid username"); // codex: bound what we fetch
  const headers: Record<string, string> = { accept: "application/vnd.github+json" };
  if (token) headers.authorization = `Bearer ${token}`; // BYO token: header only, never echoed
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}${encodeURIComponent(login)}`, { headers, signal: opts.signal });
      if (res.status === 404) throw new Error("github: user not found");
      if (!res.ok) throw new Error(`github HTTP ${res.status}`); // 401/403 rate-limit surfaced, key never in msg
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object" || typeof (json as GithubUser).login !== "string") {
    throw new Error("github: unexpected response shape");
  }
  const u = json as GithubUser;
  // Login-echo guard (codex adversarial): a hostile response must not attribute ANOTHER account's profile
  // to the queried handle. The echoed login MUST match the query (case-insensitive), else throw.
  if ((u.login ?? "").toLowerCase() !== login.toLowerCase()) throw new Error("github: response login does not match the query");
  const entities: OsintEntity[] = [];
  // The profile itself is the anchor account pivot. Use the API's OWN html_url (RUNTIME data) — never a
  // source literal "github.com/<login>" (that bare host is not in connect-src; a literal would trip the leak
  // gate, per the username-sweep precedent). api.github.com — the fetch host — is the allowlisted origin.
  const profileUrl = u.html_url ? httpUrlOrNull(u.html_url) : null;
  if (profileUrl) entities.push({ type: "account", value: profileUrl, note: `GitHub profile of ${login}` });
  if (u.name) entities.push({ type: "person", value: u.name, note: `GitHub display name of ${login}` });
  if (u.company) entities.push({ type: "org", value: u.company.replace(/^@/, ""), note: `GitHub company field of ${login}` });
  const blog = u.blog ? httpUrlOrNull(u.blog.startsWith("http") ? u.blog : `https://${u.blog}`) : null;
  if (blog) entities.push({ type: "url", value: blog, note: `GitHub blog of ${login}` });
  if (u.email && EMAIL_RE.test(u.email)) entities.push({ type: "email", value: u.email.toLowerCase(), note: `public email on GitHub profile of ${login}` });
  // Validate the twitter handle before interpolating it into an account URL (codex adversarial): a hostile
  // twitter_username with slashes/query/fragment must never become a junk pivot. Drop if not a real handle.
  const twitter = u.twitter_username?.replace(/^@/, "") ?? "";
  if (twitter && isTwitterHandle(twitter)) {
    entities.push({ type: "account", value: `https://twitter.com/${twitter}`, note: `linked Twitter on GitHub profile of ${login}` });
  }

  const summary = [
    u.location ? `location: ${u.location}` : "",
    typeof u.public_repos === "number" ? `${u.public_repos} repos` : "",
    typeof u.followers === "number" ? `${u.followers} followers` : "",
  ].filter(Boolean).join(" · ");
  return { provider: "github", query: login, tier: "T3", entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`), summary: summary || undefined };
}
