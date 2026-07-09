// npm-user — keyless npm maintainer→packages lookup via the registry search API (registry.npmjs.org/-/v1/
// search, CORS `*`, re-probed live from the hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers
// finding-5/6. The `-/user/...` profile endpoint needs auth (401), so this uses the ANONYMOUS maintainer
// search: it enumerates the packages a username publishes, each carrying the publisher email + the source
// repo. Package authorship is a T3 LEAD (a username can publish anything), so infra:false.
//
// finding-6 divergence: identity-lookup.sh / osint_mcp git_emails mine emails from a repo's git history
// server-side; this DIVERGES to the keyless registry search — it reaches the publisher email + repo URL that
// the registry already indexes, no git clone. Emits typed pivots (account/url/email), not summary text.
// NO token for the anonymous search API — keyless only.
import { httpUrlOrNull, isBareHandle, isNpmPackageName, MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://registry.npmjs.org/-/v1/search";
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

interface SearchObject {
  package?: {
    name?: string;
    links?: { repository?: string; homepage?: string; npm?: string };
    publisher?: { email?: string; username?: string };
  };
}
interface SearchResponse {
  total?: number;
  objects?: SearchObject[];
}

/** username → the packages they maintain, as typed pivots (npm package account, source repo url, publisher
 *  email). Keyless T3 lead (anonymous search API, no token). */
export async function npmUser(handle: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const username = handle.trim().replace(/^@/, "");
  if (!isBareHandle(username)) throw new Error("npm: not a valid username"); // codex: bound what we fetch
  const url = `${ENDPOINT}?text=${encodeURIComponent(`maintainer:${username}`)}&size=25`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`npm HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object" || !Array.isArray((json as SearchResponse).objects)) {
    throw new Error("npm: unexpected response shape");
  }
  const objects = (json as SearchResponse).objects!.slice(0, MAX_ENRICH_RESULTS); // cap before materializing entities
  const entities: OsintEntity[] = [];
  const emails = new Set<string>();
  for (const o of objects) {
    const pkg = o.package;
    if (!pkg) continue;
    // Validate the provider-controlled package name before interpolating it into a URL (codex adversarial):
    // a hostile name with slashes/query/fragment must never become a junk pivot. Encode the path segments
    // (a valid scoped name @scope/name keeps its one slash — encode each part, not the separator).
    if (pkg.name && isNpmPackageName(pkg.name)) {
      const path = pkg.name.split("/").map(encodeURIComponent).join("/");
      entities.push({ type: "account", value: `https://www.npmjs.com/package/${path}`, note: `npm package published by ${username}` });
    }
    const repo = pkg.links?.repository;
    if (repo) {
      const clean = httpUrlOrNull(repo.replace(/^git\+/, "").replace(/\.git$/, ""));
      if (clean) entities.push({ type: "url", value: clean, note: `source repo of an ${username} package` });
    }
    // Only the publisher email for THIS username is an identity lead (a co-maintainer's email is not).
    const pub = pkg.publisher;
    if (pub?.username?.toLowerCase() === username.toLowerCase() && pub.email && EMAIL_RE.test(pub.email)) {
      emails.add(pub.email.toLowerCase());
    }
  }
  for (const e of emails) entities.push({ type: "email", value: e, note: `npm publisher email of ${username}` });
  const capped = uniqueBy(entities, (e) => `${e.type}:${e.value}`).slice(0, MAX_ENRICH_RESULTS);
  const summary = `${objects.length} package(s) maintained by ${username}`;
  return { provider: "npm", query: username, tier: "T3", entities: capped, summary };
}
