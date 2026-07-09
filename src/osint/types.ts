// Browser-native OSINT: typed results from CORS-open providers. No key, no proxy.
// Evidence tier per the q-investigation ruleset (T1 = non-fakeable record).

export type EntityType =
  | "domain"
  | "subdomain"
  | "ip"
  | "nameserver"
  | "mailserver"
  | "registrar"
  | "registrant"
  | "cert"
  | "wallet"
  // chunk-5 enrich: an Autonomous System number + a scanned URL. Both are already in the gate's
  // INFRA_ENTITY_TYPES (gate.ts); `asn` is also in OPAQUE_VALUE_TYPES, so its value bypasses the
  // bare-digits junk check (an ASN is a number, not a phone/tracking id).
  | "asn"
  | "url"
  // PRD prd-hydra-free-osint-providers finding-5: identity/corporate typed pivots. NONE are in the gate's
  // INFRA_ENTITY_TYPES, so an identity/lead entity NEVER inflates infra_source_count — they land as T3
  // graph pivots (finding-5: typed, not summary text), never as promoted attribution on their own. `account`
  // = a platform account / profile (github/gitlab/HN/npm/social handle or profile URL); `person` = a person
  // name; `org` = a company / organization; `email` = an email address surfaced as a lead.
  | "account"
  | "person"
  | "org"
  | "email";

export interface OsintEntity {
  type: EntityType;
  value: string;
  note?: string;
}

export interface OsintResult {
  provider: string;
  query: string;
  tier: "T1" | "T2" | "T3";
  entities: OsintEntity[];
  /** restore-tool-belt: a human-readable analysis block for tools whose VALUE is the text, not a typed
   *  entity (phone parse, email triage/headers, ofac screen). runTool surfaces it to the agent alongside
   *  the entities. Optional — the entity-only infra tools (dns/rdap/ct/on-chain) never set it. */
  summary?: string;
}

export type FetchLike = typeof fetch;

export interface OsintOpts {
  fetchImpl?: FetchLike;
  retries?: number;
  /** Abort an in-flight lookup (the agent loop's Stop button). Threaded into fetch + backoff. */
  signal?: AbortSignal;
  /** PRD-B agent-browser-forensics: the user's deployed Worker-proxy URL (setting:worker_url). The agent's
   *  browser-forensic + CORS-blocked tools route through it (renderViaProxy). Injected by the session into
   *  toolOpts; absent until the user deploys + configures their Worker (the tools then error gracefully). */
  workerUrl?: string;
}

function abortError(): DOMException {
  return new DOMException("aborted", "AbortError");
}

/** Retry a thunk with linear backoff. Degenerate case retries=0 -> single attempt.
 *  An AbortSignal stops it cleanly: a pending backoff sleep rejects, and no further
 *  attempt starts once aborted. */
export async function withRetry<T>(
  fn: () => Promise<T>,
  retries = 2,
  backoffMs = 250,
  signal?: AbortSignal,
): Promise<T> {
  let last: unknown;
  for (let attempt = 0; attempt <= retries; attempt++) {
    if (signal?.aborted) throw abortError();
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (attempt < retries) await sleep(backoffMs * (attempt + 1), signal);
    }
  }
  throw last;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(abortError());
      },
      { once: true },
    );
  });
}

// ---- chunk-5 enrich: shared adapter helpers (kept here, NOT in enrich.ts, so the adapters can
//      import them without a cycle — enrich.ts imports the adapters for the registry). ----

/** Per-provider hard cap on how many raw result rows an adapter parses. A malicious or huge
 *  provider response can never materialize an unbounded entity array (codex D7): the adapter
 *  SLICES the result list to this length BEFORE parsing/deduping. */
export const MAX_ENRICH_RESULTS = 100;

/** A valid http(s):// URL WITH a host, or null (codex D8). A junk / hostless / non-http string is
 *  never emitted as a `url` entity (which would otherwise be gate-admissible infra). */
export function httpUrlOrNull(value: string): string | null {
  try {
    const u = new URL(value.trim());
    if ((u.protocol === "http:" || u.protocol === "https:") && u.hostname) return u.href;
  } catch {
    /* not a URL */
  }
  return null;
}

// A hostname that is a real FQDN (same shape as enrich.ts DOMAIN_RE): 1-253 chars, labelled, TLD 2-63.
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/** The lowercased FQDN, or null if `value` is not a valid domain (PRD prd-hydra-free-osint-providers
 *  adversarial finding-1/2). A provider-controlled hostname is validated BEFORE it is emitted as a
 *  gate-admissible `domain` entity, so a hostile response cannot inject junk as an infra pivot. */
export function validDomainOrNull(value: string): string | null {
  const v = value.trim().toLowerCase();
  return DOMAIN_RE.test(v) ? v : null;
}

/** Normalize an ASN to the canonical `AS<number>` form, or null if it is not a number (codex D8).
 *  Accepts 15169, "15169", "AS15169", "as15169". */
export function normalizeAsn(raw: string | number | undefined | null): string | null {
  if (raw === undefined || raw === null) return null;
  const m = /^\s*(?:AS)?(\d+)\s*$/i.exec(String(raw));
  return m ? `AS${m[1]}` : null;
}

/** RFC4648 base64 of `s` (browser btoa, with a Buffer fallback for the node test env). Used for
 *  Censys Basic auth — base64("id:secret"). */
export function base64(s: string): string {
  if (typeof btoa === "function") return btoa(s);
  // node test env fallback (vitest); never reached in the browser bundle
  return Buffer.from(s, "utf8").toString("base64");
}

// PRD prd-hydra-free-osint-providers finding-5 (codex): a bare identity handle — alphanumeric-start, then
// 0-38 of [alnum . _ -], no leading @ (the caller strips it). Bounds what the free identity adapters will
// fetch so a pasted bio / free-text query can't be sent to github/gitlab/HN/npm as a "username".
const BARE_HANDLE_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{0,38})$/;
export function isBareHandle(value: string): boolean {
  return BARE_HANDLE_RE.test(value);
}

// A bare Twitter/X handle: 1-15 word chars (Twitter's own rule). A hostile GitHub `twitter_username` that
// is not a real handle is dropped rather than interpolated into an account-URL pivot (codex adversarial).
const TWITTER_HANDLE_RE = /^[A-Za-z0-9_]{1,15}$/;
export function isTwitterHandle(value: string): boolean {
  return TWITTER_HANDLE_RE.test(value);
}

// A valid npm package name (optionally @scope/name), url-path-safe charset only. A hostile registry `name`
// that is not a real package name is dropped rather than interpolated into a package-URL pivot (codex).
const NPM_NAME_RE = /^(?:@[a-z0-9-~][a-z0-9._~-]*\/)?[a-z0-9-~][a-z0-9._~-]*$/;
export function isNpmPackageName(value: string): boolean {
  return value.length <= 214 && NPM_NAME_RE.test(value);
}

// PRD prd-hydra-free-osint-providers finding-3 (codex): a provider-controlled string rendered into a
// summary must be length-bounded — a hostile response can return giant strings that blow up the tool result
// / UI / model context even when the COUNT is capped. Returns "" for a non-string, else the trimmed value
// truncated to `max` (default 120) chars with an ellipsis marker.
export function capString(value: unknown, max = 120): string {
  if (typeof value !== "string") return "";
  const v = value.trim();
  return v.length <= max ? v : `${v.slice(0, max)}…`;
}

// PRD prd-hydra-free-osint-providers finding-5 (codex adversarial): a relatedness guard for entity-resolution
// providers (GLEIF / Wikidata). A hostile registry/knowledge-graph response must not attribute an UNRELATED
// entity to the queried name. Normalize both to lowercase-alphanumeric and require a containment overlap
// either direction (query ⊆ candidate or candidate ⊆ query), with a 2-char floor so a trivial token can't
// match everything. Deliberately lenient (it allows "Apple" ↔ "Apple Inc."), strict enough to drop a wholly
// unrelated substitution.
export function normalizeName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}
export function isNameRelated(query: string, candidate: string): boolean {
  const q = normalizeName(query);
  const c = normalizeName(candidate);
  if (q.length < 2 || c.length < 2) return false;
  return q.includes(c) || c.includes(q);
}

export function uniqueBy<T>(items: T[], keyFn: (t: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const it of items) {
    const k = keyFn(it);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(it);
    }
  }
  return out;
}
