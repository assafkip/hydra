// rel-vocab (INC-4a, parity port of investigations/enrich/rel_vocab.py): the CLOSED controlled
// vocabulary for typed-relationship edge labels + the single `normalizeRel` gate every landing path
// calls. No free-form rel_type reaches the persisted graph — normalizeRel returns a vocab member, a
// clean per-case schema label (allowNovel), or null (skip). Kept term-for-term faithful to the Python
// source (tests/entity/rel-vocab.test.ts reads rel_vocab.py and asserts key parity — codex P4), so the
// two enums can never drift.

// The closed set: term -> human gloss. Membership is what matters; the gloss feeds the edge legend.
export const REL_VOCAB: Record<string, string> = {
  // DNS / hosting
  resolves_to: "resolves to IP",
  hosted_on: "hosted on",
  uses_nameserver: "uses nameserver",
  uses_mailserver: "uses mailserver (MX)",
  has_subdomain: "has subdomain",
  reverse_dns: "reverse DNS",
  prior_resolution: "previously resolved to",
  routes_through: "routes through (CDN/proxy)",
  // TLS / platform fingerprint
  shares_certificate: "shares TLS certificate",
  same_platform: "same backend platform / kit",
  // Registration
  registered_by: "registered by",
  same_registrant: "same registrant",
  // Geo / network
  geolocated_in: "geolocated in",
  shared_infra: "shared infrastructure",
  // Threat
  flagged_ioc: "flagged as IOC",
  exposed_service: "exposed service",
  // Identity
  same_as: "same entity as",
  alias_of: "alias of",
  linked_account: "linked account",
  // Actor / org
  operated_by: "operated by",
  operates: "operates",
  same_operator: "same operator as",
  member_of: "member of",
  affiliated_with: "affiliated with",
  // Backend / application
  uses_backend: "uses backend",
  api_endpoint: "API endpoint",
  payment_endpoint: "payment endpoint",
  // Financial
  transacts_with: "transacts with",
  drains_to: "drains funds to",
  uses_affiliate: "uses affiliate program",
  // Behavioral
  shills: "shills / promotes",
  targets: "targets",
  contradicts: "contradicts",
  // Shared-fingerprint correlation (the "same operator" signal)
  shares_tracking_tag: "shares tracking tag (same operator)",
  shares_walletconnect: "shares WalletConnect id (same kit/operator)",
  shares_service_account: "shares SaaS service account (same operator)",
  shares_registrant: "shares registrant (same registrant)",
  shares_nameserver: "shares nameserver (shared infrastructure)",
  shares_registrar: "shares registrar (weak)",
  // Hacktivist / disinfo domain labels (analyze.py no-schema default REL_TYPES)
  posts_in: "posts in channel",
  ally_with: "public ally with",
  predecessor_of: "predecessor of (replaced/deleted by)",
  defaced: "defaced",
  co_admin: "co-administers",
  // Generic fallback (an unrecognized label generalizes here, never lost)
  linked_to: "linked to",
};

// Near-dupe / legacy / provider labels → one canonical vocab term. Every value must be a REL_VOCAB key
// (asserted at module load, mirroring _assert_synonyms_valid).
export const REL_SYNONYMS: Record<string, string> = {
  // backend family
  uses_backend_api: "uses_backend",
  backend_api: "uses_backend",
  backend_of: "uses_backend",
  uses_backend_domain: "uses_backend",
  // DNS / hosting aliases
  runs_on: "hosted_on",
  hosted_by: "hosted_on",
  cdn_host: "routes_through",
  uses_ns: "uses_nameserver",
  uses_mx: "uses_mailserver",
  // endpoint aliases
  exposes_endpoint: "api_endpoint",
  // registration aliases
  registered_same_day: "same_registrant",
  registered_as: "registered_by",
  // affiliate aliases
  affiliate_instance_of: "uses_affiliate",
  // cert / geo / account aliases
  shares_cert: "shares_certificate",
  geolocated: "geolocated_in",
  account_found: "linked_account",
  breach_exposure: "linked_account",
  same_branding: "same_platform",
  // generic agent / search discovery → the catch-all
  enriched: "linked_to",
  enriched_via_agent: "linked_to",
  discovered_with: "linked_to",
  linked_via_search: "linked_to",
  related: "linked_to",
  related_to: "linked_to",
  linked: "linked_to",
};

// Co-occurrence flags that are a NODE PROPERTY, not an edge → normalizeRel returns null.
export const DROP_RELS: ReadonlySet<string> = new Set(["flagged_malicious_alongside"]);

// Vague labels worth a second pass against the evidence text before falling back to linked_to.
const VAGUE: ReadonlySet<string> = new Set(["same_campaign", "linked_to"]);

const CLEAN_TOKEN_MAX = 40;

// fail loud at module load if a synonym points outside the vocab (mirrors _assert_synonyms_valid)
for (const [k, v] of Object.entries(REL_SYNONYMS)) {
  if (!(v in REL_VOCAB)) throw new Error(`REL_SYNONYMS value not in REL_VOCAB: ${k} -> ${v}`);
}

/** Lowercase, collapse any non-alnum run to a single underscore, strip edge underscores. A non-string
 *  (malformed LLM JSON) → "" so normalizeRel skips the row instead of crashing the apply pass. */
export function slugRel(rel: unknown): string {
  if (typeof rel !== "string") return "";
  return rel.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/** A vague label resolved against the evidence/provenance text to a concrete vocab term. Only upgrades
 *  a vague label, never downgrades; every output is a vocab member. Order matches Python exactly. */
export function evidenceRemap(evidence: string): string {
  const e = (evidence || "").toLowerCase();
  if (e.includes("a record") || e.includes("resolves to") || e.includes("resolved to") || e.includes("dns a ")) return "resolves_to";
  if (e.includes("reverse dns") || e.includes("ptr record") || e.includes("ptr:")) return "reverse_dns";
  if (e.includes("name server") || e.includes("nameserver") || e.includes("ns record")) return "uses_nameserver";
  if (e.includes("hosted on") || e.includes("hosted by") || e.includes("hosting provider")) return "hosted_on";
  if (e.includes("fingerprint") || e.includes("platform") || e.includes("/api/") || e.includes("kit")) return "same_platform";
  if (e.includes("cloudflare") || e.includes(" pop") || e.includes("shared ip") || e.includes("same ip") || e.includes("same asn") || e.includes("shared asn")) return "shared_infra";
  if (e.includes("registered by")) return "registered_by";
  if (e.includes("registr")) return "same_registrant";
  return "linked_to";
}

/** A short snake_case token (a-z0-9 + underscores, within bound, not all-digits). */
export function isCleanToken(norm: string): boolean {
  return !!norm && norm.length <= CLEAN_TOKEN_MAX && /^[a-z0-9_]+$/.test(norm) && !/^\d+$/.test(norm);
}

/** The single binding gate (parity with normalize_rel): map ANY proposed edge label to a vocab term,
 *  or null to skip. Order: slug → drop co-occurrence flags → synonym map → vocab? → evidence remap for
 *  vague → found_via_* prefix → novel(allowNovel)/linked_to. */
export function normalizeRel(rel: unknown, evidence = "", allowNovel = false): string | null {
  let norm = slugRel(rel);
  if (!norm) return null;
  if (DROP_RELS.has(norm) || norm.endsWith("_alongside")) return null;
  norm = REL_SYNONYMS[norm] ?? norm;
  if (VAGUE.has(norm)) norm = evidenceRemap(evidence);
  if (norm in REL_VOCAB) return norm;
  if (norm.startsWith("found_via_")) return "linked_to";
  if (allowNovel && isCleanToken(norm)) return norm; // genuine per-case domain label
  return "linked_to"; // unknown → generalize, never invent
}

/** Human-readable label for a vocab term (edge legend / tooltip). */
export function gloss(rel: string): string {
  return REL_VOCAB[rel] ?? rel;
}
