// PRD-2: the tradecraft floor, ported from the Python investigator + admission gate
// (investigations/agent/investigator.py::_promotion_gate, _grade_finding;
// investigations/admission.py::is_admissible). It keeps junk and name-only
// attributions OFF the graph in the browser exactly as the server does.
//
// The critical fidelity point (codex finding-1): the grade is computed from REAL
// tool corroboration, NOT from fields the model supplied. attributeFindings()
// scrubs agent-asserted grade/counts/identity before deriving the counts from the
// actual tool_result entities, so a forged "source_count: 9" cannot promote a node.
//
// Noise rules (phone shape, registry/reference domain lists, registry switchboard numbers)
// live in ./noise.ts — the verbatim port of investigations/noise.py — so the LISTS have ONE
// source, exactly as the original splits noise.py from admission.py. The first port folded a
// WEAKER inline copy here and 9 junk classes leaked (proven 2026-06-22); this imports the
// faithful module instead.

import { isNoiseDomain, isRealPhone, isBoilerplatePhone } from "./noise.js";
// sp-918b0d0d: reuse the ONE hard-token extractor (port of verify.py:hard_tokens) — the same primitive
// the grounded-Q&A citation check uses. No second copy of the regex set. The reverse import in
// grounding.ts is `import type` (erased at runtime), so there is no runtime cycle.
import { hardTokens } from "../chat/grounding.js";

export interface Finding {
  entity: string;
  entity_type: string;
  confidence?: string;
  unvalidated?: boolean;
  claim_unverified?: boolean;
  source_count?: number;
  infra_source_count?: number;
  grade?: string;
  identity_anchor?: string;
  // sp-918b0d0d: the agent's free-text claim + the claim-corroboration counts derived from it
  // (how many hard tokens the claim asserts, and how many a real tool result actually contained).
  claim?: string;
  claim_tokens?: number;
  claim_tokens_backed?: number;
  [k: string]: unknown;
}

/** One tool's observed result, for attribution. `infra` = an authoritative infra tool (DNS/RDAP/CT).
 *  An entity marked `self` is the QUERIED target echoed back by the provider (m3 / codex D4) — it does
 *  not corroborate a finding about that same target. */
export interface Observed {
  provider: string;
  infra: boolean;
  entities: { type: string; value: string; self?: boolean }[];
  // sp-918b0d0d: the (redacted) raw tool-result text. CLAIM-prose hard-token corroboration reads this
  // — the parsed `entities` alone can't prove the agent's claim asserted a fact a tool actually saw
  // (a whois result's "created 2025-12-22" is in the text, not in an extracted entity). Optional so
  // older call sites + entity-only tests keep working; absent text simply contributes nothing to backing.
  text?: string;
}

export interface GateVerdict {
  promote: boolean;
  grade: "A" | "B" | "C" | "D";
  reason: string;
}

const INFRA_ENTITY_TYPES = new Set(["domain", "subdomain", "ip", "ip_address", "url", "netblock", "asn"]);
const PERSON_ENTITY_TYPES = new Set(["person", "handle", "username", "account", "alias", "persona"]);
const HARD_FACT_TYPES = new Set(["ip", "ip_address", "email", "wallet", "crypto_wallet", "date"]);

const norm = (s: string): string => s.trim().toLowerCase();

// ---- attribution: derive corroboration from real tool results, scrub model trust ----

/**
 * Returns a finding with grade-bearing fields RECOMPUTED from the observed tool
 * results: agent-supplied grade / source_count / infra_source_count / identity_anchor
 * are dropped first (a forged count must never promote), then source_count and
 * infra_source_count are set from how many tools (and how many infra tools) actually
 * surfaced this entity. A hard-fact entity (IP/email/wallet/date) that no tool
 * corroborates is flagged claim_unverified.
 */
export function attributeFinding(finding: Finding, observed: Observed[], observedHardTokens?: Set<string>): Finding {
  const f: Finding = { ...finding };
  delete f.grade;
  delete f.source_count;
  delete f.infra_source_count;
  delete f.identity_anchor;
  delete (f as Record<string, unknown>).asset_confidence;
  // claim_unverified + its counts are DERIVED-trust fields — we compute them from real tool output, so a
  // model-supplied value must never persist (codex C: the scrub invariant — derived fields come from us,
  // not the model). The hard-fact-entity + claim-prose checks below set claim_unverified true when earned.
  delete f.claim_unverified;
  delete f.claim_tokens;
  delete f.claim_tokens_backed;

  const value = norm(f.entity ?? "");
  const providers = new Set<string>();
  const infraProviders = new Set<string>();
  for (const o of observed) {
    // A provider echoing the QUERIED target back (self:true) is not corroboration for a finding about
    // that same target (codex D4) — match only NON-self entities. Infra credit additionally requires the
    // MATCHED entity's OWN type to NOT be a person type (codex D5): a provider's person/handle echo must
    // never satisfy the person gate (which promotes a person finding once infra_source_count >= 1). The
    // strict "INFRA_ENTITY_TYPES only" reading was rejected — it would wrongly drop legitimate
    // wallet/cert/nameserver infra facts the free tools emit; denying only PERSON-typed matches is the
    // precise fix for the stated failure mode and regresses no free-tool path (they emit no person types).
    const match = o.entities.find((e) => !e.self && norm(e.value) === value);
    if (!match) continue;
    providers.add(o.provider);
    if (o.infra && !PERSON_ENTITY_TYPES.has(norm(match.type))) infraProviders.add(o.provider);
  }
  f.source_count = providers.size;
  f.infra_source_count = infraProviders.size;
  if (HARD_FACT_TYPES.has((f.entity_type ?? "").toLowerCase()) && f.source_count < 1) {
    f.claim_unverified = true;
  }

  // CLAIM-level corroboration (port of investigator.py _attribute_findings, replay D5). The check above
  // proves a tool saw the ENTITY; this proves a tool saw the asserted FACT. If the claim prose asserts a
  // hard token (ISO date / IPv4 / email / wallet) that NO tool result contains, it is an inference or
  // fabrication → flag claim_unverified (graded D, held as a lead). Soft claims (no hard token) are not
  // checkable here and pass through. Matches Python `claim_unverified = bool(claim_toks) and not backed`
  // — ANY one backed token clears the flag (it is not all-or-each). Backing is by TOKEN-SET membership,
  // not substring (codex D): the observed tool text is tokenized with the SAME hardTokens extractor, so
  // a claimed 1.2.3.4 is not falsely backed by 11.2.3.45 — a gate must fail closed. The observed token
  // set is precomputed ONCE per attribution pass (codex B) and passed in; computed here when absent so
  // the function stays standalone-testable.
  const claimToks = hardTokens(typeof f.claim === "string" ? f.claim : "");
  if (claimToks.size > 0) {
    const obsToks = observedHardTokens ?? observedTokenSet(observed);
    const backed = [...claimToks].filter((t) => obsToks.has(t)); // both sides lowercased by hardTokens
    f.claim_tokens = claimToks.size;
    f.claim_tokens_backed = backed.length;
    if (backed.length === 0) f.claim_unverified = true;
  } else {
    f.claim_tokens = 0;
  }
  return f;
}

/** The hard-token set across ALL observed tool-result text — extracted with the same hardTokens()
 *  the claim side uses, so claim-vs-observation backing is token-set membership (not substring). */
function observedTokenSet(observed: Observed[]): Set<string> {
  return hardTokens(observed.map((o) => (typeof o.text === "string" ? o.text : "")).join(" "));
}

export function attributeFindings(findings: Finding[], observed: Observed[]): Finding[] {
  // codex B: tokenize the observed tool text ONCE per pass, not once per finding (a deep run with many
  // findings + large tool outputs would otherwise be O(findings × total_text)).
  const obsToks = observedTokenSet(observed);
  return findings.map((f) => attributeFinding(f, observed, obsToks));
}

// ---- grade (port of _grade_finding) ----

export function gradeFinding(f: Finding): "A" | "B" | "C" | "D" {
  const srcs = f.source_count ?? 0;
  const infra = f.infra_source_count ?? 0;
  const conf = (f.confidence ?? "medium").toLowerCase();
  if (f.unvalidated || f.claim_unverified || srcs < 1) return "D";
  if (infra >= 2 || (infra >= 1 && conf === "high")) return "A";
  if (infra >= 1 || srcs >= 2) return "B";
  return "C";
}

// ---- admission (port of admission.is_admissible) ----

const CSS_AT_RE = /^@(media|import|keyframes|font-face|charset|supports|namespace|page)\b/i;
const MISPARSE_PHRASES = [
  "report date",
  "registrar privacy",
  "privacy-proxy",
  "privacy proxy",
  "whois privacy",
  "mis-parsed",
  "misparsed",
  "parser glitch",
  "ocr artifact",
];
const DOMAINISH = new Set(["domain", "subdomain", "url"]);
// sp-d743695e: the noise-domain check also applies to nameserver/mailserver values — a registrar/registry
// nameserver (whois.*, generic NS markers, known NOISE_DOMAINS) is host-shaped boilerplate, not target
// infra, and was reaching the graph because isAdmissible only consulted isNoiseDomain for DOMAINISH types.
const NOISE_CHECKED_TYPES = new Set([...DOMAINISH, "nameserver", "mailserver"]);
const OPAQUE_VALUE_TYPES = new Set([
  "affiliate_id",
  "wallet",
  "crypto_wallet",
  "hash_sha256",
  "hash_md5",
  "asn",
  "indicator",
  "fingerprint",
]);
// \p{Nd} (Unicode decimal), NOT ASCII `\d` — admission.py's `_DOTTED_QUAD_RE` is Unicode `\d` + `int()`,
// so an IPv4 written in a supported OCR script (ara → Arabic-Indic, fas → Farsi, CJK → fullwidth) is a
// real IP. The ASCII regex missed it: the dot-strip in isUniversalJunk then collapsed ١.١.١.١ → ١١١١
// (all-same) and DROPPED a real IP as a placeholder — a data-loss divergence on a supported language
// (sp-34441101 gap-3). Math-bold / exotic \p{Nd} (gap-1) is accepted-as-designed: see toAsciiDigits below.
const DOTTED_QUAD_RE = /^\p{Nd}{1,3}(?:\.\p{Nd}{1,3}){3}$/u;
function isDottedQuad(v: string): boolean {
  if (!DOTTED_QUAD_RE.test(v)) return false;
  // Normalize the supported scripts to ASCII first, then require fully-ASCII octets: an unsupported
  // \p{Nd} script (e.g. math-bold) leaves a non-ASCII octet → Number() NaN, so it is NOT treated as a
  // quad here (falls through to the bare-digit path, no new divergence). int()/Number() ≤255 matches Python.
  const ascii = toAsciiDigits(v);
  if (!/^[0-9.]+$/.test(ascii)) return false;
  return ascii.split(".").every((o) => Number(o) <= 255);
}

// Decimal-digit '0' code points for the scripts kipi actually processes. This table is COMPLETE for
// kipi's tesseract OCR language set (eng/ara/fas/heb/rus/chi): eng/rus emit ASCII digits, heb has no
// \p{Nd} digits (Hebrew numerals are letters), CJK ideographic numerals are not \p{Nd} either —
// ara → Arabic-Indic U+0660, fas → Extended-Arabic/Farsi U+06F0, CJK text → fullwidth U+FF10. So no
// other \p{Nd} script (Devanagari, Thai, NKo, Mathematical-Alphanumeric) can ever enter the pipeline;
// leaving those unmapped is correct-by-construction, NOT a gap (codex adversarial 2026-06-23 confirmed
// 0/3079 divergences across the 4 supported scripts; its math-bold/Devanagari/Thai counter-examples are
// unreachable input — sp-34441101 gaps 1-2, accepted-as-designed).
// Each script's ten digits are the next ten code points (a Unicode invariant), so value = cp - base.
const DIGIT_ZERO_BASES = [0x30, 0x0660, 0x06f0, 0xff10];

// Map the supported \p{Nd} scripts' digits to ASCII 0-9, matching admission.py's `int()` (Unicode-aware).
// An explicit base table — NOT an offset-from-run-zero walk: the Mathematical Alphanumeric blocks
// (U+1D7CE…) pack five decimal runs back-to-back, so a walk maps double-struck '0' to "9" (codex). A
// \p{Nd} script not in the table is left verbatim, so the ASCII guard in isUniversalJunk skips the
// date-parse for it (no wrong value) — those exotic scripts are out of kipi's real input set (sp-f9d3c9ff).
function toAsciiDigits(s: string): string {
  return s.replace(/\p{Nd}/gu, (ch) => {
    const cp = ch.codePointAt(0)!;
    for (const base of DIGIT_ZERO_BASES) if (cp >= base && cp <= base + 9) return String(cp - base);
    return ch;
  });
}

function isUniversalJunk(value: string): boolean {
  const low = value.toLowerCase();
  if (CSS_AT_RE.test(value)) return true;
  if (/[\n\r\t]/.test(value) || /\\[nrt]/.test(value)) return true;
  if (MISPARSE_PHRASES.some((p) => low.includes(p))) return true;
  if (isDottedQuad(value)) return false; // a real IPv4 is structural, never a bare-number placeholder
  const rawDigits = value.replace(/[\s().+-]/g, "");
  // \p{Nd} (any Unicode decimal digit), NOT /^\d+$/ (ASCII only) — admission.py's isdigit() is Unicode-aware.
  if (/^\p{Nd}+$/u.test(rawDigits)) {
    if (new Set(rawDigits).size <= 1) return true; // 000000000 / ٠٠٠٠٠٠ placeholder (raw set, matches Python; any \p{Nd})
    const digits = toAsciiDigits(rawDigits); // normalize for the value checks below (matches Python int())
    // Only date-parse a string we fully normalized to ASCII; an unsupported \p{Nd} script falls through here.
    if (!/^[0-9]+$/.test(digits)) return false;
    if (digits.length === 8) {
      const y = +digits.slice(0, 4);
      const mo = +digits.slice(4, 6);
      const d = +digits.slice(6, 8);
      if (y >= 2000 && y <= 2099 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31) return true; // YYYYMMDD
    }
    // YYMMDD (6-digit) date fragment — a date written 26-05-27 strips to "260527" and was reaching the
    // graph as a junk node (founder, 2026-06-22). NARROW to keep real 6-digit IDs: the YY must be the
    // CURRENT DECADE (20-29) AND a valid month (01-12) AND day (01-31). So '123456' (mo 34), '100200'
    // (day 00), and '120531' (yy 12 — a plausible order/ticket id) are NOT gated; '260527' (yy 26) is.
    // (codex: an unbounded YYMMDD over-gated real ids. Extend the YY window past 2029 when the decade turns.)
    if (digits.length === 6) {
      const yy = +digits.slice(0, 2);
      const mo = +digits.slice(2, 4);
      const d = +digits.slice(4, 6);
      if (yy >= 20 && yy <= 29 && mo >= 1 && mo <= 12 && d >= 1 && d <= 31) return true; // YYMMDD, current decade
    }
  }
  return false;
}

/** (admissible, "") or (false, reason). THE one entity-admission contract, in TS.
 *  `prevalidated` (ig-extract D7): a phone whose value was already validated by upstream context
 *  (a phone-LABEL within 24 chars in the extractor — Python's phone_prevalidated) bypasses the
 *  bare-digits isRealPhone check, matching the server. The universal-junk/date guard still applies. */
export function isAdmissible(entityType: string | undefined, value: string | undefined, prevalidated = false): [boolean, string] {
  // A forged/legacy vault record can carry a NON-string entity_type/value at runtime (it's `as`-cast past
  // the type system) — `?? ""` only guards null/undefined, so a number/object reaches `.trim()` and crashes
  // the whole entity-DB build (the latent /entities + /inbox-Sources crash). Coerce by type, the same
  // validate-a-forged-record-to-a-safe-shape discipline as canonType / canonRef / validateAnalysisRecord.
  const et = (typeof entityType === "string" ? entityType : "").trim().toLowerCase();
  const v = (typeof value === "string" ? value : "").trim();
  if (!v) return [false, "empty value"];
  if (v.length <= 2) return [false, "too short to be a real entity"];
  if (!OPAQUE_VALUE_TYPES.has(et) && isUniversalJunk(v)) {
    return [false, "mis-parsed / placeholder / date — not an entity"];
  }
  if (et === "phone" && isBoilerplatePhone(v)) {
    return [false, "a registry's own whois contact number — boilerplate, not the target"];
  }
  if (et === "phone" && !prevalidated && !isRealPhone(v)) {
    return [false, "not a phone number — a bare id / tracking number"];
  }
  if (DOMAINISH.has(et) && (v.endsWith("'") || v.endsWith('"'))) {
    return [false, "trailing quote — a quoted-string fragment, not the entity itself"];
  }
  if (NOISE_CHECKED_TYPES.has(et) && isNoiseDomain(v)) {
    return [false, "registry / WHOIS / reference boilerplate — not target infrastructure"];
  }
  if (et === "email" && isNoiseDomain(v)) {
    return [false, "a registry / reference domain's contact address — whois boilerplate"];
  }
  return [true, ""];
}

// ---- live-graph worthiness (PRD live-graph-quality, Codex finding-1) ----

// A value a tool emits under MULTIPLE entity types within ONE observation is tooling noise (e.g. an
// A-record IP echoed as ip + nameserver + mailserver by a loose parser). collapseObservedTwins keeps ONE
// node per value, typed by this fixed precedence (structural/most-specific first), dropping the redundant
// twins. The precedence list is the SINGLE source of truth — no "pick the best type" judgment. A value
// seen under a single type is untouched; this dedups ONLY within one observation, so genuine cross-tool /
// cross-observation corroboration (same value+type from two tools) is never affected.
const LIVE_TYPE_PRECEDENCE = ["ip", "ip_address", "domain", "subdomain", "url", "wallet", "crypto_wallet", "email", "nameserver", "mailserver"];

export function liveTypeRank(type: string | undefined): number {
  const i = LIVE_TYPE_PRECEDENCE.indexOf((type ?? "").trim().toLowerCase());
  return i < 0 ? LIVE_TYPE_PRECEDENCE.length : i; // an unknown type ranks LAST (kept only if it has no known-type twin)
}

/** Collapse same-value multi-type twins to ONE entity (highest precedence), preserving first-seen order.
 *  Generic so it accepts the loop's ObservedEvent entities ({type,value,self?}) unchanged.
 *
 *  Only collapses a value whose collision involves at least one KNOWN structural type (codex finding-1): a
 *  value emitted under an `ip`/`domain`/… type AND a junk twin is tooling noise → keep the structural one.
 *  A value whose colliding types are ALL unlisted (e.g. registrar+registrant, person+handle) is left intact
 *  — those may be legitimately distinct entities that happen to share a value, NOT tooling noise. */
export function collapseObservedTwins<T extends { type: string; value: string }>(entities: T[]): T[] {
  const byValue = new Map<string, T[]>();
  for (const e of entities) {
    const key = e.value.trim().toLowerCase();
    const list = byValue.get(key);
    if (list) list.push(e);
    else byValue.set(key, [e]);
  }
  const drop = new Set<T>();
  for (const group of byValue.values()) {
    if (group.length < 2) continue; // a single observation of a value is never collapsed
    const best = Math.min(...group.map((e) => liveTypeRank(e.type)));
    if (best >= LIVE_TYPE_PRECEDENCE.length) continue; // ALL types unlisted → keep all (not tooling noise)
    let kept = false;
    for (const e of group) {
      if (!kept && liveTypeRank(e.type) === best) { kept = true; continue; } // keep the first best-ranked twin
      drop.add(e); // drop every other typing of this same value
    }
  }
  return entities.filter((e) => !drop.has(e));
}

// ---- promotion gate (port of _promotion_gate) ----

/** Whether a finding may auto-build the graph, and if not, why. A/B promote; C/D land as LEADS. */
export function promotionGate(finding: Finding): GateVerdict {
  const f: Finding = { ...finding };
  delete f.identity_anchor; // never trust an agent-supplied identity annotation
  const grade = gradeFinding(f);
  const etype = (f.entity_type ?? "").toLowerCase();
  const value = f.entity ?? "";

  const [ok, why] = isAdmissible(etype, value);
  if (!ok) return { promote: false, grade, reason: `not graphed (${why}); lead` };
  if (f.unvalidated) return { promote: false, grade, reason: "agent marked unvalidated (grade D)" };
  if (f.claim_unverified) {
    return { promote: false, grade, reason: "claim asserts a hard fact no tool result contains — lead" };
  }
  if (grade === "D") return { promote: false, grade, reason: "grade D — no tool result contains this; lead" };
  if (grade === "C") return { promote: false, grade, reason: "grade C — single web/inferred source; lead" };
  if (INFRA_ENTITY_TYPES.has(etype) && (f.infra_source_count ?? 0) < 1) {
    return { promote: false, grade, reason: "web-recall only — no infra tool confirmed this domain/IP; lead" };
  }
  if (PERSON_ENTITY_TYPES.has(etype) && (f.infra_source_count ?? 0) < 1) {
    return {
      promote: false,
      grade: grade === "A" || grade === "B" ? "C" : grade,
      reason: "person/handle with no non-fakeable crosslink (name/web only) — unverified identity; lead",
    };
  }
  return { promote: true, grade, reason: "" };
}
