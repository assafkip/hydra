// ig-extract: the entity extractor, ported from investigations/ingest/extractor.py. PURE: no DOM,
// clock, randomness, LLM, or fetch. Every candidate runs through the EXISTING isAdmissible gate
// (agent/gate.ts) — the same admission contract the graph + entity DB use — so junk / placeholders /
// dates / noise-domains never become entities.
//
// Faithful ports the codex review pinned:
//  - DOMAIN_TLDS is the EXACT frozenset incl. the deliberate file-extension ccTLD omissions
//    (.md/.py/.rs/.sh/.so/.pe) so README.md / main.py are never typed as domains (D10).
//  - _scan_gated: ambiguous patterns (walletconnect 32-hex, solana/xrp base58) emit ONLY when a
//    context keyword sits within GATE_WINDOW=60 chars of the match (D9).
//  - cross-type precedence by START-OFFSET (Python tracks m.start()): a span claimed by an earlier,
//    more specific scan is skipped by a later scan (governs walletconnect_id vs md5) (D8).
//  - phone: a phone LABEL within 24 chars before the match prevalidates a bare number (D7); a
//    date-shape is rejected first.
//
// SCOPE (D6): this chunk ships the high-confidence infra/ioc/contact subset. It INTENTIONALLY DEFERS
// person / tech_stack / saas_service_account / registrar / nameserver (person extraction is
// high-false-positive); those are a later chunk.

import { isAdmissible } from "../agent/gate.js";
import { IANA_TLDS } from "./iana-tlds.js"; // the authoritative IANA TLD universe (generated mirror of extractor.py's iana_tlds.txt)

export interface ExtractedEntity {
  value: string;
  type: string;
  start?: number; // char offset of this occurrence in the scanned text — used by inferRelationships
                  // for proximity co-occurrence (parity with extractor.py). Optional: structured
                  // (CSV/XLSX) entities have no text offset; consumers that only need value/type ignore it.
}

// extractor.py infer_relationships default — two entities co-occur only within this many chars.
const PROXIMITY_CHARS = 200;

// ---- regex set (verbatim from extractor.py) ----
const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]+\b/g; // clu-email-trailing-punct: trailing \b (verbatim from extractor.py) so a sentence-final email drops the trailing period
const HANDLE_RE = /(?<![\w@])@[A-Za-z0-9_]{2,32}\b/g;
const TELEGRAM_RE = /\b(?:t\.me|telegram\.me)\/(?:joinchat\/)?([A-Za-z0-9_-]{3,})/gi;
const PHONE_RE = /\+?\d[\d\s().-]{7,}\d/g;
const SHA256_RE = /\b[a-fA-F0-9]{64}\b/g;
const MD5_RE = /\b[a-fA-F0-9]{32}\b/g;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b/g;
const WALLET_RE = /\b(?:0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{6,87}|BC1[AC-HJ-NP-Z02-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g;
const DOMAIN_RE = /\b(?!www\.)(?:[a-zA-Z0-9-]+\.)+([a-zA-Z]{2,24})\b/g;
const TRACKING_TAG_RE = /\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{6,8}|AW-\d{9,11})\b/g;
const TRON_RE = /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g;
const WALLETCONNECT_RE = /\b[0-9a-f]{32}\b/g; // collides with md5 -> gated, scanned BEFORE md5
const SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;
const XRP_RE = /\br[1-9A-HJ-NP-Za-km-z]{24,34}\b/g;

const GATE_WALLETCONNECT = ["walletconnect", "projectid", "project id", "web3modal", "wagmi", "reown"];
const GATE_SOL = ["solana", "sol ", "phantom", "spl", "$sol", "sol/"];
const GATE_XRP = ["xrp", "ripple", "xrpl", "destinationtag", "destination tag"];
const GATE_WINDOW = 60;

const _PHONE_LABEL_RE = /\b(phone|tel|mobile|cell|fax|whatsapp|msisdn)\b/i;
const _DATE_SHAPE_RE = /\d{4}[-.]\d{1,2}[-.]\d{1,2}|\d{1,2}[-.]\d{1,2}[-.]\d{4}/;

// ---- FILE_EXT_DENY — the EXACT frozenset from extractor.py ----
// Domain detection gates the TLD on the authoritative IANA list (./iana-tlds.ts — every real scam TLD
// lands, prose like "1.Introduction" doesn't) MINUS this file-extension denylist, so a filename whose
// ext is also a real ccTLD (.md/.py/.sh) or a common doc/code/image ext (.pdf/.png) never types as a
// domain. Founder 2026-06-22: flexible TLDs, no hand-curated allow-list. Mirrors extractor.py.
const FILE_EXT_DENY = new Set(
  "md py rs sh so pe ts js go rb c h cpp java php json yml yaml toml ini txt log csv tsv xml html htm css scss pdf doc docx xls xlsx ppt pptx odt rtf png jpg jpeg gif svg webp bmp tif tiff ico zip gz tar exe dll dmg iso img bin dat db sql mp3 mp4 mov avi wav".split(
    /\s+/,
  ),
);

// undefang — reverse common threat-report DEFANGING so the IOC regexes see real values. Mirrors
// extractor.py:undefang VERBATIM. HIGH-PRECISION: bracketed/parenthesized forms + hxxp only — NEVER
// bare " dot "/" at " (ordinary prose words). Without it DOMAIN_RE never matches worldcup2026-tickets[.]com.
function undefang(text: string): string {
  let t = text ?? "";
  t = t.replace(/hxxp/gi, "http"); // hxxp:// / hxxps:// → http(s)://
  t = t.replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, "."); // [.] (.) {.}
  t = t.replace(/\[\s*dot\s*\]|\(\s*dot\s*\)/gi, "."); // [dot] (dot)
  t = t.replace(/\[\s*at\s*\]|\(\s*at\s*\)/gi, "@"); // [at] (at)
  t = t.replace(/\[\s*:\s*\]/g, ":"); // [:]
  return t;
}

// ---- the scan core (start-offset precedence, D8) ----

interface RawMatch {
  surface: string;
  start: number;
}

function matchesOf(text: string, re: RegExp): RawMatch[] {
  const out: RawMatch[] = [];
  const r = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m: RegExpExecArray | null;
  while ((m = r.exec(text)) !== null) {
    out.push({ surface: m[0], start: m.index });
    if (m.index === r.lastIndex) r.lastIndex++; // zero-width guard
  }
  return out;
}

function emit(
  out: ExtractedEntity[],
  text: string,
  re: RegExp,
  type: string,
  claimed: Set<number>,
  opts: { gate?: string[]; predicate?: (s: string) => boolean; prevalidated?: (s: string, start: number) => boolean } = {},
): void {
  const low = text.toLowerCase();
  for (const { surface, start } of matchesOf(text, re)) {
    if (claimed.has(start)) continue; // a more specific scan already claimed this start (D8)
    // context gate (D9): a keyword must sit within GATE_WINDOW chars of the match
    if (opts.gate) {
      const s = Math.max(0, start - GATE_WINDOW);
      const e = Math.min(low.length, start + surface.length + GATE_WINDOW);
      const win = low.slice(s, e);
      if (!opts.gate.some((g) => win.includes(g))) continue; // rejected gate does NOT claim (no starve)
    }
    if (opts.predicate && !opts.predicate(surface)) continue; // rejected predicate does NOT claim
    const prevalidated = opts.prevalidated ? opts.prevalidated(surface, start) : false;
    const value = surface.trim().toLowerCase();
    if (!isAdmissible(type, value, prevalidated)[0]) continue;
    claimed.add(start);
    out.push({ value, type, start });
  }
}

function domainPredicate(surface: string): boolean {
  const m = /\.([a-zA-Z]{2,24})$/.exec(surface);
  if (!m) return false;
  const tld = m[1].toLowerCase();
  // gate on the authoritative IANA TLD list (flexible: every real scam TLD lands; "introduction" doesn't),
  // minus file-extension lookalikes (.md/.py/.pdf...). Mirrors extractor.py: an empty IANA set (would only
  // happen if the bundle were stripped) degrades to denylist-only rather than dropping every domain.
  return (IANA_TLDS.size === 0 || IANA_TLDS.has(tld)) && !FILE_EXT_DENY.has(tld);
}

function phonePrevalidated(text: string): (surface: string, start: number) => boolean {
  return (_surface, start) => {
    const before = text.slice(Math.max(0, start - 24), start);
    return _PHONE_LABEL_RE.test(before);
  };
}
function notDateShape(surface: string): boolean {
  return !_DATE_SHAPE_RE.test(surface);
}

/**
 * Extract typed entities from document text. Scan ORDER encodes cross-type precedence (the most
 * specific patterns claim their start-offset first; walletconnect is gated BEFORE md5 so a gated
 * 32-hex types as walletconnect_id, else md5).
 */
function scanEntities(text: string): ExtractedEntity[] {
  // Returns EVERY occurrence (with its start offset), NOT yet deduped — inferRelationships needs
  // each occurrence to compute text proximity; extractEntities dedups on top.
  // Mirror extractor.py EXACTLY: decode literal \n/\r/\t escape PAIRS to spaces (JSON-escaped input
  // would otherwise forge a twin across the escape boundary, e.g. "\\nbar.evil" → "nbar.evil"), THEN
  // un-defang, THEN scan. Same two pre-passes, same order, as the Python pipeline.
  const t = undefang((text ?? "").replace(/\\[nrt]/g, " "));
  const out: ExtractedEntity[] = [];
  const claimed = new Set<number>();

  emit(out, t, EMAIL_RE, "email", claimed);
  emit(out, t, TRACKING_TAG_RE, "tracking_tag", claimed);
  emit(out, t, WALLET_RE, "wallet", claimed);
  emit(out, t, TRON_RE, "wallet", claimed);
  emit(out, t, IPV4_RE, "ip", claimed);
  emit(out, t, SHA256_RE, "hash_sha256", claimed);
  emit(out, t, WALLETCONNECT_RE, "walletconnect_id", claimed, { gate: GATE_WALLETCONNECT });
  emit(out, t, SOL_RE, "wallet", claimed, { gate: GATE_SOL });
  emit(out, t, XRP_RE, "wallet", claimed, { gate: GATE_XRP });
  emit(out, t, MD5_RE, "hash_md5", claimed); // after walletconnect (D8)
  emit(out, t, TELEGRAM_RE, "telegram_channel", claimed);
  emit(out, t, HANDLE_RE, "handle", claimed);
  emit(out, t, DOMAIN_RE, "domain", claimed, { predicate: domainPredicate });
  emit(out, t, PHONE_RE, "phone", claimed, { predicate: notDateShape, prevalidated: phonePrevalidated(t) });
  return out;
}

export function extractEntities(text: string): ExtractedEntity[] {
  // de-dup (value,type) — the same value can recur across the document
  const seen = new Set<string>();
  return scanEntities(text).filter((e) => {
    const k = `${e.type} ${e.value}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Proximity co-occurrence — VERBATIM port of extractor.py:infer_relationships. Two entities
 * co-occur ONLY when an occurrence of each sits within PROXIMITY_CHARS of the other in the text
 * (sorted by offset; the inner loop breaks past the window). The original draws a SPARSE, local
 * graph this way; the clone's old all-pairs co_occurs (db.ts) drew a complete graph (the hairball,
 * PRD prd-parity-graph-faithful). Returns unordered, de-duplicated entity-VALUE pairs. Offsets are
 * transient (used here, never stored) — zero-retention preserved; only the sparse pairs land.
 */
export function inferRelationships(text: string): Array<[string, string]> {
  const ents = scanEntities(text)
    .filter((e) => typeof e.start === "number")
    .sort((a, b) => (a.start as number) - (b.start as number));
  const seen = new Set<string>();
  const pairs: Array<[string, string]> = [];
  for (let i = 0; i < ents.length; i++) {
    const a = ents[i];
    for (let j = i + 1; j < ents.length; j++) {
      const b = ents[j];
      if ((b.start as number) - (a.start as number) > PROXIMITY_CHARS) break; // sorted → nothing closer past here
      if (a.value === b.value) continue; // same canonical value → one entity, not a co-occurrence
      const key = [a.value, b.value].sort().join(" ");
      if (seen.has(key)) continue;
      seen.add(key);
      pairs.push([a.value, b.value]);
    }
  }
  return pairs;
}
