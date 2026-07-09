// ig-record: structured CSV/XLSX column typing, ported from investigations/ingest/record_ingest.py.
//
// A spreadsheet is not prose. A column of wallets, a column of emails, a column of usernames, a
// column of FULL NAMES — the flat regex-over-CSV-text path misses the ones with no regex signature
// (person, handle), and types the rest with no column context. Here each COLUMN is typed once (by
// value-majority, else by header-name hint), then every cell in a typed column becomes a typed entity.
//
// WHY this exists in the zero-retention web: the client keeps NO raw text (ingestText discards it), so
// the original's "bounded dataset summary" is moot — the ONLY thing that survives is the extracted
// entities, and the flat path silently drops person/handle columns. This restores the typing so a
// 'Full Name' / 'username' column lands real entities. Every emitted value still passes isAdmissible
// (the one admission contract), so junk never leaks.

import { isAdmissible } from "../agent/gate.js";
import type { ExtractedEntity } from "./extract.js";

const SAMPLE_ROWS = 50; // rows sampled to infer each column's type (record_ingest.py:SAMPLE_ROWS)
const MAX_ROWS = 5000; // cap (record_ingest.py:MAX_ROWS) — a 50k-row CSV can't flood the entity set

// Column-name hints (substring → surface type) — used when the values don't self-identify (a 'name'
// column has no regex signature). Verbatim from record_ingest.py:HEADER_HINTS, mapping to the web's
// entity type strings (the flat extractor emits "wallet", not "crypto_wallet", so a wallet found by
// both paths dedups).
const HEADER_HINTS: [string, string][] = [
  ["wallet", "wallet"], ["address", "wallet"],
  ["email", "email"], ["e-mail", "email"],
  ["domain", "domain"], ["website", "domain"], ["site", "domain"],
  ["url", "url"], ["link", "url"],
  ["ipv4", "ip"], ["ip_", "ip"], ["ip address", "ip"],
  ["phone", "phone"], ["mobile", "phone"], ["tel", "phone"],
  ["username", "handle"], ["handle", "handle"], ["screen_name", "handle"],
  ["sha256", "hash_sha256"], ["sha", "hash_sha256"], ["md5", "hash_md5"],
  ["full name", "person"], ["name", "person"],
];

// Value matchers (surface type → anchored predicate). Order = priority on ambiguous cells
// (record_ingest.py:VALUE_MATCHERS). Patterns mirror extractor.py / extract.ts, anchored (fullmatch).
const WALLET_FULL = /^(?:0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{6,87}|BC1[AC-HJ-NP-Z02-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})$/;
// email/url anchored to match extractor.py's word-boundary/excluded-char rules: an email must END in a
// word char (so 'a@b.com.' is NOT a match, matching EMAIL_RE's trailing \b); a url excludes < > " ' ) \ `
// (so 'https://x.com"' / an escaped fragment is rejected, matching URL_RE) — codex review 2026-06-22.
const EMAIL_FULL = /^[\w.+-]+@[\w-]+\.[\w.-]*[A-Za-z0-9_]$/;
const IPV4_FULL = /^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const SHA256_FULL = /^[a-fA-F0-9]{64}$/;
const MD5_FULL = /^[a-fA-F0-9]{32}$/;
const URL_FULL = /^https?:\/\/[^\s<>"'`)\\]+$/i;
const DOMAIN_FULL = /^(?!www\.)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}$/;
const HANDLE_FULL = /^@?[A-Za-z0-9_]{2,32}$/; // a username column: a handle shape, never free text

const VALUE_MATCHERS: [string, RegExp][] = [
  ["wallet", WALLET_FULL],
  ["email", EMAIL_FULL],
  ["ip", IPV4_FULL],
  ["hash_sha256", SHA256_FULL],
  ["hash_md5", MD5_FULL],
  ["url", URL_FULL],
  ["domain", DOMAIN_FULL],
];

// Per-cell shape check, applied to EVERY emitted cell (not just column profiling). The web's
// admission floor is HARD everywhere (parity-and-directives) — unlike record_ingest.py, which
// trusted a typed column wholesale (gate=False), a header-hinted 'wallet'/'username'/'name' column
// must NOT emit a junk cell ('not a wallet', a pasted key, free prose). A type with a value-matcher
// must match it; handle/person/phone get their own shape; everything else passes.
function cellMatchesType(surface: string, value: string): boolean {
  const vm = VALUE_MATCHERS.find(([t]) => t === surface);
  if (vm) return vm[1].test(value);
  if (surface === "handle") return HANDLE_FULL.test(value);
  if (surface === "person") return looksLikeName(value);
  if (surface === "phone") return /\d/.test(value); // header vouches; require a digit (isAdmissible re-checks shape)
  return true;
}

function headerType(name: string): string | null {
  const low = name.toLowerCase();
  for (const [frag, t] of HEADER_HINTS) if (low.includes(frag)) return t;
  return null;
}

function valueType(value: string): string | null {
  const v = value.trim();
  if (!v) return null;
  for (const [t, re] of VALUE_MATCHERS) if (re.test(v)) return t;
  return null;
}

/** Plausible multi-word personal name (record_ingest.py:_looks_like_name): 2–4 alpha words, no digits. */
function looksLikeName(value: string): boolean {
  const parts = value.split(/\s+/).filter(Boolean);
  if (parts.length < 2 || parts.length > 4) return false;
  return parts.every((p) => /^[a-zA-ZÀ-￿]/.test(p)) && !/\d/.test(value);
}

/** col index → surface type. Strong value-majority wins (≥50% of sampled cells type the same),
 *  else the header-name hint (record_ingest.py:_profile_columns). */
function profileColumns(header: string[], rows: string[][]): Map<number, string> {
  const colTypes = new Map<number, string>();
  for (let ci = 0; ci < header.length; ci++) {
    const sampled: string[] = [];
    for (const r of rows.slice(0, SAMPLE_ROWS)) {
      if (ci < r.length && r[ci].trim()) sampled.push(r[ci]);
    }
    const counts = new Map<string, number>();
    for (const val of sampled) {
      const t = valueType(val);
      if (t) counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    if (sampled.length && counts.size) {
      let bestT = "", bestN = 0;
      for (const [t, n] of counts) if (n > bestN) { bestT = t; bestN = n; }
      if (bestN / sampled.length >= 0.5) { colTypes.set(ci, bestT); continue; }
    }
    const ht = headerType(header[ci]);
    if (ht) colTypes.set(ci, ht);
  }
  return colTypes;
}

/**
 * Typed entities from a delimited file's rows (header + data). Mirrors record_ingest.ingest's
 * cell loop: profile columns, then for each typed column emit one entity per distinct cell value,
 * person columns filtered to plausible names. Every value passes isAdmissible (a header-typed phone
 * column vouches for a bare number → prevalidated, like the Python extractor's phone_prevalidated).
 * Returns [] when there is no header or no typed column (the caller falls back to flat extraction).
 */
export function recordEntities(header: string[], rows: string[][]): ExtractedEntity[] {
  if (!header.length || !rows.length) return [];
  const colTypes = profileColumns(header, rows);
  if (!colTypes.size) return [];

  const out: ExtractedEntity[] = [];
  const seen = new Set<string>(); // (col, value-lower) within the dataset (record_ingest.py:seen_in_report)
  for (const row of rows.slice(0, MAX_ROWS)) {
    for (const [ci, surface] of colTypes) {
      if (ci >= row.length) continue;
      const value = row[ci].trim();
      if (!value) continue;
      // HARD per-cell shape check (web admission floor; stricter than record_ingest.py): a junk cell in
      // a typed column never emits, even when the column header says wallet/username/name.
      if (!cellMatchesType(surface, value)) continue;
      const key = `${ci} ${value.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // The web admission floor is value-only and HARD everywhere (founder: hard in CLI AND web). A
      // header-typed phone column does NOT vouch a bare number past it: record_ingest.py stored bare
      // phones with gate=False, but in the web every downstream gate (promotionGate, the entity-DB
      // build) re-checks isAdmissible WITHOUT prevalidation context, so a bare phone can't survive.
      // A formatted phone (+ / separators) lands like any other path; a bare-digit phone is a bare-id.
      // Documented divergence, not a silent strip.
      if (!isAdmissible(surface, value)[0]) continue;
      out.push({ value, type: surface });
    }
  }
  return out;
}

/** Merge structured + flat extraction, de-duped by (type,value) — the dataset's typed columns PLUS
 *  any IOC embedded in a free-text column. Strictly additive: never drops a flat-path entity. */
export function mergeEntities(...lists: ExtractedEntity[][]): ExtractedEntity[] {
  const seen = new Set<string>();
  const out: ExtractedEntity[] = [];
  for (const list of lists) {
    for (const e of list) {
      const k = `${e.type} ${e.value}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(e);
    }
  }
  return out;
}
