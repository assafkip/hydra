// A6 typosquat: lookalike-domain candidate generation, ported from investigations/enrich/typosquat.py
// (which shells dnstwist — a pip dep the browser can't use, so the permutation logic is reimplemented
// here, pure + deterministic). crt.sh confirms certs that already exist; it can NOT generate the
// lookalike phishing domains a brand-impersonation / crypto-fraud operator might register. This does.
//
// T3 -> T1 gate (typosquat.py): a raw candidate is T3 (generated, unconfirmed) — header-only. A
// candidate that RESOLVES (live A record via DoH) is a real hostname (T1) and is the ONLY kind emitted
// as a promotable `domain` entity, so unverified lookalikes never enter the findings file
// (q-investigation evidence-tier rule). Keyless: generation is local; liveness uses the same dns.google
// DoH endpoint as doh.ts (already CORS-open + CSP-allowed), capped to avoid hammering DNS.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const DOH = "https://dns.google/resolve";
const MAX_CHECK = 25; // typosquat.py:_MAX_CHECK — cap liveness checks (generation yields many candidates)

// Common alternate TLDs a squatter swaps onto a brand (dnstwist's tld dictionary, trimmed to the
// high-signal set). The original's full TLD list is large; this covers the squats actually seen.
const SWAP_TLDS = [
  "com", "net", "org", "co", "io", "info", "biz", "online", "site", "app", "xyz", "live",
  "shop", "store", "click", "link", "vip", "cc", "club", "top", "sale", "fund", "finance",
];
// Homoglyph / keyboard-adjacency substitutions (dnstwist homoglyph + replacement fuzzers, ASCII subset).
const HOMOGLYPHS: Record<string, string[]> = {
  a: ["e", "o", "q", "4", "@"], b: ["d", "lb", "h", "8"], c: ["e", "o", "g"], d: ["b", "cl", "o"],
  e: ["a", "c", "3"], g: ["q", "9", "6"], i: ["l", "1", "j", "!"], l: ["i", "1", "I"], m: ["n", "nn", "rn"],
  n: ["m", "r", "h"], o: ["0", "q", "c", "u"], q: ["g", "o"], rn: ["m"], s: ["5", "z", "$"],
  t: ["7", "f"], u: ["v", "o"], v: ["u", "w"], w: ["vv", "v"], z: ["s", "2"], "0": ["o"], "1": ["l", "i"],
};

interface DohResp {
  Status: number;
  Answer?: { type: number; data: string }[];
}

/** (candidate, fuzzer-kind) pairs, dedup'd, excluding the original — the dnstwist fuzzers reimplemented:
 *  omission, insertion (keyboard-adjacent doubling), repetition, transposition, replacement/homoglyph,
 *  hyphenation, subdomain (dot insertion), and tld-swap. Pure + deterministic. */
export function generateTyposquats(domain: string): { candidate: string; kind: string }[] {
  const lower = domain.trim().toLowerCase();
  // bound the input BEFORE generating (codex): a real domain is ≤253 chars with a ≤63-char squattable
  // label; a huge string would drive O(n·homoglyphs) slice/regex work over a giant candidate set.
  if (lower.length > 253 || !/^[a-z0-9.-]+$/.test(lower)) return [];
  const dot = lower.lastIndexOf(".");
  if (dot < 1 || dot > 64) return [];
  const name = lower.slice(0, dot); // the squattable label (left of the final TLD)
  const tld = lower.slice(dot + 1);
  const out = new Map<string, string>(); // candidate -> kind (first kind wins, deterministic)
  const add = (cand: string, kind: string): void => {
    if (cand && cand !== lower && /^[a-z0-9.-]+\.[a-z]{2,}$/.test(cand) && !out.has(cand)) out.set(cand, kind);
  };
  const chars = [...name];

  // omission: drop one character
  for (let i = 0; i < chars.length; i++) add(`${name.slice(0, i)}${name.slice(i + 1)}.${tld}`, "omission");
  // repetition: double one character
  for (let i = 0; i < chars.length; i++) add(`${name.slice(0, i)}${chars[i]}${name.slice(i)}.${tld}`, "repetition");
  // transposition: swap two adjacent characters
  for (let i = 0; i < chars.length - 1; i++) {
    const t = [...chars]; [t[i], t[i + 1]] = [t[i + 1], t[i]];
    add(`${t.join("")}.${tld}`, "transposition");
  }
  // replacement / homoglyph: substitute a char with each of its look/keyboard-alikes
  for (let i = 0; i < chars.length; i++) {
    for (const sub of HOMOGLYPHS[chars[i]] ?? []) add(`${name.slice(0, i)}${sub}${name.slice(i + 1)}.${tld}`, "homoglyph");
  }
  // insertion: insert each homoglyph-source char between adjacent chars (keyboard-adjacency proxy)
  for (let i = 1; i < chars.length; i++) {
    for (const ins of HOMOGLYPHS[chars[i]] ?? []) {
      if (ins.length === 1) add(`${name.slice(0, i)}${ins}${name.slice(i)}.${tld}`, "insertion");
    }
  }
  // hyphenation: insert a hyphen between adjacent chars
  for (let i = 1; i < chars.length; i++) add(`${name.slice(0, i)}-${name.slice(i)}.${tld}`, "hyphenation");
  // subdomain: a dot turns part of the label into a deceptive subdomain (brand.com -> br.and.com)
  for (let i = 2; i < chars.length - 1; i++) add(`${name.slice(0, i)}.${name.slice(i)}.${tld}`, "subdomain");
  // tld-swap: same label, different TLD
  for (const t of SWAP_TLDS) if (t !== tld) add(`${name}.${t}`, "tld-swap");

  return [...out.entries()].map(([candidate, kind]) => ({ candidate, kind }));
}

async function resolvesA(domain: string, opts: OsintOpts): Promise<boolean> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  try {
    const json = await withRetry(
      async () => {
        const res = await fetchImpl(`${DOH}?name=${encodeURIComponent(domain)}&type=A`, {
          headers: { accept: "application/dns-json" },
          signal: opts.signal,
        });
        if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
        return (await res.json()) as DohResp;
      },
      opts.retries ?? 0,
      undefined,
      opts.signal,
    );
    return (json.Answer ?? []).some((a) => a.type === 1); // an A record = live (T1)
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    return false; // a failed lookup is treated as not-live (conservative; stays a T3 lead)
  }
}

/**
 * Generate lookalike candidates for a seed domain and DoH-check the first MAX_CHECK for liveness.
 * Only LIVE candidates (a real resolving hostname, T1) are emitted as `domain` entities — so the gate
 * promotes them; unconfirmed candidates stay in the note as T3 leads, never auto-graphed. The provider
 * tier is T1 because the EMITTED entities are all DNS-confirmed (typosquat.py's promotion rule).
 */
export async function typosquatDomains(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const bare = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  if (!bare || !bare.includes(".")) throw new Error("typosquat: pass a bare domain (e.g. binance.com)");
  const candidates = generateTyposquats(bare);
  const toCheck = candidates.slice(0, MAX_CHECK);
  const live: { candidate: string; kind: string }[] = [];
  const unconfirmed: string[] = [];
  for (const c of toCheck) {
    if (await resolvesA(c.candidate, opts)) live.push(c);
    else unconfirmed.push(c.candidate);
  }
  const entities: OsintEntity[] = live.map((c) => ({
    type: "domain",
    value: c.candidate,
    note: `live lookalike of ${bare} (${c.kind}) — confirmed by DNS A record`,
  }));
  // The unconfirmed candidates ride in a single note entity? No — notes attach to entities. Surface the
  // T3 candidate count in the live entities' provenance; the agent sees the full set via the result's
  // query + the live entities. (We never emit an unconfirmed candidate as a node — typosquat.py rule.)
  return {
    provider: "typosquat",
    query: `${bare} — ${candidates.length} candidates, ${live.length} live of ${toCheck.length} checked${
      unconfirmed.length ? `; unconfirmed (T3, not graphed): ${unconfirmed.slice(0, 40).join(", ")}` : ""
    }`,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
