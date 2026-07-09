// td-detect: DETERMINISTIC investigation-type detection — a verbatim port of
// investigations/intake/types.py (the keyword + entity-histogram signal scorer). PURE: no DOM,
// clock, randomness, LLM, or fetch. The server consults an LLM only on a thin/tied signal; the
// client ships the deterministic winner / 'general' (the use_llm=False branch) — an on-demand LLM
// tiebreak is a later opt-in. Nothing is fabricated: the type is a mechanical score over the run's
// already-gated entities + objective.
//
// Entity weights are keyed to the client's CANONICAL types via the SHARED canonType (codex D4 — no
// second alias table), with the hash aliases MERGED to one 'hash' weight = max(hash_sha256:3,
// hash_md5:2) = 3 (codex D3/D5). Ties resolve by TAXONOMY_ORDER (codex D2), mirroring Python's
// stable sort over the fixed taxonomy insertion order.

import { canonType } from "../graph/model.js";

interface TypeSignal {
  keywords: Record<string, number>;
  entities: Record<string, number>;
}

/** The fixed taxonomy insertion order — the deterministic tie-breaker (codex D2). */
export const TAXONOMY_ORDER = [
  "crypto-fraud", "disinfo", "hacktivist", "financial-fraud", "intrusion-apt", "person-of-interest",
] as const;

// VERBATIM keyword weights from types.py; entity weights keyed to canonical types (D3/D4/D5).
export const TAXONOMY: Record<string, TypeSignal> = {
  "crypto-fraud": {
    keywords: { wallet: 3, token: 2, rug: 3, rugpull: 3, drainer: 3, drain: 2, blockchain: 2,
      ethereum: 2, solana: 2, crypto: 2, defi: 2, airdrop: 2, metamask: 3, walletconnect: 3, mint: 1,
      usdt: 2, binance: 1, etherscan: 2, "smart contract": 2, giveaway: 2, presale: 2, doubler: 3,
      "advance-fee": 2, "seed phrase": 3, tron: 2, xrp: 1, phantom: 2, tornado: 2, mixer: 2,
      streamjack: 3, hijacked: 1, stealer: 2, deepfake: 2, googletagmanager: 2, gtag: 2 },
    entities: { wallet: 6, tracking_tag: 5, walletconnect_id: 6, tech_stack: 2, domain: 1 },
  },
  "disinfo": {
    keywords: { disinformation: 3, propaganda: 3, narrative: 2, "influence operation": 3, amplif: 2,
      sockpuppet: 3, troll: 2, "coordinated inauthentic": 3, "bot network": 3, "fake news": 2,
      astroturf: 3, persona: 1 },
    entities: { handle: 2, url: 1 },
  },
  "hacktivist": {
    keywords: { deface: 3, ddos: 3, hacktivist: 3, opisrael: 2, anonymous: 1,
      "claim of responsibility": 2, crew: 2, breach: 1, leak: 1, "telegram channel": 2,
      defacement: 3, "cyber army": 2 },
    entities: { telegram_channel: 4, handle: 2 },
  },
  "financial-fraud": {
    keywords: { "money launder": 3, "shell company": 3, "wire transfer": 2, ponzi: 3,
      "pig butchering": 3, "romance scam": 3, invoice: 1, "bank account": 2, fraud: 2, mule: 2,
      kyc: 1, remittance: 2 },
    entities: { email: 1, phone: 2 },
  },
  "intrusion-apt": {
    keywords: { malware: 3, c2: 3, "command and control": 3, payload: 2, exploit: 2, cve: 2,
      backdoor: 3, "threat actor": 2, implant: 3, ttp: 2, phishing: 2, ransomware: 3, apt: 3 },
    // hash_sha256:3 + hash_md5:2 -> canonType folds both to 'hash' -> merged weight max(3,2)=3 (D3).
    entities: { ip: 3, hash: 3, domain: 2 },
  },
  "person-of-interest": {
    keywords: { "person of interest": 3, "background check": 2, dossier: 2, "skip trace": 3, alias: 1,
      "date of birth": 2, residence: 1, employer: 1, "next of kin": 2, locate: 1, subject: 1 },
    entities: { person: 3, phone: 2, email: 1 },
  },
};

export const FLOOR = 4.0; // below -> deterministic signal too thin -> 'general'

export interface DetectResult {
  type: string;
  confidence: number;
  scores: Record<string, number>;
}

// Non-overlapping substring count (Python str.count semantics).
function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let n = 0;
  let i = 0;
  while ((i = haystack.indexOf(needle, i)) !== -1) {
    n++;
    i += needle.length;
  }
  return n;
}

const round2 = (x: number): number => Math.round(x * 100) / 100;

/** Deterministic per-type score: per-keyword hits capped at 4·weight + per-entity-bucket histogram
 *  capped at 20·weight (verbatim types.py caps). */
export function scoreSignals(text: string, histogram: Record<string, number>): Record<string, number> {
  const low = (text || "").toLowerCase();
  const scores: Record<string, number> = {};
  for (const tname of TAXONOMY_ORDER) {
    const sig = TAXONOMY[tname];
    let s = 0;
    for (const [kw, w] of Object.entries(sig.keywords)) {
      const hits = countOccurrences(low, kw);
      if (hits) s += w * Math.min(hits, 4); // per-keyword cap
    }
    for (const [etype, w] of Object.entries(sig.entities)) {
      s += w * Math.min(histogram[etype] ?? 0, 20); // per-entity-bucket cap
    }
    scores[tname] = round2(s);
  }
  return scores;
}

/**
 * Detect a run's investigation type from its objective + gated entities. The signal text is the
 * objective + the entity values; the histogram counts canonType-folded entity types. Ranks by
 * (score desc, TAXONOMY_ORDER asc — stable ties, D2). Thin (top < FLOOR) -> 'general'; otherwise the
 * deterministic winner (the types.py use_llm=False branch). confidence = min(0.95, max(0.2,
 * topScore/total)).
 */
export function detectRunType(objective: string, entities: { value: string; type: string }[]): DetectResult {
  const list = Array.isArray(entities) ? entities : [];
  const text = [objective ?? "", ...list.map((e) => e?.value ?? "")].join(" ");
  const histogram: Record<string, number> = {};
  for (const e of list) {
    const t = canonType(e?.type);
    histogram[t] = (histogram[t] ?? 0) + 1;
  }
  const scores = scoreSignals(text, histogram);
  const ranked = [...TAXONOMY_ORDER].sort(
    (a, b) => scores[b] - scores[a] || TAXONOMY_ORDER.indexOf(a) - TAXONOMY_ORDER.indexOf(b),
  );
  const top = ranked[0];
  const topScore = scores[top];
  const total = Object.values(scores).reduce((a, b) => a + b, 0) || 1;
  const confidence = round2(Math.min(0.95, Math.max(0.2, topScore / total)));
  const type = topScore < FLOOR ? "general" : top;
  return { type, confidence, scores };
}

/** Whether a detected type is a SPECIFIC (non-'general') investigation type (codex D1). */
export function isSpecificType(type: string): boolean {
  return (TAXONOMY_ORDER as readonly string[]).includes(type);
}
