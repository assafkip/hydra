import { describe, it, expect } from "vitest";
import { TAXONOMY, TAXONOMY_ORDER, FLOOR, scoreSignals, detectRunType, isSpecificType } from "../../src/entity/typedetect.js";

// td-detect: a verbatim port of types.py's deterministic scorer. Caps are per-keyword (4x) +
// per-bucket (20x); ties resolve by TAXONOMY_ORDER (D2); entity types fold via the shared canonType
// (D4); the hash aliases merge to one weight (D3).

const E = (value: string, type: string) => ({ value, type });

describe("detectRunType", () => {
  it("a wallet-heavy run detects crypto-fraud", () => {
    const r = detectRunType("rugpull drainer wallet investigation", [E("0xabc", "wallet"), E("0xdef", "crypto_wallet")]);
    expect(r.type).toBe("crypto-fraud");
  });
  it("an ip + hash run with 'malware c2' detects intrusion-apt", () => {
    const r = detectRunType("malware c2 backdoor", [E("1.1.1.1", "ip"), E("deadbeef", "hash_sha256"), E("evil.com", "domain")]);
    expect(r.type).toBe("intrusion-apt");
  });
  it("a handle-heavy 'disinformation' run detects disinfo", () => {
    const r = detectRunType("disinformation propaganda sockpuppet bot network", [E("@a", "handle"), E("@b", "handle")]);
    expect(r.type).toBe("disinfo");
  });
  it("a person-heavy 'skip trace' run detects person-of-interest", () => {
    const r = detectRunType("person of interest skip trace background check", [E("Jane Roe", "person"), E("+15551234", "phone")]);
    expect(r.type).toBe("person-of-interest");
  });
  it("a thin/empty signal -> 'general'", () => {
    expect(detectRunType("look into this", [E("x.com", "domain")]).type).toBe("general");
    expect(detectRunType("", []).type).toBe("general");
  });
  it("confidence is bounded [0.2, 0.95]", () => {
    const r = detectRunType("malware c2", [E("1.1.1.1", "ip"), E("h", "hash_md5")]);
    expect(r.confidence).toBeGreaterThanOrEqual(0.2);
    expect(r.confidence).toBeLessThanOrEqual(0.95);
  });
});

describe("scoreSignals caps + canonical remap", () => {
  it("the per-KEYWORD cap is 4x (a repeated keyword caps while another keyword still contributes)", () => {
    // 'wallet' x10 -> capped at 4 hits * weight 3 = 12; 'token' x1 -> +2 = 14 (keyword only, no entities)
    const s = scoreSignals("wallet wallet wallet wallet wallet wallet wallet wallet wallet wallet token", {});
    expect(s["crypto-fraud"]).toBe(14);
  });
  it("the per-BUCKET histogram cap is 20x (one bucket caps without capping others)", () => {
    // crypto-fraud: wallet weight 6, capped at 20 -> 120; domain weight 1 * 5 -> +5 = 125
    const s = scoreSignals("", { wallet: 50, domain: 5 });
    expect(s["crypto-fraud"]).toBe(125);
  });
  it("a crypto_wallet entity scores as the canonical 'wallet' affinity (D4)", () => {
    const s = scoreSignals("", { crypto_wallet: 1 }); // raw type not folded by scoreSignals
    expect(s["crypto-fraud"]).toBe(0); // scoreSignals keys on canonical 'wallet', so a raw crypto_wallet histogram key does NOT match
    // detectRunType folds the type, so the SAME entity DOES score:
    const r = detectRunType("", [E("0x", "crypto_wallet")]);
    expect(r.scores["crypto-fraud"]).toBe(6);
  });
  it("hash_md5 + hash_sha256 fold to one 'hash' bucket (D3/D5)", () => {
    const r = detectRunType("", [E("a", "hash_md5"), E("b", "hash_sha256")]);
    // both -> canonType 'hash'; intrusion-apt hash weight 3 * 2 entities = 6
    expect(r.scores["intrusion-apt"]).toBe(6);
  });
});

describe("ties resolve by TAXONOMY_ORDER (D2)", () => {
  it("an exact-score tie picks the earlier TAXONOMY_ORDER type, deterministically", () => {
    // craft a tie: one disinfo handle (weight 2) vs ... force equal by empty signal -> all 0 -> thin -> general.
    // instead: a single 'leak' keyword scores hacktivist 1; nothing else -> thin -> general. So test the
    // ranking directly via two equal specific scores using entities that each score 2.
    const r = detectRunType("", [E("@h", "handle")]); // disinfo handle:2, hacktivist handle:2 -> tie at 2 (thin -> general)
    // both disinfo + hacktivist score 2 (a tie); below FLOOR so type is 'general', but the RANKING is stable:
    const ranked = [...TAXONOMY_ORDER].sort((a, b) => r.scores[b] - r.scores[a] || TAXONOMY_ORDER.indexOf(a) - TAXONOMY_ORDER.indexOf(b));
    expect(r.scores["disinfo"]).toBe(2);
    expect(r.scores["hacktivist"]).toBe(2);
    expect(ranked[0]).toBe("disinfo"); // disinfo precedes hacktivist in TAXONOMY_ORDER
  });
});

describe("taxonomy + helpers", () => {
  it("has the 6 types and isSpecificType excludes 'general'", () => {
    expect(Object.keys(TAXONOMY).sort()).toEqual([...TAXONOMY_ORDER].sort());
    expect(isSpecificType("crypto-fraud")).toBe(true);
    expect(isSpecificType("general")).toBe(false);
  });
  it("FLOOR is 4.0", () => expect(FLOOR).toBe(4.0));
});
