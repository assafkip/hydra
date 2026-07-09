// prd-parity-graph-faithful: inferRelationships is the verbatim port of extractor.py:infer_relationships
// (proximity co-occurrence, 200-char window). These cases mirror the original's behavior: only
// within-window pairs co-occur, the window boundary cuts, and the same canonical value never pairs
// with itself. This is the fix for the all-pairs hairball (the clone used to pair EVERY entity).
import { describe, it, expect } from "vitest";
import { inferRelationships, extractEntities } from "../../src/ingest/extract.js";

function pairSet(text: string): Set<string> {
  return new Set(inferRelationships(text).map(([a, b]) => [a, b].sort().join("|")));
}

describe("inferRelationships — proximity co-occurrence (extractor.py parity)", () => {
  it("pairs two entities within 200 chars", () => {
    const text = "Contact a-evil.com and pay-evil.com about the refund.";
    const pairs = pairSet(text);
    expect(pairs.has("a-evil.com|pay-evil.com")).toBe(true);
  });

  it("does NOT pair entities farther apart than 200 chars", () => {
    const filler = "x".repeat(260);
    const text = `first-evil.com ${filler} far-evil.com`;
    const pairs = pairSet(text);
    expect(pairs.has("far-evil.com|first-evil.com")).toBe(false);
  });

  it("is NOT a complete graph: a 3-entity chain with gaps yields fewer than C(3,2) pairs", () => {
    const gap = "y".repeat(260);
    // a near b, b far from c → {a,b} only (not {a,c} or {b,c}). All-pairs would give 3.
    const text = `aa-evil.com bb-evil.com ${gap} cc-evil.com`;
    const pairs = inferRelationships(text);
    const keys = new Set(pairs.map(([a, b]) => [a, b].sort().join("|")));
    expect(keys.has("aa-evil.com|bb-evil.com")).toBe(true);
    expect(keys.has("aa-evil.com|cc-evil.com")).toBe(false);
    expect(keys.has("bb-evil.com|cc-evil.com")).toBe(false);
    expect(pairs.length).toBeLessThan(3); // sparse, not the complete graph
  });

  it("never pairs an entity with itself even when it recurs nearby", () => {
    const text = "dup-evil.com then again dup-evil.com close by.";
    const pairs = inferRelationships(text);
    expect(pairs.every(([a, b]) => a !== b)).toBe(true);
  });

  it("de-duplicates pairs (a value pair appears at most once)", () => {
    const text = "p-evil.com q-evil.com p-evil.com q-evil.com all close together here.";
    const pairs = inferRelationships(text);
    const keys = pairs.map(([a, b]) => [a, b].sort().join("|"));
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("returns entity values that are real extracted entities", () => {
    const text = "alpha-evil.com beta-evil.com nearby.";
    const ents = new Set(extractEntities(text).map((e) => e.value));
    for (const [a, b] of inferRelationships(text)) {
      expect(ents.has(a)).toBe(true);
      expect(ents.has(b)).toBe(true);
    }
  });
});
