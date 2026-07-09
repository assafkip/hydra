import { describe, it, expect } from "vitest";
import { intakeCompleteness, renderCompleteness } from "../../src/chat/completeness.js";
import type { ExtractedEntity } from "../../src/ingest/extract.js";

// clu-chat-intake: the post-intake completeness check must be a structured, honest read — entity counts,
// the T1/T2/T3 mix, and explicit gaps. Fresh document intake is all T3 (single-source, uncorroborated).

const ents: ExtractedEntity[] = [
  { value: "acme.io", type: "domain" },
  { value: "evil.test", type: "domain" },
  { value: "1.2.3.4", type: "ip" },
  { value: "0x" + "a".repeat(40), type: "wallet" },
];

describe("intakeCompleteness (clu-chat-intake)", () => {
  it("returns the structured shape: counts, by-type tally, tier mix, non-empty gaps", () => {
    const r = intakeCompleteness(ents);
    expect(r.totalEntities).toBe(4);
    // byType sums to total
    expect(Object.values(r.byType).reduce((a, b) => a + b, 0)).toBe(r.totalEntities);
    expect(r.byType.domain).toBe(2);
    expect(r.byType.ip).toBe(1);
    expect(r.byType.wallet).toBe(1);
    // tier mix sums to total; fresh intake is all T3
    expect(r.tierMix.T1 + r.tierMix.T2 + r.tierMix.T3).toBe(r.totalEntities);
    expect(r.tierMix.T3).toBe(4);
    expect(r.tierMix.T1).toBe(0);
    expect(r.tierMix.T2).toBe(0);
    // explicit gaps, always present
    expect(Array.isArray(r.gaps)).toBe(true);
    expect(r.gaps.length).toBeGreaterThan(0);
    expect(r.gaps.join(" ")).toMatch(/T3/);
  });

  it("an empty intake yields a zero report with a guidance gap (not an error)", () => {
    const r = intakeCompleteness([]);
    expect(r.totalEntities).toBe(0);
    expect(r.tierMix).toEqual({ T1: 0, T2: 0, T3: 0 });
    expect(r.gaps.length).toBeGreaterThan(0);
  });

  it("renderCompleteness names counts + tiers but NEVER the entity values (no injection surface)", () => {
    const md = renderCompleteness(intakeCompleteness(ents));
    expect(md).toMatch(/4 entities/);
    expect(md).toMatch(/T1 0 . T2 0 . T3 4/);
    expect(md).toMatch(/2 domain/);
    // entity values must not appear — only types + counts
    expect(md).not.toContain("acme.io");
    expect(md).not.toContain("1.2.3.4");
    expect(md).not.toContain("0xaaaa");
  });
});
