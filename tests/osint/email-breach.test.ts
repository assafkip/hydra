import { describe, it, expect } from "vitest";
import { xposedOrNotEmail } from "../../src/osint/xposedornot.js";
import { hibpBreachCatalog } from "../../src/osint/hibp-catalog.js";
import { disposableEmail } from "../../src/osint/disposable-email.js";
import type { FetchLike } from "../../src/osint/types.js";

// Shapes captured live 2026-07-09 from each provider's real response.
function fetchJson(payload: unknown, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, json: async () => payload })) as unknown as FetchLike;
}
// Route by URL host so disposableEmail's two concurrent probes can be answered independently.
function fetchByHost(map: Record<string, { payload: unknown; status?: number }>): FetchLike {
  return (async (url: string) => {
    const host = new URL(url).host;
    const hit = map[host];
    if (!hit) throw new Error(`no fake for ${host}`);
    return { ok: (hit.status ?? 200) < 400, status: hit.status ?? 200, json: async () => hit.payload };
  }) as unknown as FetchLike;
}

describe("xposedOrNotEmail (finding-3: a breach match is a T3 LEAD, never proof)", () => {
  it("lists breach names as a lead summary with the not-proof caveat, NO typed entity", async () => {
    const impl = fetchJson({ breaches: [["Adobe", "Dropbox", "LinkedIn"]] });
    const r = await xposedOrNotEmail("user@example.com", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("xposedornot");
    expect(r.tier).toBe("T3");
    expect(r.entities).toHaveLength(0); // never a graph pivot
    expect(r.summary).toContain("NOT proof");
    expect(r.summary).toContain("Adobe, Dropbox, LinkedIn");
  });
  it("treats a 404 as a clean address (no breaches), not an error", async () => {
    const r = await xposedOrNotEmail("clean@example.com", { fetchImpl: fetchJson({}, 404), retries: 0 });
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("no breach-DB records");
  });
  it("caps a hostile flood of breach names AND each name's length", async () => {
    const names = Array.from({ length: 500 }, (_, i) => `Breach${i}`.padEnd(5000, "x"));
    const r = await xposedOrNotEmail("user@example.com", { fetchImpl: fetchJson({ breaches: [names] }), retries: 0 });
    const listed = r.summary!.split(": ").pop()!.split(", ");
    expect(listed.length).toBeLessThanOrEqual(100); // count cap
    expect(Math.max(...listed.map((s) => s.length))).toBeLessThanOrEqual(90); // per-string length cap (80 + ellipsis)
  });
  it("throws on a non-'Not found' error body — a failure never reads as clean (finding-1)", async () => {
    await expect(xposedOrNotEmail("user@example.com", { fetchImpl: fetchJson({ Error: "rate limited" }), retries: 0 })).rejects.toThrow(/XposedOrNot error/);
  });
  it("treats {Error:'Not found'} as a clean address, not a failure", async () => {
    const r = await xposedOrNotEmail("clean@example.com", { fetchImpl: fetchJson({ Error: "Not found" }), retries: 0 });
    expect(r.summary).toContain("no breach-DB records");
  });
});

describe("hibpBreachCatalog (finding-3: domain site-context ONLY, never per-email)", () => {
  it("returns site-breach context for a domain (T3, no typed entity)", async () => {
    const impl = fetchJson([{ Name: "Adobe", Title: "Adobe", BreachDate: "2013-10-04", Domain: "adobe.com" }]);
    const r = await hibpBreachCatalog("adobe.com", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("hibp-catalog");
    expect(r.tier).toBe("T3");
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("site-breach CONTEXT");
    expect(r.summary).toContain("NOT proof any specific address was exposed");
    expect(r.summary).toContain("Adobe (2013-10-04)");
  });
  it("treats a 404 as no breaches recorded for the domain", async () => {
    const r = await hibpBreachCatalog("clean.test", { fetchImpl: fetchJson([], 404), retries: 0 });
    expect(r.summary).toContain("no breaches recorded");
  });
  it("throws on a non-array shape and surfaces a 429 rate-limit", async () => {
    await expect(hibpBreachCatalog("x.com", { fetchImpl: fetchJson({ nope: 1 }), retries: 0 })).rejects.toThrow(/unexpected response shape/);
    await expect(hibpBreachCatalog("x.com", { fetchImpl: fetchJson([], 429), retries: 0 })).rejects.toThrow(/rate-limited/);
  });
  it("length-caps giant provider-controlled titles/dates and drops non-string fields (finding-3)", async () => {
    const impl = fetchJson([{ Title: "A".repeat(5000), BreachDate: "2020-01-01" }, { Name: 12345, Title: null }]);
    const r = await hibpBreachCatalog("x.com", { fetchImpl: impl, retries: 0 });
    expect(r.summary!.length).toBeLessThan(300); // the giant title is truncated; the non-string-name row is dropped
  });
});

describe("disposableEmail (debounce + Kickbox cross-check)", () => {
  it("reports agreement when both providers agree (T3, no entity)", async () => {
    const impl = fetchByHost({
      "disposable.debounce.io": { payload: { disposable: "true" } }, // debounce = string
      "open.kickbox.com": { payload: { disposable: true } }, // kickbox = boolean
    });
    const r = await disposableEmail("x@mailinator.com", { fetchImpl: impl, retries: 0 });
    expect(r.tier).toBe("T3");
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("both agree: disposable");
  });
  it("flags a DISAGREEMENT as inconclusive", async () => {
    const impl = fetchByHost({
      "disposable.debounce.io": { payload: { disposable: "true" } },
      "open.kickbox.com": { payload: { disposable: false } },
    });
    const r = await disposableEmail("x@example.com", { fetchImpl: impl, retries: 0 });
    expect(r.summary).toContain("DISAGREE");
  });
  it("still answers on a single source when the other provider fails", async () => {
    const impl = fetchByHost({
      "disposable.debounce.io": { payload: { disposable: "false" } },
      "open.kickbox.com": { payload: {}, status: 500 },
    });
    const r = await disposableEmail("x@example.com", { fetchImpl: impl, retries: 0 });
    expect(r.summary).toContain("single source only");
  });
  it("throws when BOTH providers fail (never a fake verdict)", async () => {
    const impl = fetchByHost({
      "disposable.debounce.io": { payload: {}, status: 500 },
      "open.kickbox.com": { payload: {}, status: 500 },
    });
    await expect(disposableEmail("x@example.com", { fetchImpl: impl, retries: 0 })).rejects.toThrow(/both providers failed/);
  });
});
