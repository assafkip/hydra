import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// Pairs with the post-audit `process-stop-and-real-smoke` issue (prd-kipi-web-post-audit-fixes-2026-06-20).
// Deterministic guards so the two fixes can't silently regress: the Process Stop button stays wired to the
// abort path, and the parity-shots smoke keeps REAL assertions (no swallowed waits — the theater-test scar).
// Registered as a permanent prd-os gate (bypass_check). Read-only: scans committed source.

describe("post-audit: process stop button is wired", () => {
  const pages = readFileSync("src/pages.ts", "utf8");

  it("renderProcessPanel surfaces a Stop control", () => {
    expect(pages).toContain("proc-stop-btn");
  });

  it("the Stop control consumes the wired abort dep (d.abortProcess)", () => {
    expect(pages).toMatch(/d\.abortProcess\(\)/);
  });
});

describe("post-audit: parity-shots smoke is not theater", () => {
  const spec = readFileSync("tests/smoke/parity-shots.spec.ts", "utf8");

  it("has zero swallowed waits (.catch(() => {}) in any spacing)", () => {
    expect(spec.includes(".catch(() => {})")).toBe(false);
    expect(/\.catch\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/.test(spec)).toBe(false);
  });

  it("has at least one real visibility assertion", () => {
    expect(spec.includes("expect(")).toBe(true);
    expect(spec.includes(".toBeVisible(")).toBe(true);
  });
});
