import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// rsn-case-switch-wipe: a DETERMINISTIC, in-`npm test` guard that the run store is wiped on the
// case-derived-state teardown. The behavioral proof is the live smoke (run-survives-nav.spec.ts), but
// smokes run outside the required-checks gate and can rot silently (the stale-smokes scar). This source
// guard runs every CI test pass, so removing the resetRunStore() wiring breaks the build here. Combined
// with run-store.test.ts (which proves resetRunStore() actually empties the store), the cross-case-leak
// invariant is gated end-to-end: the call exists (here) AND the call wipes (there).

const appTs = readFileSync(new URL("../src/app.ts", import.meta.url), "utf8");

/** The body of a top-level `function <name>(...)` — from its signature to the first column-0 `}`. */
function topLevelFnBody(name: string): string {
  const start = appTs.indexOf(`function ${name}(`);
  expect(start, `function ${name} not found in app.ts`).toBeGreaterThan(-1);
  const end = appTs.indexOf("\n}", start);
  expect(end, `closing brace for ${name} not found`).toBeGreaterThan(start);
  return appTs.slice(start, end);
}

describe("rsn-case-switch-wipe: run store is wiped on case-derived teardown", () => {
  it("clearCaseDerivedState() calls resetRunStore()", () => {
    // clearCaseDerivedState is the single chokepoint applyVault/switchCase/lock/reset all route through.
    expect(topLevelFnBody("clearCaseDerivedState")).toMatch(/resetRunStore\(\)/);
  });

  it("resetRunStore is imported from the run store module", () => {
    expect(appTs).toMatch(/import\s*\{[^}]*\bresetRunStore\b[^}]*\}\s*from\s*"\.\/run-store\.js"/);
  });
});
