import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  suggestNextStep,
  type ConductorState,
} from "../src/lifecycle.js";

// clu-conductor: the chat conductor is a state machine that SUGGESTS the next step; the analyst drives.
// Challenge/Premortem/Reality-check are SUGGESTIONS in the cycle order, NOT hard gates — the brief is never
// blocked (founder: auto-created, no blocking). This is the pure decision function.

const base: ConductorState = {
  scopeSet: false,
  hasIntake: false,
  hasRuns: false,
  hasFindings: false,
  challengeRan: false,
  premortemRan: false,
  realityCheckRan: false,
  hasBrief: false,
};

describe("suggestNextStep — suggest, not auto (clu-conductor)", () => {
  it("a suggestion NEVER auto-runs: it always requires an explicit analyst greenlight", () => {
    // suggestNextStep is pure (no run callback, no side effect). Every run-bearing step is flagged
    // requiresGreenlight so the UI cannot start a spendy run without the analyst.
    const s = suggestNextStep({ ...base, scopeSet: true, hasIntake: true });
    expect(s.requiresGreenlight).toBe(true);
    expect(s.step).toBe("investigate");
  });

  it("walks the cycle: scope → intake → investigate → challenge → premortem → reality_check → deliver → done", () => {
    expect(suggestNextStep({ ...base }).step).toBe("scope");
    expect(suggestNextStep({ ...base, scopeSet: true }).step).toBe("intake");
    expect(suggestNextStep({ ...base, scopeSet: true, hasIntake: true }).step).toBe("investigate");
    const withFindings = { ...base, scopeSet: true, hasIntake: true, hasRuns: true, hasFindings: true };
    expect(suggestNextStep(withFindings).step).toBe("challenge");
    expect(suggestNextStep({ ...withFindings, challengeRan: true }).step).toBe("premortem");
    expect(suggestNextStep({ ...withFindings, challengeRan: true, premortemRan: true }).step).toBe("reality_check");
    expect(suggestNextStep({ ...withFindings, challengeRan: true, premortemRan: true, realityCheckRan: true }).step).toBe("deliver");
    expect(
      suggestNextStep({ ...withFindings, challengeRan: true, premortemRan: true, realityCheckRan: true, hasBrief: true }).step,
    ).toBe("done");
  });

  it("Challenge is SUGGESTED before the deliverable once findings exist (cycle order, not a gate)", () => {
    const s = suggestNextStep({ ...base, scopeSet: true, hasIntake: true, hasRuns: true, hasFindings: true });
    expect(s.step).toBe("challenge");
    expect(s.step).not.toBe("deliver");
  });
});

// clu-conductor: the brief is NOT gated (founder: auto-created, no blocking). This guard asserts NO brief
// writer path is fenced behind an assertCanWriteFindings call — a re-introduced hard gate fails this.
describe("the brief is never hard-gated in app.ts (founder: no blocking)", () => {
  const src = readFileSync(new URL("../src/app.ts", import.meta.url), "utf8");
  it("app.ts holds no assertCanWriteFindings enforcement", () => {
    expect(src.includes("assertCanWriteFindings(")).toBe(false);
  });
});
