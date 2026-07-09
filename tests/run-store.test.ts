import { describe, it, expect, beforeEach } from "vitest";
import {
  getRunStore,
  isRunActive,
  beginRun,
  recordRunStep,
  recordRunFindings,
  setRunStatus,
  resetRunStore,
  formatRunProgress,
  formatRunDone,
  type RunLead,
} from "../src/run-store.js";
import type { Step } from "../src/agent/loop.js";
import type { Finding } from "../src/agent/gate.js";

// rsn-run-store (prd-run-survives-navigation): the store is the run's home OUTSIDE the dock DOM. This
// proves the run-lifecycle writes accumulate in it across a simulated run — the foundation the reattach
// (issue 3) and the case-switch wipe (issue 2) build on. It is a PURE, DOM-free module on purpose (the
// codebase has no jsdom and app.ts is not import-safe under node), so this is a real executable test.

function reasoning(text: string): Step {
  return { kind: "reasoning", text };
}
function toolStep(tool: string, result: string): Step {
  return { kind: "tool", tool, result };
}
function finding(entity: string, type: string): Finding {
  return { entity, entity_type: type };
}
function lead(entity: string, reason: string): RunLead {
  return { finding: finding(entity, "domain"), verdict: { promote: false, grade: "C", reason } };
}

describe("run-store", () => {
  beforeEach(() => resetRunStore()); // the module is a singleton — isolate every test

  it("starts idle and empty", () => {
    const s = getRunStore();
    expect(s.status).toBe("idle");
    expect(s.objective).toBe("");
    expect(s.steps).toEqual([]);
    expect(s.findings).toEqual([]);
    expect(s.leads).toEqual([]);
    expect(isRunActive()).toBe(false);
  });

  it("accumulates steps and then findings across a simulated run", () => {
    beginRun("investigate evil.com");
    expect(getRunStore().status).toBe("running");
    expect(isRunActive()).toBe(true);
    expect(getRunStore().objective).toBe("investigate evil.com");

    recordRunStep(reasoning("planning the dig"));
    recordRunStep(toolStep("dns_lookup", "1.2.3.4"));
    recordRunStep(toolStep("rdap", "registrar X"));

    // the trail accumulates IN ORDER, independent of any DOM
    const steps = getRunStore().steps;
    expect(steps).toHaveLength(3);
    expect(steps[0]).toEqual(reasoning("planning the dig"));
    expect(steps[1].tool).toBe("dns_lookup");
    expect(steps[2].tool).toBe("rdap");

    // findings/leads land at finalize
    recordRunFindings([finding("1.2.3.4", "ip"), finding("evil.com", "domain")], [lead("maybe.com", "single source")]);
    setRunStatus("done");

    const s = getRunStore();
    expect(s.status).toBe("done");
    expect(isRunActive()).toBe(false);
    expect(s.findings.map((f) => f.entity)).toEqual(["1.2.3.4", "evil.com"]);
    expect(s.leads).toHaveLength(1);
    expect(s.leads[0].finding.entity).toBe("maybe.com");
    expect(s.steps).toHaveLength(3); // steps survive finalize (the trail is not cleared)
  });

  it("beginRun resets the prior run (run-supersede): a new run starts from empty", () => {
    beginRun("first");
    recordRunStep(reasoning("a"));
    recordRunFindings([finding("x", "domain")], []);
    setRunStatus("done");

    beginRun("second"); // a superseding run
    const s = getRunStore();
    expect(s.objective).toBe("second");
    expect(s.status).toBe("running");
    expect(s.steps).toEqual([]); // the prior run's trail/findings are gone
    expect(s.findings).toEqual([]);
  });

  it("a run that never finalizes can be marked aborted", () => {
    beginRun("interrupted");
    recordRunStep(reasoning("got partway"));
    setRunStatus("aborted");
    expect(getRunStore().status).toBe("aborted");
    expect(isRunActive()).toBe(false);
    expect(getRunStore().steps).toHaveLength(1); // the partial trail is retained
  });

  // G1 (video-review 2026-06-25): the run-progress ENVELOPE strings that drive the live chip label + the
  // terminal flash — the founder could not tell "did it start? where is it? did it end?".
  describe("run-progress envelope (G1)", () => {
    it("formatRunProgress shows 'starting…' before the first step lands (answers 'did it start?')", () => {
      expect(formatRunProgress("the whole case", 0, 0)).toBe("Investigating the whole case · starting…");
    });
    it("formatRunProgress shows live step count + mm:ss elapsed (answers 'where is it?')", () => {
      expect(formatRunProgress("fifa-fr.com", 1, 9_000)).toBe("Investigating fifa-fr.com · 1 step · 0:09");
      expect(formatRunProgress("fifa-fr.com", 14, 94_000)).toBe("Investigating fifa-fr.com · 14 steps · 1:34");
    });
    it("formatRunProgress falls back to 'the case' when the objective is blank", () => {
      expect(formatRunProgress("", 3, 5_000)).toBe("Investigating the case · 3 steps · 0:05");
    });
    it("formatRunDone reads a clean finish, dropping the redundant end_turn reason", () => {
      expect(formatRunDone("done", 17, 8, "end_turn")).toBe("✓ Done — 17 promoted, 8 leads");
      expect(formatRunDone("done", 1, 1, "budget")).toBe("✓ Done — 1 promoted, 1 lead (budget)");
    });
    it("formatRunDone reads a stop plainly (answers 'did it end?')", () => {
      expect(formatRunDone("aborted", 3, 2, "aborted")).toBe("■ Run stopped");
    });
  });

  it("resetRunStore wipes everything back to idle (the case-switch confidentiality invariant)", () => {
    beginRun("case A run");
    recordRunStep(reasoning("dug something"));
    recordRunFindings([finding("secret.com", "domain")], []);
    setRunStatus("running");

    resetRunStore();

    const s = getRunStore();
    expect(s.status).toBe("idle");
    expect(s.objective).toBe("");
    expect(s.steps).toEqual([]);
    expect(s.findings).toEqual([]); // case A's findings can never replay into case B
    expect(s.leads).toEqual([]);
  });
});
