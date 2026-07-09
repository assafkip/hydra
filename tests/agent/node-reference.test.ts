import { describe, it, expect } from "vitest";
import { focusedQuestionFor } from "../../src/agent/session.js";

// Node-reference (founder ask 2026-06-24): the graph is a VISUAL on the analyst's screen — Claude can't see
// it. Selecting a node is how the analyst points at what "this" means. focusedQuestionFor folds the selected
// entity into the Q&A prompt so "what is this?" resolves to the node the analyst clicked. The hook existed
// (selectedNodeData + chatDeps.selectedName) but nothing consumed it; this connects the two ends.

describe("focusedQuestionFor: the selected graph node references into the Q&A", () => {
  it("folds the selected entity into the question so 'this' resolves to it", () => {
    const out = focusedQuestionFor("what is this?", "fifa-rewards.com");
    expect(out).toContain("fifa-rewards.com"); // the node the analyst clicked is named
    expect(out).toContain("what is this?"); // the original question is preserved
    expect(out.toLowerCase()).toMatch(/selected|this|refers/); // it tells the model the selection is the referent
  });

  it("is a no-op when no node is selected (null / blank) — pure Q&A unchanged", () => {
    expect(focusedQuestionFor("who runs example.com?", null)).toBe("who runs example.com?");
    expect(focusedQuestionFor("who runs example.com?", undefined)).toBe("who runs example.com?");
    expect(focusedQuestionFor("who runs example.com?", "   ")).toBe("who runs example.com?");
  });

  // N4a (video-review 2026-06-25): a CASE-WIDE question must ignore the selection. The founder had a node
  // selected, asked "what should I investigate next in this case?", and got an answer scoped to that one IP
  // because the old prompt forced every question onto the selection ("…or is otherwise about the selection").
  it("does NOT fold the selection into a case-wide / non-deictic question (the over-scope bug)", () => {
    const caseWide = "what should I investigate next in this case?";
    expect(focusedQuestionFor(caseWide, "104.21.39.186")).toBe(caseWide); // unchanged — selection irrelevant
    const named = "are any of the domains active?";
    expect(focusedQuestionFor(named, "104.21.39.186")).toBe(named); // a question about "the domains" is case-wide
    const find = "what did you find?";
    expect(focusedQuestionFor(find, "104.21.39.186")).toBe(find);
  });

  it("STILL folds the selection into a deictic question (this / it / here / that node)", () => {
    expect(focusedQuestionFor("who's behind it?", "evil.com")).toContain("evil.com");
    expect(focusedQuestionFor("what is this node?", "evil.com")).toContain("evil.com");
    expect(focusedQuestionFor("dig here", "evil.com")).toContain("evil.com");
  });
});
