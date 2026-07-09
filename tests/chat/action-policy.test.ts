import { describe, expect, it } from "vitest";
import { classifyChatAction } from "../../src/chat/action-policy";

describe("chat action policy", () => {
  it("keeps ordinary questions in the answer lane", () => {
    expect(classifyChatAction("who runs example.com?")).toMatchObject({
      kind: "answer",
      commit: "none",
    });
  });

  it("keeps live investigation requests in the investigate lane", () => {
    expect(classifyChatAction("investigate example.com")).toMatchObject({
      kind: "investigate",
      commit: "run",
    });
  });

  it("blocks destructive durable-state requests from chat text alone", () => {
    expect(classifyChatAction("delete all findings")).toMatchObject({
      kind: "blocked",
      commit: "none",
      risk: "destructive",
    });
    expect(classifyChatAction("wipe this case")).toMatchObject({
      kind: "blocked",
      commit: "none",
      risk: "destructive",
    });
  });

  it("turns findings and edge mutation asks into propose-only actions", () => {
    expect(classifyChatAction("add this as a finding")).toMatchObject({
      kind: "propose",
      commit: "approval_required",
      target: "finding",
    });
    expect(classifyChatAction("connect alpha.example to 1.2.3.4")).toMatchObject({
      kind: "propose",
      commit: "approval_required",
      target: "relationship",
    });
  });

  it("turns reversible graph node removal into an approval-required proposal", () => {
    expect(classifyChatAction("remove 93.184.216.34")).toMatchObject({
      kind: "propose",
      commit: "approval_required",
      target: "graph",
      targetValue: "93.184.216.34",
    });
  });

  it("refuses raw graph dumps and co-occurrence-as-truth edges with verify-first guidance", () => {
    expect(classifyChatAction("add every uploaded entity to the graph")).toMatchObject({
      kind: "blocked",
      risk: "raw_upload_dump",
    });
    expect(classifyChatAction("create edges for every co-occurrence")).toMatchObject({
      kind: "propose",
      target: "relationship",
      reason: expect.stringContaining("verify"),
    });
  });

  it("classifies unconfigured-provider asks as needs_capability", () => {
    expect(classifyChatAction("use VirusTotal on this domain")).toMatchObject({
      kind: "needs_capability",
      capability: "virustotal",
      commit: "none",
    });
  });
});
