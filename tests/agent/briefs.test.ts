import { describe, it, expect } from "vitest";
import {
  filterReportEntities,
  relatedness,
  groupReports,
  verdictForGroup,
  groupContext,
  formatGroupBrief,
  formatStandalone,
  type ReportInput,
} from "../../src/agent/briefs.js";
import { canonKey } from "../../src/entity/db.js";

// sf-briefs: the engine is the faithful port of investigations/briefs.py. These tests pin the verdict
// thresholds, the COMPOUND union gate, Jaccard-only grouping when no analyze clusters exist, the entity
// filter, and the markdown structure the /briefs viewer parses.

function report(objective: string, entityKeys: string[], clusterNames: string[] = []): ReportInput {
  return { meta: { objective, title: objective }, entityKeys: new Set(entityKeys), clusterNames: new Set(clusterNames) };
}

describe("filterReportEntities (the briefs.py 3-way filter)", () => {
  it("drops incidental names, role:noise, and person_candidate-with-no-role; keeps the rest", () => {
    const keys = filterReportEntities([
      { value: "t.me", type: "domain", role: "channel" }, // incidental name → drop
      { value: "evil.com", type: "domain", role: "operator" }, // keep
      { value: "junk", type: "domain", role: "noise" }, // role:noise → drop
      { value: "Maybe Person", type: "person_candidate", role: "" }, // person_candidate no role → drop
      { value: "Real Person", type: "person_candidate", role: "operator" }, // person_candidate WITH role → keep
    ]);
    expect(keys.has(canonKey("domain", "evil.com"))).toBe(true);
    expect(keys.has(canonKey("person_candidate", "Real Person"))).toBe(true);
    expect(keys.has(canonKey("domain", "t.me"))).toBe(false);
    expect(keys.has(canonKey("domain", "junk"))).toBe(false);
    expect(keys.has(canonKey("person_candidate", "Maybe Person"))).toBe(false);
    expect(keys.size).toBe(2);
  });
});

describe("relatedness verdict thresholds", () => {
  it("jaccard >= 0.15 → strong", () => {
    const a = report("A", ["a", "b", "c", "d", "e"]);
    const b = report("B", ["a", "b"]); // overlap 2 / union 5 = 0.4
    expect(relatedness(a, b).verdict).toBe("strong");
  });
  it("0.03 <= jaccard < 0.15 → weak", () => {
    const a = report("A", ["a", "b", "c", "d"]);
    const b = report("B", ["a", "e", "f", "g", "h", "i", "j"]); // overlap 1 / union 10 = 0.1
    const rel = relatedness(a, b);
    expect(rel.jaccard).toBeCloseTo(0.1, 5);
    expect(rel.verdict).toBe("weak");
  });
  it("jaccard < 0.03 (no overlap) → disjoint", () => {
    expect(relatedness(report("A", ["a", "b"]), report("B", ["c", "d"])).verdict).toBe("disjoint");
  });
  it("an empty entity set → disjoint", () => {
    expect(relatedness(report("A", []), report("B", ["c", "d"])).verdict).toBe("disjoint");
  });
  it("a shared cluster makes a zero-jaccard pair STRONG (the shared-cluster trigger)", () => {
    const a = report("A", ["a", "b", "c"], ["Drainer Infra"]);
    const b = report("B", ["x", "y", "z"], ["Drainer Infra"]); // jaccard 0 but a shared cluster
    const rel = relatedness(a, b);
    expect(rel.jaccard).toBe(0);
    expect(rel.sharedClusters).toBe(1);
    expect(rel.verdict).toBe("strong");
  });
});

describe("groupReports union-find (the COMPOUND gate)", () => {
  it("unions a high-jaccard pair and leaves a disjoint report alone (Jaccard-only, no clusters)", () => {
    const reports = [report("A", ["a", "b", "c", "d"]), report("B", ["a", "b"]), report("C", ["x", "y"])];
    const { groups } = groupReports(reports);
    // largest group first; A+B union (jaccard 0.5), C standalone
    expect(groups[0].sort()).toEqual(["A", "B"]);
    expect(groups.some((g) => g.length === 1 && g[0] === "C")).toBe(true);
  });
  it("unions a ZERO-jaccard pair ONLY because they share a cluster (compound gate)", () => {
    const reports = [report("A", ["a", "b"], ["C1"]), report("B", ["x", "y"], ["C1"])];
    const { groups } = groupReports(reports);
    expect(groups[0].sort()).toEqual(["A", "B"]);
  });
  it("does NOT union a weak pair (verdict !== strong)", () => {
    const a = report("A", ["a", "b", "c", "d"]);
    const b = report("B", ["a", "e", "f", "g", "h", "i", "j"]); // jaccard 0.1 → weak, no cluster
    const { groups } = groupReports([a, b]);
    expect(groups.length).toBe(2); // not unioned
  });
});

describe("verdictForGroup", () => {
  it("a singleton group is standalone; a strong pair is strong", () => {
    const reports = [report("A", ["a", "b", "c", "d"]), report("B", ["a", "b"]), report("C", ["x", "y"])];
    const { edges } = groupReports(reports);
    expect(verdictForGroup(["A", "B"], edges)).toBe("strong");
    expect(verdictForGroup(["C"], edges)).toBe("standalone");
  });
});

describe("formatGroupBrief markdown (the viewer parses this)", () => {
  const a: ReportInput = { meta: { objective: "rep-A", title: "Report A", ingestedAt: "2026-06-01T00:00:00Z", sourceType: "file_ingest" }, entityKeys: new Set(["a", "b"]), clusterNames: new Set() };
  const b: ReportInput = { meta: { objective: "rep-B", title: "Report B", ingestedAt: "2026-06-03T00:00:00Z", sourceType: "file_ingest" }, entityKeys: new Set(["a", "b"]), clusterNames: new Set() };
  const ctx = groupContext(["rep-A", "rep-B"], new Map([["rep-A", a], ["rep-B", b]]), [
    { label: "shared.com", type: "domain", role: "operator", runs: ["rep-A", "rep-B"] },
  ]);
  const md = formatGroupBrief(1, ctx, "strong", "The two reports share shared.com and front the same drainer.");

  it("emits the title, verdict, reports count, and time window the viewer regexes need", () => {
    expect(md).toMatch(/^# Brief: group 1$/m);
    expect(md).toMatch(/\*\*Relatedness verdict:\*\* strong/);
    expect(md).toMatch(/\*\*Reports in group:\*\* 2/);
    expect(md).toMatch(/\*\*Time window:\*\* 2026-06-01T00:00:00Z → 2026-06-03T00:00:00Z/);
  });

  it("Summary is ALWAYS followed by a ## section so the preview regex bounds (review finding 8)", () => {
    const m = md.match(/## Summary\n\n([\s\S]+?)(\n\n##|$)/);
    expect(m).toBeTruthy();
    expect(m![1]).toContain("share shared.com");
    expect(m![2]).toBe("\n\n##"); // bounded by the next section, NOT end-of-doc
    expect(md).toContain("## Cross-cutting entities");
  });

  it("lists the cross-cutting entity (in >=2 reports)", () => {
    expect(md).toContain("**shared.com** (domain/operator) — in 2 reports");
  });
});

describe("formatStandalone", () => {
  it("emits a '- ' line per orphan (the viewer counts these)", () => {
    const out = formatStandalone([
      { meta: { objective: "rep-X", title: "Report X" }, entityCount: 5, summary: "An unrelated report." },
    ]);
    expect(out).toContain("# Standalone reports");
    expect(out).toMatch(/^- \*\*Report X\*\* \(5 entities\)\. An unrelated report\./m);
  });
});
