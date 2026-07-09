import { describe, it, expect } from "vitest";
import { attributeFindingsToSteps, displayTrail, bottomLine, assetRollupFor, pivotsFor, type RunEntityLike } from "../../src/agent/runtrail.js";
import type { Step } from "../../src/agent/loop.js";

// r1-runtrail: the PURE run-trail helpers. Attribution links a finding ONLY to a step's emitted
// entities (D3/D4/D5), display is capped + redaction-agnostic (D7/D9), bottomLine is deterministic.

interface Ent { type: string; value: string; note?: string }
function toolStep(tool: string, input: unknown, entities: Ent[], opts?: { isError?: boolean; raw?: string }): Step {
  const result = opts?.raw ?? JSON.stringify(opts?.isError ? { error: "boom" } : { provider: tool, tier: "T1", entities });
  return { kind: "tool", tool, input, result, isError: !!opts?.isError };
}
const reasoning = (text: string): Step => ({ kind: "reasoning", text });
const F = (value: string, type: string, promoted = true) => ({ value, type, promoted });

describe("attributeFindingsToSteps", () => {
  it("attributes to the LAST tool step whose emitted entities contain the value", () => {
    const steps: Step[] = [
      toolStep("dns_lookup", { domain: "a.com" }, [{ type: "ip", value: "1.2.3.4" }]),
      reasoning("thinking about 1.2.3.4"),
      toolStep("rdap_domain", { domain: "b.com" }, [{ type: "ip", value: "1.2.3.4" }]),
    ];
    const [a] = attributeFindingsToSteps(steps, [F("1.2.3.4", "ip")]);
    expect(a.stepRef).toBe(3); // the later tool step wins (1-based)
    expect(a.stepTool).toBe("rdap_domain");
  });

  it("matches canonically: alias-folded type + case-insensitive value", () => {
    const steps: Step[] = [toolStep("dns_lookup", { domain: "a.com" }, [{ type: "ip_address", value: "9.9.9.9" }])];
    const [a] = attributeFindingsToSteps(steps, [F("9.9.9.9", "ip")]); // ip vs ip_address -> canonType folds
    expect(a.stepRef).toBe(1);
  });

  it("does NOT substring-match (1.2.3.4 must not link to 11.2.3.45)", () => {
    const steps: Step[] = [toolStep("dns_lookup", { domain: "a.com" }, [{ type: "ip", value: "11.2.3.45" }])];
    const [a] = attributeFindingsToSteps(steps, [F("1.2.3.4", "ip")]);
    expect(a.stepRef).toBeUndefined();
  });

  it("does NOT attribute a value that appears only in a note, not as an emitted entity value", () => {
    const steps: Step[] = [toolStep("dns_lookup", { domain: "example.com" }, [{ type: "ip", value: "9.9.9.9", note: "A of example.com" }])];
    const [a] = attributeFindingsToSteps(steps, [F("example.com", "domain")]);
    expect(a.stepRef).toBeUndefined(); // example.com is only in the note
  });

  it("does NOT attribute from an isError step (even if the value is in the error text)", () => {
    const steps: Step[] = [toolStep("rdap_domain", { domain: "x.com" }, [], { isError: true, raw: JSON.stringify({ error: "RDAP HTTP 404 for 1.2.3.4" }) })];
    const [a] = attributeFindingsToSteps(steps, [F("1.2.3.4", "ip")]);
    expect(a.stepRef).toBeUndefined();
  });

  it("never attributes from a reasoning step or an unparseable result", () => {
    const steps: Step[] = [
      reasoning("the ip is 1.2.3.4"),
      toolStep("dns_lookup", { domain: "a.com" }, [], { raw: "not json but mentions 1.2.3.4" }),
    ];
    const [a] = attributeFindingsToSteps(steps, [F("1.2.3.4", "ip")]);
    expect(a.stepRef).toBeUndefined();
  });

  it("no match -> stepRef undefined; the finding fields survive", () => {
    const steps: Step[] = [toolStep("dns_lookup", { domain: "a.com" }, [{ type: "ip", value: "5.5.5.5" }])];
    const [a] = attributeFindingsToSteps(steps, [F("8.8.8.8", "ip", false)]);
    expect(a.stepRef).toBeUndefined();
    expect(a.value).toBe("8.8.8.8");
    expect(a.promoted).toBe(false);
  });
});

describe("displayTrail", () => {
  it("renders tool steps with ONLY allowlisted scalar input keys (a junk blob is dropped — D9)", () => {
    const steps: Step[] = [toolStep("dns_lookup", { domain: "x.com", extra: "Z".repeat(5000) }, [{ type: "ip", value: "1.2.3.4" }])];
    const [d] = displayTrail(steps);
    expect(d.kind).toBe("tool");
    expect(d.inputText).toContain("domain=x.com");
    expect(d.inputText).not.toContain("Z"); // the 5KB junk key is never shown
  });

  it("caps a long reasoning step + sets truncated (D7)", () => {
    const [d] = displayTrail([reasoning("a".repeat(5000))]);
    expect(d.kind).toBe("reasoning");
    expect(d.text!.length).toBeLessThan(500);
    expect(d.truncated).toBe(true);
  });

  it("summarizes emitted entities + slices a large list with a +N more marker", () => {
    const ents: Ent[] = Array.from({ length: 20 }, (_, i) => ({ type: "subdomain", value: `h${i}.x.com` }));
    const [d] = displayTrail([toolStep("crtsh_subdomains", { domain: "x.com" }, ents)]);
    expect(d.resultText).toContain("20 entit");
    expect(d.resultText).toContain("more");
    expect(d.truncated).toBe(true);
  });

  it("renders an error step's compact error line", () => {
    const [d] = displayTrail([toolStep("rdap_domain", { domain: "x.com" }, [], { isError: true, raw: JSON.stringify({ error: "RDAP HTTP 404" }) })]);
    expect(d.isError).toBe(true);
    expect(d.resultText).toContain("RDAP HTTP 404");
  });
});

describe("bottomLine", () => {
  it("0 findings -> nothing-surfaced next move", () => {
    expect(bottomLine(0, 0, "end_turn")).toMatch(/nothing surfaced/i);
  });
  it("promoted + leads -> brief/expand next move", () => {
    const s = bottomLine(2, 1, "end_turn");
    expect(s).toContain("2 promoted, 1 lead");
    expect(s).toMatch(/brief|expand/i);
  });
  it("leads only -> corroborate next move", () => {
    expect(bottomLine(0, 3, "end_turn")).toMatch(/expand the strongest lead|corroborate/i);
  });
  it("aborted / budget stopReasons are surfaced", () => {
    expect(bottomLine(1, 0, "aborted")).toMatch(/stopped early/i);
    expect(bottomLine(1, 0, "budget")).toMatch(/budget/i);
  });
  it("worked:false LEADS with the tooling diagnostic (sp-2c870c26 — not read as clean-empty)", () => {
    const s = bottomLine(0, 0, "end_turn", false, "every OSINT tool call failed — check your keys / connectivity");
    expect(s).toMatch(/did no real work/i);
    expect(s).toMatch(/tool call failed/i);
    expect(s).not.toMatch(/nothing surfaced/i); // the degraded message replaces the clean-empty next-move
  });
  it("worked:false with a BLANK reason still reads degraded via a static fallback (codex issue-review)", () => {
    expect(bottomLine(0, 0, "end_turn", false, "")).toMatch(/did no real work.*OSINT tool returned data/i);
    expect(bottomLine(0, 0, "end_turn", false, undefined)).toMatch(/did no real work/i);
  });
  it("a degradedReason on a worked:true / legacy record does NOT read as degraded (gate is `worked`)", () => {
    // forged/stale degradedReason on a worked run — must be ignored.
    expect(bottomLine(2, 0, "end_turn", true, "forged degraded text")).not.toMatch(/did no real work/i);
    // legacy record (worked undefined) — preserves prior clean-empty behavior.
    expect(bottomLine(0, 0, "end_turn", undefined, "forged degraded text")).toMatch(/nothing surfaced/i);
  });
});

// sf-findings: the Discovered-assets rollup + the deterministic Next-moves pivots — PURE projections.

describe("assetRollupFor", () => {
  it("rolls each emitted entity up: found-via (FIRST step), checked-with (every emitting tool), on-graph", () => {
    const steps: Step[] = [
      toolStep("dns_lookup", { domain: "x.com" }, [{ type: "ip", value: "1.2.3.4" }]),
      toolStep("rdap_ip", { ip: "1.2.3.4" }, [{ type: "ip", value: "1.2.3.4" }, { type: "domain", value: "y.com" }]),
    ];
    const findings: RunEntityLike[] = [F("1.2.3.4", "ip", true), F("y.com", "domain", false)];
    const assets = assetRollupFor(steps, findings);

    const ip = assets.find((a) => a.asset === "1.2.3.4")!;
    expect(ip.foundStep).toBe(1); // FIRST step that emitted it (dns_lookup)
    expect(ip.foundVia).toBe("dns_lookup");
    expect(ip.checkedWith).toEqual(["dns_lookup", "rdap_ip"]); // every tool that surfaced it, first-seen order
    expect(ip.onGraph).toBe(true); // it's a promoted finding

    const dom = assets.find((a) => a.asset === "y.com")!;
    expect(dom.foundStep).toBe(2);
    expect(dom.foundVia).toBe("rdap_ip");
    expect(dom.onGraph).toBe(false); // a lead, not promoted
  });

  it("chased = a LATER step took the asset as an INPUT (not just emitted it)", () => {
    const steps: Step[] = [
      toolStep("dns_lookup", { domain: "x.com" }, [{ type: "ip", value: "1.2.3.4" }, { type: "domain", value: "sub.x.com" }]),
      toolStep("rdap_ip", { ip: "1.2.3.4" }, [{ type: "ip", value: "1.2.3.4" }]), // chased 1.2.3.4 as input
    ];
    const assets = assetRollupFor(steps, [F("1.2.3.4", "ip", true)]);
    const ip = assets.find((a) => a.asset === "1.2.3.4")!;
    expect(ip.chased).toBe(true); // step 2's ip input is 1.2.3.4
    const sub = assets.find((a) => a.asset === "sub.x.com")!;
    expect(sub.chased).toBe(false); // never taken as a later input
  });

  it("ignores reasoning + error + unparseable steps (only successful tool-emitted entities)", () => {
    const steps: Step[] = [
      reasoning("the ip is 9.9.9.9"),
      toolStep("rdap_domain", { domain: "x.com" }, [], { isError: true, raw: JSON.stringify({ error: "404 for 9.9.9.9" }) }),
      toolStep("dns_lookup", { domain: "x.com" }, [], { raw: "not json 9.9.9.9" }),
    ];
    expect(assetRollupFor(steps, [F("9.9.9.9", "ip", false)])).toEqual([]); // nothing was a real emitted entity
  });
});

describe("pivotsFor", () => {
  const lead = (value: string, grade?: string, confidence?: string): RunEntityLike => ({ value, type: "domain", promoted: false, grade, confidence });

  it("promoted findings are NOT pivots (they're already on the graph)", () => {
    expect(pivotsFor([F("on.graph.com", "domain", true)])).toEqual([]);
  });

  it("ranks leads by grade (A>B>C>D) then confidence (high>medium>low)", () => {
    const pivots = pivotsFor([lead("c.com", "C", "high"), lead("a.com", "A", "low"), lead("b.com", "B", "medium")]);
    expect(pivots.map((p) => p.entity)).toEqual(["a.com", "b.com", "c.com"]); // grade dominates the sort
  });

  it("returns one honest 'chase to corroborate' list (no reachability now/blocked split — a signed divergence)", () => {
    const pivots = pivotsFor([
      lead("ready.com", "B", "medium"),
      lead("ungraded.com", undefined, "low"), // ungraded leads still appear (ranked last), each chaseable
    ]);
    expect(pivots.map((p) => p.entity)).toEqual(["ready.com", "ungraded.com"]); // graded first, ungraded last
    expect(pivots[0].reason).toMatch(/grade B lead/i);
    expect(pivots[1].reason).toMatch(/chase to corroborate/i);
  });
});

// sf-findings: the enriched confidence + claim fields survive attribution (they ride on RunEntityLike).
describe("enriched finding fields (confidence + claim)", () => {
  it("attributeFindingsToSteps preserves confidence + claim onto the attributed finding", () => {
    const steps: Step[] = [toolStep("dns_lookup", { domain: "x.com" }, [{ type: "ip", value: "1.2.3.4" }])];
    const enriched: RunEntityLike = { value: "1.2.3.4", type: "ip", promoted: true, grade: "A", confidence: "high", claim: "DNS A record resolved by dns_lookup." };
    const [a] = attributeFindingsToSteps(steps, [enriched]);
    expect(a.stepRef).toBe(1);
    expect(a.confidence).toBe("high");
    expect(a.claim).toBe("DNS A record resolved by dns_lookup.");
  });
});
