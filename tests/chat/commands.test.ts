import { describe, it, expect } from "vitest";
import { parseGraphCommand, classifyInput, isBareEntityToken, objectiveFrom } from "../../src/chat/commands.js";

// cd-commands (D3): the deterministic mode grammar. The headline guarantee is the spendy-run
// guard — a natural-language question that MENTIONS an entity must classify as a question, never
// as an investigator run.

describe("parseGraphCommand", () => {
  it("parses show-all / reset / clear filters", () => {
    for (const s of ["show all", "show everything", "reset", "reset filters", "clear filters"]) {
      expect(parseGraphCommand(s)).toEqual({ kind: "showAll" });
    }
  });

  it("parses fit / re-layout / layout <name>", () => {
    expect(parseGraphCommand("fit")).toEqual({ kind: "fit" });
    expect(parseGraphCommand("re-layout")).toEqual({ kind: "relayout" });
    expect(parseGraphCommand("relayout")).toEqual({ kind: "relayout" });
    expect(parseGraphCommand("layout fcose")).toEqual({ kind: "setLayout", layout: "fcose" });
    expect(parseGraphCommand("layout dagre")).toEqual({ kind: "setLayout", layout: "dagre" });
    expect(parseGraphCommand("layout nonsense")).toBeNull(); // unknown layout is not a command
  });

  it("parses search / min score / type filter", () => {
    expect(parseGraphCommand("search gambler")).toEqual({ kind: "search", query: "gambler" });
    expect(parseGraphCommand("highlight trumpfundus.com")).toEqual({ kind: "search", query: "trumpfundus.com" });
    expect(parseGraphCommand("min score 50")).toEqual({ kind: "minScore", score: 50 });
    expect(parseGraphCommand("score over 80")).toEqual({ kind: "minScore", score: 80 });
    expect(parseGraphCommand("min score 200")).toEqual({ kind: "minScore", score: 100 }); // capped
    expect(parseGraphCommand("only domains")).toEqual({ kind: "filterType", etype: "domain" });
    expect(parseGraphCommand("wallets")).toEqual({ kind: "filterType", etype: "crypto_wallet" });
    expect(parseGraphCommand("show ips")).toEqual({ kind: "filterType", etype: "ip" });
  });

  it("returns null for non-commands", () => {
    for (const s of ["", "  ", "investigate example.com", "who runs example.com?", "findings", "hello there"]) {
      expect(parseGraphCommand(s)).toBeNull();
    }
  });

  it("parses node-removal (remove/delete <node>), stripping a trailing edges clause", () => {
    expect(parseGraphCommand("remove fifastore.us")).toEqual({ kind: "removeNode", target: "fifastore.us" });
    expect(parseGraphCommand("delete fifastore.us")).toEqual({ kind: "removeNode", target: "fifastore.us" });
    // the founder's phrasing: "remove this node and all edges associated with them"
    expect(parseGraphCommand("remove fifastore.us and all edges associated with them"))
      .toEqual({ kind: "removeNode", target: "fifastore.us" });
    expect(parseGraphCommand("drop acme.io with its connections")).toEqual({ kind: "removeNode", target: "acme.io" });
    expect(parseGraphCommand("exclude 1.2.3.4 and its edges")).toEqual({ kind: "removeNode", target: "1.2.3.4" });
  });

  it("targets the selected node for 'remove this/the selected node' (empty target)", () => {
    expect(parseGraphCommand("remove this node")).toEqual({ kind: "removeNode", target: "" });
    expect(parseGraphCommand("delete the selected node")).toEqual({ kind: "removeNode", target: "" });
    expect(parseGraphCommand("remove this node and all its edges")).toEqual({ kind: "removeNode", target: "" });
  });

  it("does not hijack 'remove filters' (stays a reset, not a node removal)", () => {
    expect(parseGraphCommand("remove filters")).toEqual({ kind: "showAll" });
    expect(parseGraphCommand("remove all filters")).toEqual({ kind: "showAll" });
  });
});

describe("isBareEntityToken", () => {
  it("accepts a single bare entity token", () => {
    for (const s of ["example.com", "trumpfundus.com", "93.184.216.34", "@cutdead", "https://t.me/ord403",
      "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "0x52908400098527886E0F7030069857D2E4169EE7"]) {
      expect(isBareEntityToken(s)).toBe(true);
    }
  });
  it("rejects sentences and bare words", () => {
    for (const s of ["who runs example.com?", "example.com is sketchy", "domain", "circle", "example.com?", ""]) {
      expect(isBareEntityToken(s)).toBe(false);
    }
  });
});

describe("classifyInput precedence", () => {
  it("graph commands classify as command", () => {
    for (const s of ["show all", "fit", "re-layout", "layout fcose", "search gambler", "min score 50", "only domains"]) {
      expect(classifyInput(s)).toBe("command");
    }
  });

  it("findings/runs/trail classify as runs", () => {
    for (const s of ["findings", "runs", "run trail", "trail", "show findings"]) {
      expect(classifyInput(s)).toBe("runs");
    }
  });

  it("explicit verbs and bare tokens classify as objective", () => {
    expect(classifyInput("investigate trumpfundus.com")).toBe("objective");
    expect(classifyInput("look into @cutdead")).toBe("objective");
    expect(classifyInput("dig bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")).toBe("objective");
    expect(classifyInput("example.com")).toBe("objective"); // bare domain token
    expect(classifyInput("93.184.216.34")).toBe("objective"); // bare ip token
    expect(classifyInput("@handle")).toBe("objective"); // bare handle token
  });

  it("A3: whole-case intents classify as 'case' (a roster sweep, not a single target)", () => {
    for (const s of [
      "investigate the case", "investigate the whole case", "investigate everything", "investigate all",
      "investigate all the seeds", "run the whole case", "work the case", "sweep the case", "dig into the entire case",
    ]) {
      expect(classifyInput(s)).toBe("case");
    }
    // a single target is still a per-objective run, NOT a whole-case sweep:
    expect(classifyInput("investigate x.com")).toBe("objective");
    expect(classifyInput("investigate the iranian cluster")).toBe("objective");
    // codex: an "all …" phrase with a SPECIFIC target stays single-objective (anchored regex):
    expect(classifyInput("investigate all leads for example.com")).toBe("objective");
    expect(classifyInput("dig into all targets from x.com")).toBe("objective");
    // the spendy-run guard still wins: a QUESTION about the case answers, never sweeps:
    expect(classifyInput("should I investigate the case?")).toBe("question");
    expect(classifyInput("what's in the whole case?")).toBe("question");
  });

  // RCA rca-start-investigation-routes-to-qa (2026-06-24): the founder typed "start investigation" and
  // "continue from scope" on the FIFA case and BOTH returned a Q&A summary instead of launching a run —
  // no verb/case pattern owned start/begin/continue/resume/go, so they fell to the cost-safe Q&A lane.
  // Conductor affirmatives (no named target) MUST drive the whole case.
  it("conductor affirmatives: start/begin/continue/resume/go drive the whole case (not Q&A)", () => {
    for (const s of [
      "start investigation", "start the investigation", "start investigating", "begin", "begin the investigation",
      "let's start", "continue", "continue from scope", "continue the investigation",
      "resume", "resume the investigation", "proceed", "go", "go ahead", "keep going", "carry on", "do it",
    ]) {
      expect(classifyInput(s)).toBe("case");
    }
    // a NAMED target after the affirmative stays a single-objective run, not a whole-case sweep:
    expect(classifyInput("continue investigating fifa.com")).toBe("objective");
    expect(classifyInput("start with @cutdead")).toBe("objective");
    // the spendy-run guard still wins: a QUESTION about starting answers, never sweeps:
    expect(classifyInput("should I start the investigation?")).toBe("question");
    expect(classifyInput("how do I start?")).toBe("help"); // onboarding walkthrough, not a run
  });

  it("analyst-led direction: natural imperatives classify as objective (not Q&A)", () => {
    expect(classifyInput("focus on the iranian cluster")).toBe("objective");
    expect(classifyInput("expand around acme.io")).toBe("objective");
    expect(classifyInput("trace the funds from that wallet")).toBe("objective");
    expect(classifyInput("dig into who's behind trumpfundus.com")).toBe("objective");
    expect(classifyInput("look at the connections to @cutdead")).toBe("objective");
    expect(classifyInput("pivot on the registrant email")).toBe("objective");
  });

  // RCA rca-investigate-routes-to-qa-verb-allowlist (2026-06-24): the reproducer is bound to the REFERENCE,
  // not a synthetic verb list. The 4_points ops-log objective is verbatim "identify malicious connections,
  // actors and money trails" — the run LEADS with "identify", which the old allowlist omitted, so the
  // founder's exact (b) objective classified as Q&A (the FAIL). These assert the reference phrasing ACTS.
  it("(b) reference objective: the analyst's verbatim ops-log phrasing classifies as a run, not Q&A", () => {
    // the founder's EXACT (b) live-test objective (no magic phrase):
    expect(classifyInput("identify malicious activity and money travel fifa-rewards.com fifaredeem.com")).toBe("objective");
    // the ops-log verb LEADS with "identify" with no inline entity (an active-scope objective):
    expect(classifyInput("identify the money trail")).toBe("objective");
    // "find <sentence>" is an objective (not swallowed by the graph 'find' filter); "find <term>" stays a graph search:
    expect(classifyInput("find the malicious actors behind fifa-rewards.com")).toBe("objective");
    expect(classifyInput("find gambler")).toBe("command"); // single-term graph search preserved
    // altitude backstop: a non-question that NAMES a target acts even when its leading verb isn't enumerated:
    expect(classifyInput("show me who is behind fifa-rewards.com")).toBe("objective");
    expect(classifyInput("the money flow around 0x52908400098527886E0F7030069857D2E4169EE7")).toBe("objective");
    // chatter with no target and no verb still answers (no silent spend on idle text):
    expect(classifyInput("hello there")).toBe("question");
    expect(classifyInput("thanks, that's helpful")).toBe("question");
    // an entity-bearing QUESTION still answers (question guard runs before the entity backstop):
    expect(classifyInput("what do we know about fifa-rewards.com")).toBe("question");
  });

  it("the cost-safe Q&A lane: a QUESTION-LED input answers, never spends", () => {
    expect(classifyInput("who runs example.com?")).toBe("question");
    expect(classifyInput("what do we know about trumpfundus.com")).toBe("question");
    expect(classifyInput("is 93.184.216.34 connected to the seed?")).toBe("question");
    expect(classifyInput("summarize the case")).toBe("question");
    // an input that LEADS with a question word still answers, even when an action verb appears mid-sentence:
    expect(classifyInput("should I focus on the iranian cluster?")).toBe("question");
    expect(classifyInput("can you dig into trumpfundus.com?")).toBe("question");
    expect(classifyInput("what should I investigate next?")).toBe("question");
  });

  // Door A (D3 / finding-4): the QUESTION_RE precedence no longer OUTRANKS a leading verb. A verb-LED
  // imperative is an objective and DIGS even when casually phrased with a trailing "?"; objectiveFrom strips
  // the "?" so the run target is clean. This removes the cage ("a question can never accidentally investigate")
  // for explicit imperatives, while a genuinely question-LED input (above) still answers cheap.
  it("Door A: a verb-led imperative digs even with a trailing '?', and the objective is clean", () => {
    expect(classifyInput("investigate trumpfundus.com?")).toBe("objective");
    expect(classifyInput("focus on the iranian cluster?")).toBe("objective");
    expect(classifyInput("trace the funds from that wallet?")).toBe("objective");
    expect(objectiveFrom("investigate trumpfundus.com?")).toBe("trumpfundus.com"); // "?" stripped from the target
    // a plain whole-case sweep still classifies as 'case'; the verb-led imperatives keep digging as before:
    expect(classifyInput("investigate the whole case")).toBe("case");
    expect(classifyInput("investigate trumpfundus.com")).toBe("objective");
    expect(classifyInput("focus on the iranian cluster")).toBe("objective");
  });

  // Cost-safety boundary (Codex review): the trailing-"?" override is for a LEADING VERB only. A bare entity
  // OR a whole-case phrase WITH a trailing "?" is NOT a clean imperative — it stays a cost-safe question
  // (bare entity) or a single objective (the verb still leads), never a silent behavior surprise.
  it("Door A boundary: a bare-entity-with-'?' stays a question; a verb still leads on a '?'-suffixed case", () => {
    expect(classifyInput("example.com?")).toBe("question"); // bare entity + "?" → cost-safe Q&A, not a dig
    expect(classifyInput("example.com")).toBe("objective"); // the CLEAN bare entity digs
    // "investigate the whole case?" — CASE_RE is end-anchored (no "?"), so the leading verb wins → a single
    // objective with a CLEAN target ("the whole case"), not a roster sweep. It still DIGS (not Q&A).
    expect(classifyInput("investigate the whole case?")).toBe("objective");
    expect(objectiveFrom("investigate the whole case?")).toBe("the whole case");
  });
});

describe("objectiveFrom", () => {
  it("strips the leading verb so the target is the objective", () => {
    expect(objectiveFrom("investigate trumpfundus.com")).toBe("trumpfundus.com");
    expect(objectiveFrom("look into @cutdead")).toBe("@cutdead");
    expect(objectiveFrom("run on: example.com")).toBe("example.com");
  });
  it("strips broadened directive verbs, keeping the natural-language direction", () => {
    expect(objectiveFrom("focus on the iranian cluster")).toBe("the iranian cluster");
    expect(objectiveFrom("expand around acme.io")).toBe("acme.io");
    expect(objectiveFrom("trace the funds from that wallet")).toBe("the funds from that wallet");
    expect(objectiveFrom("pivot on the registrant email")).toBe("the registrant email");
  });
  it("leaves a bare token unchanged, and a lone verb keeps the original", () => {
    expect(objectiveFrom("example.com")).toBe("example.com");
    expect(objectiveFrom("investigate")).toBe("investigate"); // nothing after the verb → keep something
  });
});
