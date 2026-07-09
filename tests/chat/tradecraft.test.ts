import { describe, it, expect } from "vitest";
import {
  parseTradecraftCommand,
  helperPromptFor,
  isHelpIntent,
  TOOL_GUIDE,
  TRADECRAFT_GATE_KEYS,
  CHALLENGE_SYSTEM,
  PREMORTEM_SYSTEM,
  HELPER_PROMPTS,
} from "../../src/chat/tradecraft.js";
import { classifyInput } from "../../src/chat/commands.js";

// cd-tradecraft / cd-guidance (chat-graph-parity-fixes): the typed-command grammar + help intent that
// restore the Scope/Challenge/Premortem gates + the empty-case walkthrough to the one chat input.

describe("parseTradecraftCommand", () => {
  it("parses the three gates, with or without a leading slash", () => {
    expect(parseTradecraftCommand("scope")).toEqual({ kind: "scope", question: "" });
    expect(parseTradecraftCommand("/scope")).toEqual({ kind: "scope", question: "" });
    expect(parseTradecraftCommand("scope who owns the funnel?")).toEqual({ kind: "scope", question: "who owns the funnel?" });
    expect(parseTradecraftCommand("challenge")).toEqual({ kind: "gate", step: "challenge" });
    expect(parseTradecraftCommand("/premortem")).toEqual({ kind: "gate", step: "premortem" });
  });

  it("parses the helpers, including the optional subject and reality-check spelling variants", () => {
    expect(parseTradecraftCommand("timeline")).toEqual({ kind: "helper", step: "timeline", subject: "" });
    expect(parseTradecraftCommand("target acme.com")).toEqual({ kind: "helper", step: "target", subject: "acme.com" });
    expect(parseTradecraftCommand("reality check")).toEqual({ kind: "helper", step: "reality_check", subject: "" });
    expect(parseTradecraftCommand("reality-check")).toEqual({ kind: "helper", step: "reality_check", subject: "" });
    expect(parseTradecraftCommand("/reality check")).toEqual({ kind: "helper", step: "reality_check", subject: "" });
  });

  it("returns null for non-tradecraft input", () => {
    for (const s of ["", "investigate acme.com", "who runs acme.com?", "findings", "only domains", "scoped down"]) {
      // "scoped down" must NOT match scope (firstWord is "scoped", not "scope")
      expect(parseTradecraftCommand(s)).toBeNull();
    }
  });
});

describe("helperPromptFor", () => {
  it("uses the verbatim template for bare helpers and a subject-specific prompt for target <x>", () => {
    expect(helperPromptFor("timeline", "")).toBe(HELPER_PROMPTS.timeline);
    expect(helperPromptFor("reality_check", "")).toBe(HELPER_PROMPTS.reality_check);
    expect(helperPromptFor("target", "")).toBe(HELPER_PROMPTS.target);
    expect(helperPromptFor("target", "acme.com")).toContain("acme.com");
    expect(helperPromptFor("target", "acme.com").toLowerCase()).toContain("profile");
  });

  it("a target-with-subject prompt still classifies as an investigator objective (verb-led), not Q&A", () => {
    expect(classifyInput(helperPromptFor("target", "acme.com"))).toBe("objective");
  });
});

describe("isHelpIntent", () => {
  it("detects onboarding / meta questions", () => {
    for (const s of ["help", "how do I start?", "what can you do?", "walk me through this", "I'm new", "get started", "how does this work?"]) {
      expect(isHelpIntent(s), s).toBe(true);
    }
  });
  it("does NOT hijack a real case question or an objective (narrow + end-anchored)", () => {
    for (const s of [
      "who runs acme.com?",
      "investigate acme.com",
      "what is the operating domain?", // a real case question, NOT meta — must stay a question
      "how do I find the registrant?", // case-specific how, not "how do I use/start"
      "what does acme.com resolve to?",
      "what is this domain doing?", // codex Major: a case question that STARTS with "what is this"
      "what should i do about acme.com?", // starts with "what should i do" but is case-specific
      "what can we do with this wallet?", // starts with "what can we do" but is case-specific
      "findings",
    ]) {
      expect(isHelpIntent(s), s).toBe(false);
    }
  });

  it("still fires for the STANDALONE meta phrasings (end-anchored tier)", () => {
    for (const s of ["what is this?", "what is this tool", "what should i do?", "what can you do?", "what should i do here"]) {
      expect(isHelpIntent(s), s).toBe(true);
    }
  });
});

describe("classifyInput precedence (help + tradecraft above objective/question)", () => {
  it("routes help, tradecraft gates, and helpers to their modes; bare entity still runs", () => {
    expect(classifyInput("help")).toBe("help");
    expect(classifyInput("how do I begin?")).toBe("help");
    expect(classifyInput("scope")).toBe("tradecraft");
    expect(classifyInput("challenge")).toBe("tradecraft");
    expect(classifyInput("premortem")).toBe("tradecraft");
    expect(classifyInput("timeline")).toBe("tradecraft");
    expect(classifyInput("reality check")).toBe("tradecraft");
    // the spendy-run guard is intact: a bare entity token still classifies as an objective
    expect(classifyInput("acme.com")).toBe("objective");
    expect(classifyInput("investigate acme.com")).toBe("objective");
    // a plain case question is still a question
    expect(classifyInput("who is behind this?")).toBe("question");
  });
});

describe("ported constants are faithful to tradecraft.py", () => {
  it("keeps the three gate keys and the verbatim personas", () => {
    expect(TRADECRAFT_GATE_KEYS).toEqual(["scope", "challenge", "premortem"]);
    expect(CHALLENGE_SYSTEM).toContain("devil's-advocate");
    expect(CHALLENGE_SYSTEM).toContain("Name-match traps");
    expect(PREMORTEM_SYSTEM).toContain("PREMORTEM");
    expect(PREMORTEM_SYSTEM).toContain("Before delivery:");
    expect(TOOL_GUIDE).toContain("investigate <domain>");
    expect(TOOL_GUIDE).toContain("scope");
  });
});
