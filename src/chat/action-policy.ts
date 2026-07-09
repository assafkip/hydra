import { classifyInput } from "./commands.js";

export type ChatActionKind = "answer" | "investigate" | "propose" | "blocked" | "needs_capability";
export type ChatCommitMode = "none" | "run" | "approval_required";
export type ChatActionTarget = "finding" | "relationship" | "graph" | "brief" | "unknown";
export type ChatActionRisk = "destructive" | "raw_upload_dump" | "ungrounded_edge" | "unsupported";

export interface ChatActionPolicy {
  kind: ChatActionKind;
  commit: ChatCommitMode;
  target?: ChatActionTarget;
  targetValue?: string;
  risk?: ChatActionRisk;
  capability?: string;
  reason: string;
  userText: string;
}

export interface ChatActionPolicyOpts {
  configuredCapabilities?: Iterable<string>;
}

const PROVIDERS: Record<string, RegExp> = {
  virustotal: /\bvirus\s*total\b|\bvirustotal\b|\bvt\b/i,
  apify: /\bapify\b/i,
  perplexity: /\bperplexity\b/i,
};

const RAW_UPLOAD_DUMP_RE =
  /\b(add|put|dump|show|place|load)\b.*\b(every|all|raw)\b.*\b(upload(?:ed)?|file|document|evidence|entit(?:y|ies))\b.*\b(graph|canvas|node|nodes)\b/i;

const DESTRUCTIVE_RE =
  /\b(delete|wipe|erase|destroy|purge|remove|clear)\b.*\b(all\s+)?(findings?|leads?|evidence|reports?|uploads?|cases?|case|briefs?|history|vault|database|db)\b/i;

const GRAPH_REMOVE_RE = /^(?:remove|delete|drop|exclude)\s+(.+)$/i;

const FINDING_MUTATION_RE =
  /\b(add|create|promote|mark|save|record|commit)\b.*\b(finding|lead|claim)\b|\bmake\b.*\bthis\b.*\b(finding|lead)\b/i;

const EDGE_MUTATION_RE =
  /\b(add|create|draw|connect|link|commit)\b.*\b(edge|relationship|connection|link)\b|\bconnect\b.+\b(to|with)\b/i;

const COOCCURRENCE_EDGE_RE =
  /\b(co-?occurr?ence|co-?mention|mentioned together|appears together)\b.*\b(edge|relationship|connection|link)\b|\b(edge|relationship|connection|link)s?\b.*\b(co-?occurr?ence|co-?mention|mentioned together|appears together)\b/i;

export function classifyChatAction(raw: string, opts: ChatActionPolicyOpts = {}): ChatActionPolicy {
  const text = (raw || "").trim();
  const configured = new Set([...opts.configuredCapabilities ?? []].map((c) => c.toLowerCase()));

  for (const [capability, pattern] of Object.entries(PROVIDERS)) {
    if (pattern.test(text) && !configured.has(capability)) {
      return {
        kind: "needs_capability",
        commit: "none",
        capability,
        reason: `${capability} is not configured. Explain the missing key and offer available pivots.`,
        userText: text,
      };
    }
  }

  if (RAW_UPLOAD_DUMP_RE.test(text)) {
    return {
      kind: "blocked",
      commit: "none",
      target: "graph",
      risk: "raw_upload_dump",
      reason: "Raw uploads must go through extraction, typing, and gating before they affect the graph.",
      userText: text,
    };
  }

  if (DESTRUCTIVE_RE.test(text)) {
    return {
      kind: "blocked",
      commit: "none",
      risk: "destructive",
      reason: "Destructive durable-state changes cannot be committed from chat text alone.",
      userText: text,
    };
  }

  const graphRemove = text.match(GRAPH_REMOVE_RE);
  if (graphRemove) {
    const targetValue = graphRemove[1].trim();
    if (!/^(all\s+)?filters?$/i.test(targetValue)) {
      return {
        kind: "propose",
        commit: "approval_required",
        target: "graph",
        targetValue,
        reason: "Graph removals are reversible, but still need explicit approval before changing the case view.",
        userText: text,
      };
    }
  }

  if (COOCCURRENCE_EDGE_RE.test(text)) {
    return {
      kind: "propose",
      commit: "approval_required",
      target: "relationship",
      risk: "ungrounded_edge",
      reason: "Co-occurrence is a hint. verify with evidence before adding an edge.",
      userText: text,
    };
  }

  if (EDGE_MUTATION_RE.test(text)) {
    return {
      kind: "propose",
      commit: "approval_required",
      target: "relationship",
      reason: "Relationship changes need investigated evidence before commit.",
      userText: text,
    };
  }

  if (FINDING_MUTATION_RE.test(text)) {
    return {
      kind: "propose",
      commit: "approval_required",
      target: "finding",
      reason: "Findings and leads need validation/gating before durable commit.",
      userText: text,
    };
  }

  const mode = classifyInput(text);
  if (mode === "case" || mode === "objective") {
    return {
      kind: "investigate",
      commit: "run",
      reason: "Start or continue a live investigation run.",
      userText: text,
    };
  }

  return {
    kind: "answer",
    commit: "none",
    reason: "Answer, clarify, cite, or say unknown without mutating durable state.",
    userText: text,
  };
}
