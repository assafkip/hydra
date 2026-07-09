// cd-commands (PRD chat-dock D3): the deterministic mode grammar for the ONE chat input box.
// Ported from investigations/webapp/templates/_chat.html `tryGraphCommand` + the implicit
// router, made explicit + node-testable. ONE input, three modes, FIXED precedence so a
// question ("who runs example.com?") can NEVER accidentally start a spendy investigator run.
//
// Precedence (classifyInput):
//   1. explicit GRAPH command  (parseGraphCommand matches)        -> "command"
//   2. findings / runs / trail shortcut                            -> "runs"
//   3. help / onboarding intent (isHelpIntent)                     -> "help"
//   4. tradecraft command (scope/challenge/premortem/helpers)      -> "tradecraft"
//   5. investigator intent (verb OR a bare entity token)          -> "objective"
//   6. anything else                                               -> "question"  (grounded Q&A)
//
// Door A (D3): an explicit IMPERATIVE outranks the question guard. An investigator run fires on a leading
// action verb (investigate / look into / dig / focus on / expand / trace / examine / … — analyst-led direction,
// the rest of the line is the objective) — even when casually phrased with a trailing "?" (objectiveFrom strips
// it so the run target is clean). A whole-case sweep (CASE_RE) and a bare entity token also dig, in their CLEAN
// form. Only an input that names NO imperative falls through to the cost-safe Q&A lane: a question-WORD-led
// input ("who runs x?", "should I focus on the cluster?") ANSWERS, because VERB_RE is ^-anchored so a
// mid-sentence verb never trips it; a bare entity WITH a trailing "?" ("example.com?") also stays a question.
// So "investigate x?" and "focus on the cluster" ACT, while "example.com?" and "who runs example.com?" ANSWER.
//
// Help + tradecraft sit ABOVE objective so "scope", "challenge", "timeline", and "how do I start?"
// reach their handlers instead of being mistaken for an investigator objective or a Q&A question.

import { parseTradecraftCommand, isHelpIntent } from "./tradecraft.js";

export type GraphCommand =
  | { kind: "showAll" }
  | { kind: "fit" }
  | { kind: "relayout" }
  | { kind: "setLayout"; layout: string }
  | { kind: "search"; query: string }
  | { kind: "minScore"; score: number }
  | { kind: "filterType"; etype: string }
  | { kind: "removeNode"; target: string }; // node-removal: target = an entity value, or "" for the selected node

export type InputMode = "command" | "runs" | "help" | "tradecraft" | "case" | "objective" | "question";

const LAYOUTS = new Set(["cose", "fcose", "dagre", "concentric", "circle"]);

// Bare-word type aliases (ported verbatim from _chat.html TYPES) → the graph's canonical etype.
const TYPES: Record<string, string> = {
  domain: "domain", domains: "domain", ip: "ip", ips: "ip", email: "email", emails: "email",
  wallet: "crypto_wallet", wallets: "crypto_wallet", org: "organization", orgs: "organization",
  organization: "organization", organizations: "organization", person: "person", people: "person",
  persons: "person", handle: "handle", handles: "handle", url: "url", urls: "url",
};

/** Parse a typed GRAPH command, or null if the text is not one. Pure. */
export function parseGraphCommand(raw: string): GraphCommand | null {
  const t = (raw || "").trim().toLowerCase();
  if (!t) return null;

  if (/^(show (all|everything)|reset( filters?)?|clear filters?)$/.test(t)) return { kind: "showAll" };
  if (/^(fit|fit graph|zoom to fit)$/.test(t)) return { kind: "fit" };
  if (/^(re-?\s?layout|re ?layout|relayout)$/.test(t)) return { kind: "relayout" };

  let m = t.match(/^layout\s+([a-z-]+)$/);
  if (m && LAYOUTS.has(m[1])) return { kind: "setLayout", layout: m[1] };

  m = t.match(/^(?:search|highlight)\s+(.+)$/);
  if (m) return { kind: "search", query: m[1].trim() };
  // RCA rca-investigate-routes-to-qa-verb-allowlist: "find" is BOTH a graph-filter verb and the second-most
  // natural intel objective ("find the actors behind X"). A single-term "find gambler" stays a graph search;
  // a "find <sentence>" falls through so classifyInput can route it to the investigator (VERB_RE owns "find").
  m = t.match(/^find\s+(\S+)$/);
  if (m) return { kind: "search", query: m[1].trim() };

  m = t.match(/^(?:min(?:imum)?\s+score|score)\s*(?:>=?|over|above)?\s*(\d+)$/);
  if (m) return { kind: "minScore", score: Math.min(100, parseInt(m[1], 10)) };

  // node-removal (founder 2026-06-25): "remove/delete <node>" → exclude it (reversible). An optional trailing
  // "and (all|its) edges/connections" is stripped — edges drop automatically when the node goes. "remove this/
  // the selected node" targets the currently-selected node (empty target; the handler resolves it).
  m = t.match(/^(?:remove|delete|drop|exclude)\s+(.+)$/);
  if (m) {
    let target = m[1].trim();
    if (/^(all\s+)?filters?$/.test(target)) return { kind: "showAll" }; // "remove filters" = reset, not a node
    target = target.replace(/\s+(?:and|with|,)\s*(?:(?:all|its|their|the)\s+)*(?:edges?|connections?|links?)(?:\s+(?:associated|connected|attached)(?:\s+(?:with|to)\s+(?:it|them))?)?\s*$/i, "").trim();
    // "this/that/the (selected|current) node" → the currently-selected node (empty target). Strip the
    // selection words; if nothing real remains, it's the selected node (a real entity value survives this).
    const remainder = target.replace(/\bnodes?\b/g, " ").replace(/\b(?:this|that|the|selected|current)\b/g, " ").trim();
    if (remainder === "") target = "";
    return { kind: "removeNode", target };
  }

  // bare-type filter ("domains", "only domains", "show ips", "filter by wallets")
  m = t.match(/^(?:only |show |filter (?:to |by )?)?([a-z]+)s?$/);
  if (m) {
    const etype = TYPES[m[1]] || TYPES[m[1] + "s"];
    if (etype) return { kind: "filterType", etype };
  }
  return null;
}

const RUNS_RE = /^(show\s+)?(findings?|runs?|run\s*trail|trail)$/;

// Investigator-intent verbs — a LEADING action verb means "go drive the case" (analyst-led direction):
// the rest of the line becomes the objective, which the autonomously-deep agent interprets (a high-level
// "focus on the Iranian cluster" is a valid objective, not just a bare domain). Broadened beyond the original
// investigate/look-into set so natural direction acts instead of falling through to Q&A. "enrich" is NOT here
// — enrich is a manual provider action on the Enrich page (the user's keyed direct fetch), not a run.
// The intel verbs identify/find/determine/uncover/attribute/surface/establish/enumerate are DERIVED from the
// 4_points ops-log objective ("identify malicious connections, actors and money trails"), not hand-authored —
// the reference run LEADS with "identify", which the old allowlist omitted, so the system answered instead of
// acting on its own spec objective (RCA rca-investigate-routes-to-qa-verb-allowlist).
const VERB_RE = /^(investigate|look\s+into|look\s+up|look\s+at|dig\s+into|dig|run\s+on|probe|profile|focus\s+on|expand(\s+(on|around|the))?|trace|examine|pull\s+up|check\s+out|go\s+after|pivot(\s+on)?|target|map(\s+out)?|identify|find|determine|uncover|attribute|surface|establish|enumerate)\b/i;

// The cost-safe Q&A lane: a question-WORD-led input ("should I dig into X?", "who runs X?") → grounded Q&A.
// Door A: checked AFTER the verb/case/entity tests, so an explicit imperative ("investigate X?", "focus on the
// cluster") DIGS even when phrased with a trailing "?"; only an input that names no imperative answers cheap.
// VERB_RE is ^-anchored, so a mid-sentence verb in a question ("can you dig into X?") never trips a run.
const QUESTION_RE = /^(\s*(who|whom|whose|what|which|where|when|why|how|is|are|was|were|do|does|did|can|could|should|would|will|has|have|had|any|tell\s+me|summar)\b)|\?\s*$/i;

// A3 whole-case intent: "investigate the case / everything / all (the seeds/entities)", "run the whole
// case", "work the case", "sweep the case". Distinct from a single-target objective ("investigate x.com")
// — it drives investigateCase over the ENTIRE roster. Checked AFTER the QUESTION guard (so "should I
// investigate the case?" still ANSWERS) and BEFORE the single-objective verb test.
// Anchored to END-of-input (codex): the WHOLE input must be the case intent, so "investigate all leads
// for example.com" / "dig into all targets from x" keep a specific target and stay single-objective runs.
const CASE_RE = /^(?:investigate|run|work|sweep|dig\s+into|do)\s+(?:the\s+|this\s+)?(?:whole\s+|entire\s+|full\s+)?(?:case|everything|all(?:\s+(?:the\s+)?(?:seeds|entities|targets|leads))?)\s*$/i;

// Conductor affirmatives (RCA rca-start-investigation-routes-to-qa): "start" / "begin" / "continue (from
// scope)" / "resume" / "go (ahead)" / "keep going" / "proceed" — the analyst telling the agent to DRIVE the
// case with NO specific target named. The 4points loop ends with the conductor asking "want me to start?";
// the analyst's reply ("start investigation", "continue from scope", "go") MUST launch a run, not answer.
// These mean a whole-case sweep (investigateCase over the roster), so they route to "case", not "objective".
// END-anchored + a generic trailing noun only, so a NAMED target stays a single-objective run ("continue
// with fifa.com" → objective). Bug 2026-06-24: the founder typed "start investigation" and "continue from
// scope" on the FIFA case and BOTH fell to cost-safe Q&A — no verb/case pattern owned the words.
const START_CASE_RE =
  /^(?:let'?s\s+|please\s+|ok(?:ay)?,?\s+|yes,?\s+)?(?:start|begin|continue|resume|proceed|go(?:\s+ahead)?|carry\s+on|keep\s+going|do\s+it|run\s+it)(?:\s+(?:with\s+|from\s+|on\s+)?(?:the\s+|this\s+|my\s+|our\s+)?(?:investigation|investigating|case|scope|analysis|dig(?:ging)?|sweep|run|work|review|enrichment))?\s*\??$/i;

/** True when the WHOLE trimmed input is a single bare entity token (domain/ip/wallet/handle/url). */
export function isBareEntityToken(raw: string): boolean {
  const t = (raw || "").trim();
  if (!t || /\s/.test(t)) return false; // must be a single token
  if (/^https?:\/\/\S+$/i.test(t)) return true; // url
  if (/^@[\w.]{2,}$/.test(t)) return true; // handle
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return true; // ipv4
  if (/^0x[0-9a-f]{40}$/i.test(t)) return true; // eth address
  if (/^(bc1|tb1)[a-z0-9]{20,}$/i.test(t)) return true; // btc bech32
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{24,34}$/.test(t)) return true; // btc base58
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(t) && /[a-z]/i.test(t.split(".").pop() || "")) return true; // domain
  return false;
}

/** Classify a typed input into one of the six modes (precedence above). Pure. */
export function classifyInput(raw: string): InputMode {
  const t = (raw || "").trim();
  if (!t) return "question";
  if (parseGraphCommand(t)) return "command";
  if (RUNS_RE.test(t.toLowerCase())) return "runs";
  if (isHelpIntent(t)) return "help";
  if (parseTradecraftCommand(t)) return "tradecraft";
  // Door A (D3 / finding-4, RCA rca-faithful-clone-wrong-reference): an explicit IMPERATIVE outranks the
  // question guard. A whole-case sweep (CASE_RE) or a leading action verb DIGS — and a verb-led imperative
  // digs even when casually phrased with a trailing "?" (objectiveFrom strips it). A bare entity token digs
  // in its clean form. Only an input that does NOT name an imperative falls through to the cost-safe Q&A lane
  // (a question-WORD-led input like "who runs x?" / "should I dig into x?", or a bare entity WITH a trailing
  // "?" like "example.com?", never spends — VERB_RE is ^-anchored so a mid-sentence verb doesn't trip it).
  // This removes the old precedence that defaulted EVERY question-shaped input to Q&A — the cage that made a
  // verb-led "investigate x?" answer instead of dig.
  if (CASE_RE.test(t)) return "case"; // A3: a whole-case sweep, before the single-target verb test
  if (START_CASE_RE.test(t)) return "case"; // conductor affirmatives ("start investigation", "continue from scope", "go") drive the whole case
  if (VERB_RE.test(t)) return "objective";
  if (isBareEntityToken(t)) return "objective";
  if (QUESTION_RE.test(t)) return "question"; // cost-safe lane: a genuinely question-led input answers, never digs
  // Altitude fix (RCA rca-investigate-routes-to-qa-verb-allowlist): a non-question input that NAMES a target
  // (a domain/handle/ip/wallet/url anywhere) ACTS, even if its leading verb isn't enumerated. This makes the
  // discriminator "objective vs question", not "listed verb vs not" — the old terminal Q&A default was the
  // same cage D3 removed at the top of the router, reintroduced at the bottom. The up-front budget (4piv-04),
  // not a Q&A default, is the cost guard. Question-WORD-led inputs already returned above, so an entity-bearing
  // QUESTION ("who runs example.com?") still answers; only a non-question that names a seed newly digs.
  if (containsInvestigableEntity(t)) return "objective";
  return "question"; // pure chatter, no target, no verb → cost-safe Q&A
}

/** True when the input contains at least one investigable entity token anywhere (domain/handle/ip/wallet/url).
 *  The ops-log discriminator for an objective: it NAMES its seeds. Pure. Domains require a ≥2-char alpha TLD so
 *  prose like "e.g" / "U.S" does not read as a target. */
export function containsInvestigableEntity(raw: string): boolean {
  for (const tokRaw of (raw || "").trim().split(/\s+/)) {
    const tok = tokRaw.replace(/[)\].,;:!?'"]+$/, ""); // strip trailing sentence punctuation
    if (/^https?:\/\/\S+$/i.test(tok)) return true; // url
    if (/^@[\w.]{2,}$/.test(tok)) return true; // handle
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(tok)) return true; // ipv4
    if (/^0x[0-9a-f]{40}$/i.test(tok)) return true; // eth address
    if (/^(bc1|tb1)[a-z0-9]{20,}$/i.test(tok)) return true; // btc bech32
    if (/^[13][a-km-zA-HJ-NP-Z1-9]{24,34}$/.test(tok)) return true; // btc base58
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i.test(tok)) return true; // domain (≥2-char alpha TLD)
  }
  return false;
}

/** Strip a leading investigator verb so the objective passed to the loop is the target/direction itself
 *  ("focus on the Iranian cluster" → "the Iranian cluster"). A bare token is unchanged. */
export function objectiveFrom(raw: string): string {
  // Door A: a casual trailing "?" on an imperative ("investigate x.com?") is conversational noise, not part
  // of the objective — strip it so the run gets a clean target ("x.com"), never "x.com?".
  const t = (raw || "").trim().replace(/\?+\s*$/, "").trim();
  const m = t.match(VERB_RE);
  if (!m) return t;
  const rest = t.slice(m[0].length).replace(/^[:\s]+/, "").trim();
  return rest || t; // a lone verb ("investigate") keeps the original so the loop still has something
}
