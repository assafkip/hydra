// cd-tradecraft (chat-graph-parity-fixes): the analytical-tradecraft surface for the ONE chat input,
// ported from investigations/tradecraft.py. The Python webapp's chat exposed Scope / Challenge /
// Premortem GATES + Timeline / Target / Reality-check HELPERS so the analytical discipline the /q-*
// commands enforce reaches the fast chat agent. The client-side port dropped all of it — this restores
// it (founder: "the chat doesn't have the scope commands and other commands essential to the operation
// of the investigation, which we had before").
//
// 3 GATES + 3 HELPERS (founder decision 2026-06-11, ported verbatim):
//   - Scope: analyst INPUT (frame the question / hypotheses / proof) — stored, no model call.
//   - Challenge / Premortem: a bounded no-tools model pass over the case findings — stored.
//   - Timeline / Target / Reality-check: templated requests that just STEER the investigator (no gate).
// State is per-case (a `tradecraft:<step>` vault DATA key, auto case-scoped); a gate is "done" when its
// artifact exists. SOFT nudge, never a hard block — the chat stays fast.

export type TradecraftKind = "gate" | "helper";

export interface TradecraftStepDef {
  key: TradecraftStep;
  label: string;
  kind: TradecraftKind;
  icon: string;
  blurb: string;
}

export type TradecraftStep =
  | "scope"
  | "challenge"
  | "premortem"
  | "timeline"
  | "target"
  | "reality_check";

// Ported verbatim from tradecraft.py STEPS (labels, icons, blurbs).
export const TRADECRAFT_STEPS: TradecraftStepDef[] = [
  { key: "scope", label: "Scope", kind: "gate", icon: "◎",
    blurb: "Frame the question, the hypotheses, and what counts as proof." },
  { key: "challenge", label: "Challenge", kind: "gate", icon: "⚔",
    blurb: "Pressure-test the findings: name-match traps, circular reasoning, source independence, confirmation bias." },
  { key: "premortem", label: "Premortem", kind: "gate", icon: "⚑",
    blurb: "Assume the brief is wrong six months from now. What made it wrong?" },
  { key: "timeline", label: "Timeline", kind: "helper", icon: "⏱",
    blurb: "Build a chronology of the case." },
  { key: "target", label: "Target", kind: "helper", icon: "◉",
    blurb: "Profile a specific target in depth." },
  { key: "reality_check", label: "Reality check", kind: "helper", icon: "⚖",
    blurb: "Sanity-check the current picture for overreach." },
];

export const TRADECRAFT_GATE_KEYS: TradecraftStep[] = TRADECRAFT_STEPS.filter((s) => s.kind === "gate").map((s) => s.key);

// Templated chat requests for the helper buttons/commands (steer the investigator, no gate). Verbatim
// from tradecraft.py HELPER_PROMPTS. `target` takes an optional subject (bare "target" profiles the
// highest-value one, "target <x>" profiles x).
export const HELPER_PROMPTS: Record<"timeline" | "target" | "reality_check", string> = {
  timeline: "Build a chronological timeline of this case from the findings so far.",
  target: "Profile the highest-value target in this case in depth.",
  reality_check:
    "Reality-check the current picture: where am I overreaching, what is asserted beyond the evidence, and what's the weakest link?",
};

// The gate personas — ported verbatim from tradecraft.py _CHALLENGE_SYSTEM / _PREMORTEM_SYSTEM.
export const CHALLENGE_SYSTEM =
  "You are a devil's-advocate intelligence analyst. Pressure-test the case below. Be " +
  "concrete and specific to THIS evidence, not generic. Cover, with a short heading each: " +
  "1) Name-match traps (an entity tied in only by a shared name); 2) Circular reasoning / " +
  "single-source loops; 3) Source-independence failures (claims that trace back to one " +
  "origin); 4) Confirmation bias (what we assumed and never tested); 5) The single weakest " +
  "load-bearing claim. End with 'To resolve:' and 2-4 concrete checks. Keep it tight.";

export const PREMORTEM_SYSTEM =
  "You are running a PREMORTEM. Assume it is six months from now and the brief on this " +
  "case turned out to be WRONG and embarrassing. Working backward, explain what made it " +
  "wrong. Be specific to THIS evidence. Give: 1) The 3-5 most likely failure modes " +
  "(misattribution, stale infra, CDN-shared false links, an unverified identity, etc.), " +
  "each with why it would happen here; 2) Which current finding each would invalidate; " +
  "3) 'Before delivery:' a short checklist that would have caught it. Keep it tight.";

export type TradecraftCommand =
  | { kind: "scope"; question: string } // bare ⇒ open the form; question ⇒ pre-fill it
  | { kind: "gate"; step: "challenge" | "premortem" }
  | { kind: "helper"; step: "timeline" | "target" | "reality_check"; subject: string };

const REALITY_RE = /^reality[ -]?check$/;

/**
 * Parse a typed tradecraft command (with or without a leading slash), or null. Pure + node-testable.
 * Recognizes: scope [question], challenge, premortem, timeline [subject], target [subject],
 * "reality check" / "reality-check".
 */
export function parseTradecraftCommand(raw: string): TradecraftCommand | null {
  let t = (raw || "").trim();
  if (!t) return null;
  if (t.startsWith("/")) t = t.slice(1).trim(); // allow /scope, /challenge, …
  const lower = t.toLowerCase();
  const firstWord = lower.split(/\s+/)[0];
  const rest = t.slice(firstWord.length).trim();

  if (firstWord === "scope") return { kind: "scope", question: rest };
  if (firstWord === "challenge") return { kind: "gate", step: "challenge" };
  if (firstWord === "premortem") return { kind: "gate", step: "premortem" };
  if (firstWord === "timeline") return { kind: "helper", step: "timeline", subject: rest };
  if (firstWord === "target") return { kind: "helper", step: "target", subject: rest };
  if (REALITY_RE.test(lower)) return { kind: "helper", step: "reality_check", subject: "" };
  return null;
}

/** The investigator prompt a helper command sends. `target <x>` profiles x; bare helpers use the template. */
export function helperPromptFor(step: "timeline" | "target" | "reality_check", subject: string): string {
  const s = subject.trim();
  if (step === "target" && s) return `Profile ${s} in depth — infrastructure, ownership, and connections.`;
  if (step === "timeline" && s) return `Build a chronological timeline of ${s} from the findings so far.`;
  return HELPER_PROMPTS[step];
}

// ---- cd-guidance (chat-graph-parity-fixes, bug #3): walk a first-time analyst through the tool ----
// Founder: "when I interact with the chat, it says I don't know from this case yet, no findings, but it
// needs to be able to walk me through the tool and I put in the key." A help-intent question (or any
// question on an empty case) gets this walkthrough instead of a dead "I don't know" refusal.

// NARROW on purpose: only CLEARLY-meta phrasings, never a generic "what is <case-thing>" / "how do I
// <find X>". Hijacking a real case question into the tool guide would be a worse bug than the dead-end
// we are fixing — so "what is the operating domain?" / "who runs X?" stay case questions (and on an
// empty case still get the guidance no-evidence answer).
// Two tiers. Tier A — unambiguous meta openers — may be followed by more text (a longer help ask).
// Tier B — the "what …" phrasings that COLLIDE with real case questions ("what is this domain doing?",
// "what should i do about acme?") — are END-ANCHORED (codex Major): they only fire when the WHOLE input
// is the standalone meta question, so a case question that merely STARTS with those words still answers.
const HELP_INTENT_RE =
  /^(help|\?+|walk me through|guide me|get(ting)? started|i('?m| am) (new|lost|stuck)|how (do i|to) (use|start|begin)\b|how does (this|it|the tool|the app) work\b|where (do|should) (i|we) (start|begin)\b|(what is (this|it|kipi|this (tool|app|thing))|what (do i|should i) do( (here|now|first))?|what can (you|i|it|this|we) do)\s*\??$)/i;

/** True when the input reads as a help / onboarding / meta question (not a case question). Pure. */
export function isHelpIntent(raw: string): boolean {
  const t = (raw || "").trim();
  return !!t && HELP_INTENT_RE.test(t);
}

/** The deterministic tool walkthrough (no key, no model call). Markdown — rendered escape-first. */
export const TOOL_GUIDE = [
  "**Here's how this works** — you drive the whole investigation from this one box.",
  "",
  "1. **Add evidence** — go to *Reports & intake*, drop files or paste text. Then **Process** the case to extract entities and build the graph.",
  "2. **Investigate** — type `investigate <domain>` (or a wallet / IP / @handle) and the agent runs OSINT, pivots, and grows the graph.",
  "3. **Ask** — once there are findings, ask in plain language (\"who runs this domain?\"); answers cite the run they came from.",
  "",
  "**Tradecraft commands** (the analytical discipline):",
  "- `scope` — frame the question, hypotheses, and what counts as proof.",
  "- `challenge` — pressure-test the findings for name-match traps and weak sources.",
  "- `premortem` — assume the brief is wrong; find what would make it wrong.",
  "- `timeline`, `target`, `reality check` — steer the investigator.",
  "",
  "**Drive the graph**: `only domains`, `min score 50`, `search <name>`, `show all`, `fit`. See the work: `findings` or `runs`.",
  "",
  "Add your Anthropic key on *Account* (you may have already) and start with step 1, or just type `investigate <something>`.",
].join("\n");
