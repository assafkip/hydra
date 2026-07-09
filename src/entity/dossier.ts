// adr-pass: the AI-dossier pass — adapted from investigations/profile.py (the written analyst
// profile). It is GATE-FAITHFUL by construction: a NO-TOOLS synthesis grounded ONLY on the
// entity's already-gated store facts + its derived connections. The client entity DB has
// runs/counts/connections/held-reasons — NOT report snippets/pages/screenshots — so the
// persona is scoped to that evidence (codex D3): it is "model interpretation over the case's
// gated evidence", not a verbatim profile.py clone, and it cites ONLY the supplied grounding
// block. parseDossier strips any fabricated source the model invents (codex D3).
//
// PURE: no DOM, no clock, no randomness, no fetch. The LLM call lives in session.ts.

import type { Connection, EntityRecord } from "./db.js";

/** FROZEN, timestamp-free (so the persona prefix caches). Adapted from profile.py SYSTEM. */
export const AI_DOSSIER_PERSONA = [
  "You are a FAANG-tier Senior Staff Investigator (Trust & Safety / Threat Intelligence) writing",
  "a terse actor dossier for ONE entity. You receive ONLY the case's already-gated evidence about",
  "this entity below the line: its derived facts (role/type/grade/promoted/runs/sources) and its",
  "typed connections. That grounding block is the WHOLE of your evidence.",
  "",
  "EVIDENTIARY DISCIPLINE (non-negotiable):",
  "- Every claim traces to the grounding block. If you cannot point to it there, do not write it.",
  "- Separate FACT from ASSESSMENT. Label inferences with calibrated confidence (confirmed /",
  "  assessed high|medium|low / possible). Never state an inference as fact. If attribution is not",
  "  established, write 'unattributed' — do NOT guess a real identity, group, or nation-state.",
  "- Treat self-reported / registrant / shared-infra signals as trivially faked; lower confidence.",
  "- Do NOT invent entities, URLs, report names, or sources. Cite ONLY the run labels in the",
  "  grounding block. You have no web access and no tools — there is nothing to add to the evidence.",
  "- Expertise shapes INTERPRETATION, never invents content.",
  "",
  "Output a concise markdown dossier with EXACTLY these headers, no preamble, no fence:",
  "  ## Summary",
  "  ## Threat assessment",
  "  ## Key connections",
  "  ## Open questions",
  "If the evidence is thin, say so: 'Limited evidence — single mention in one run.' Do not pad.",
].join("\n");

const CONN_CAP = 40;

/** A compact, neutral grounding block. The allowed sources are EXACTLY the run objectives the
 *  entity appears in — the model is told to cite only these (codex D3). */
export function buildDossierPrompt(entity: EntityRecord, connections: Connection[]): string {
  const facts = [
    `ENTITY: ${entity.label}`,
    `TYPE: ${entity.type || "unknown"}`,
    `ROLE: ${entity.role}`,
    `STATUS: ${entity.promoted ? "promoted (on graph)" : "lead (held)"}`,
    `GRADE: ${entity.grade ?? "unknown"}`,
    `SOURCES: ${entity.sourceCount}${entity.infraSourceCount ? ` (infra ${entity.infraSourceCount})` : ""}`,
  ];
  if (!entity.promoted && entity.reasons.length) facts.push(`HELD BECAUSE: ${entity.reasons[0]}`);

  const sources = entity.runs.slice(0, 12);
  const conns = (Array.isArray(connections) ? connections : []).slice(0, CONN_CAP);
  const connLines = conns.length
    ? conns.map((c) => `  - ${c.otherLabel} (${c.otherType || c.otherRole}) — ${c.relType}, ${c.confidence}, ${c.count} run(s)`)
    : ["  (none)"];

  return [
    "--- GROUNDING (the whole of your evidence; cite ONLY the ALLOWED SOURCES) ---",
    facts.join("\n"),
    "",
    `ALLOWED SOURCES (run labels — cite only these): ${sources.length ? sources.map((s) => `"${s}"`).join(", ") : "(none)"}`,
    "",
    "TYPED CONNECTIONS:",
    connLines.join("\n"),
    "--- END GROUNDING ---",
    "",
    "Write the dossier for the ENTITY above, grounded ONLY in this block, with EXACTLY these sections:",
    "## Summary",
    "## Threat assessment",
    "## Key connections",
    "## Open questions",
  ].join("\n");
}

const SOURCE_LINE_RE = /^[ \t>*-]*\b(sources?|citations?|references?|refs?|url|link)\b\s*:.*$/gim;
const URL_RE = /\bhttps?:\/\/[^\s)>\]]+/gi;

/**
 * Normalize the model markdown + STRIP any fabricated source (codex D3): the dossier grounds
 * only on the gated DB (no URLs/report names live there), so any URL or "Source:" line the
 * model emits is invented and must not render. Strips a wrapping fence, drops source/citation
 * lines, replaces bare URLs with a placeholder, collapses blank runs, and caps the length.
 */
export function parseDossier(text: string, cap = 8000): string {
  let s = (text ?? "").trim();
  // strip a single wrapping ```markdown fence if present
  s = s.replace(/^```[a-z]*\s*\n?/i, "").replace(/\n?```\s*$/i, "").trim();
  s = s.replace(SOURCE_LINE_RE, ""); // drop fabricated "Source:/Reference:" citation lines
  s = s.replace(URL_RE, "[external link removed]"); // no real URL belongs in a DB-grounded dossier
  s = s.replace(/\n{3,}/g, "\n\n").trim();
  return s.slice(0, cap);
}
