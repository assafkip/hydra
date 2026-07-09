// adr-pass: the semantic typed-relations pass — ported from investigations/analyze.py
// (the LLM typing job + gate_attribution). The model RE-LABELS an entity's already-gated
// connections with a semantic rel_type; it CANNOT invent an edge. Gate-faithful by
// construction (the cardinal sin is a fabricated relation):
//  - REL_TYPES is a HARD allowlist (codex D1): a label outside it (after synonym folding)
//    normalizes to the weak 'linked' — never rendered raw.
//  - synonyms canonicalize BEFORE the attribution gate (codex D1) so a synonym
//    ("shared_operator", "common_control", "same_registrant", …) cannot bypass the gate by
//    asserting common control under a different spelling.
//  - strong-attribution labels run analyze.py's deterministic confidence gate: low → DROP,
//    medium → DEMOTE to co_listed, high → KEEP. The label can never outrun its evidence.
//  - each proposal is keyed by a STABLE connection id (codex D2), derived from the owner ref
//    + the other ref + the derived relType + the direction — NOT a list index — so a
//    reordered / filtered / capped connection list can never mis-attach a label to the wrong edge.
//
// PURE: no DOM, no clock, no randomness, no fetch. The LLM call lives in session.ts.

import type { Connection, EntityRef } from "./db.js";

export type Confidence = "high" | "medium" | "low";

/** The canonical semantic vocabulary — a HARD allowlist (codex D1). Ported from analyze.py's
 *  REL_TYPES + the schema-driven crypto/infra labels (shills/deployed/drains_to/funded_by/…).
 *  A model label outside this set (after synonym folding) normalizes to 'linked'. */
export const REL_TYPES: readonly string[] = [
  // strong-attribution (subject to the confidence gate)
  "same_operator", "same_actor", "common_operator", "operated_by_same", "same_controller", "same_owner",
  // infrastructure
  "hosts", "hosted_on", "resolves_to", "registered_by", "registrant", "uses", "same_infrastructure",
  // control / ownership
  "operates", "controls", "owns", "member_of", "predecessor_of",
  // crypto-fraud
  "drains_to", "funded_by", "transacts_with", "shills", "deployed",
  // social / generic
  "posts_in", "ally_with", "targets", "defaced", "co_admin",
  // demotion / fallback
  "co_listed", "co_occurs", "linked",
];
const REL_SET = new Set(REL_TYPES);

/** analyze.py::_STRONG_ATTRIBUTION — labels that assert COMMON CONTROL / shared identity, an
 *  analyst-defensible claim. The model overclaims them on weak signal, so they are gated. */
export const STRONG_ATTRIBUTION = new Set([
  "same_operator", "same_actor", "common_operator", "operated_by_same", "same_controller", "same_owner",
]);
export const ATTRIBUTION_DEMOTED = "co_listed";

/** Synonym folding (codex D1). The attribution aliases all fold onto `same_operator` so a
 *  shared-control claim under any spelling is gated; non-attribution variants canonicalize
 *  spelling. Anything not foldable + not in the allowlist becomes 'linked' in canonRelType. */
const REL_SYNONYMS: Record<string, string> = {
  // attribution bypass aliases -> the gated canonical label
  shared_operator: "same_operator",
  common_control: "same_operator",
  common_controller: "same_operator",
  controlled_by_same: "same_operator",
  same_wallet_owner: "same_operator",
  same_registrant: "same_operator",
  same_infrastructure_operator: "same_operator",
  shared_owner: "same_owner",
  shared_controller: "same_controller",
  // non-attribution spelling variants
  hosted_by: "hosted_on",
  hosts_on: "hosted_on",
  resolves: "resolves_to",
  points_to: "resolves_to",
  registered: "registered_by",
  registers: "registered_by",
  transacts: "transacts_with",
  drains: "drains_to",
  funds: "funded_by",
  shilled_by: "shills",
  deploys: "deployed",
};

const SNAKE_RE = /[^a-z0-9_]+/g;

/** Normalize a raw model label: lowercase + snake-collapse, fold synonyms, then keep only an
 *  allowlisted label; anything else -> 'linked' (codex D1 — never render a raw unknown label). */
export function canonRelType(raw: string | undefined): string {
  const base = (raw ?? "").trim().toLowerCase().replace(SNAKE_RE, "_").replace(/^_+|_+$/g, "");
  if (!base) return "linked";
  const folded = REL_SYNONYMS[base] ?? base;
  return REL_SET.has(folded) ? folded : "linked";
}

/** analyze.py::gate_attribution — for a strong-attribution label, gate by the model's OWN
 *  confidence: low -> null (DROP), medium -> co_listed (DEMOTE), high -> keep. Non-attribution
 *  labels pass through unchanged. Returns the label to render, or null to drop. */
export function gateAttribution(relType: string, confidence: Confidence | string | undefined): string | null {
  if (!STRONG_ATTRIBUTION.has(relType)) return relType;
  const c = (confidence ?? "medium").toString().trim().toLowerCase();
  if (c === "low") return null;
  if (c === "medium") return ATTRIBUTION_DEMOTED;
  return relType;
}

/** A STABLE id for a connection (codex D2): owner ref + other ref + derived relType + direction.
 *  Deterministic + delimiter-safe (a JSON tuple), so a reordered list never mis-attaches. */
export function connId(ownerRef: EntityRef, conn: Connection): string {
  return JSON.stringify([
    ownerRef.type, ownerRef.value,
    conn.other.type, conn.other.value,
    conn.relType, conn.direction,
  ]);
}

function normConf(c: string | undefined): Confidence {
  const v = (c ?? "").toString().trim().toLowerCase();
  return v === "high" || v === "medium" || v === "low" ? v : "medium";
}

export interface SemanticRelation {
  cid: string;
  relType: string;
  confidence: Confidence;
  evidence: string;
}

/** A short, neutral description of a connection for the prompt (the model decides the type;
 *  this only tells it which two entities are connected). */
function describeConn(ownerLabel: string, conn: Connection): string {
  return `${ownerLabel} ↔ ${conn.otherLabel} (${conn.otherType || conn.otherRole})`;
}

/**
 * Build the typing prompt. Each ENTITY↔ENTITY connection (co_occurs / linked — the
 * surfaced_in-to-objective edges are excluded, they are not inter-entity relations) is
 * presented with its stable cid; the model assigns each a semantic rel_type + confidence.
 * It is told it may ONLY label the listed connections and pick a single best type.
 */
export function buildRelationsPrompt(ownerRef: EntityRef, ownerLabel: string, connections: Connection[]): string {
  const rel = relatableConnections(connections);
  const lines = rel.map((c) => `  {"cid": ${JSON.stringify(connId(ownerRef, c))}, "pair": ${JSON.stringify(describeConn(ownerLabel, c))}}`);
  return [
    `Entity: ${ownerLabel}`,
    "",
    "You are an OSINT analyst assigning a TYPED relationship to each existing connection below.",
    "These connections are ALREADY established. You may ONLY label them — never invent a new",
    "connection, entity, or source. Pick the single best short snake_case rel_type that states",
    "the actual relationship, and a confidence: high | medium | low.",
    "",
    "Strong-attribution types (same_operator / same_owner / common control) assert shared control —",
    "use them ONLY with strong, multi-signal evidence; otherwise prefer a weaker, defensible type.",
    "",
    "CONNECTIONS (label each by its cid):",
    "[",
    lines.join(",\n"),
    "]",
    "",
    "Output STRICT JSON only, no prose, no markdown fence:",
    '{"relations": [{"cid": "<one of the cids above>", "rel_type": "<snake_case>", "confidence": "high|medium|low", "evidence": "<one short line>"}]}',
    "Skip a connection if no clear type fits. Use a cid only from the list above.",
  ].join("\n");
}

/** The connections the typing pass operates on: entity↔entity only (co_occurs / linked). The
 *  surfaced_in edge points at the run's objective endpoint, not another entity. */
export function relatableConnections(connections: Connection[]): Connection[] {
  return (Array.isArray(connections) ? connections : []).filter((c) => c && c.relType !== "surfaced_in");
}

function extractJsonObject(text: string): unknown {
  // Take the LAST balanced {...} block (the model may prefix reasoning). Mirrors the loop's
  // strict trailing-JSON extraction — a truncated/garbage response yields zero relations.
  const s = (text ?? "").trim();
  const end = s.lastIndexOf("}");
  if (end < 0) return null;
  let depth = 0;
  for (let i = end; i >= 0; i--) {
    const ch = s[i];
    if (ch === "}") depth++;
    else if (ch === "{") {
      depth--;
      if (depth === 0) {
        try {
          return JSON.parse(s.slice(i, end + 1));
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

/**
 * Parse the model's relations against the entity's REAL connections. Every gate:
 *  - resolve `cid` against the live connection set; an unknown cid is DROPPED (codex D2).
 *  - canonRelType folds synonyms + allowlists (codex D1) — never a raw unknown label.
 *  - gateAttribution drops a low-confidence strong-attribution claim, demotes a medium one.
 * Returns one SemanticRelation per surviving, validated proposal.
 */
export function parseSemanticRelations(ownerRef: EntityRef, text: string, connections: Connection[]): SemanticRelation[] {
  const parsed = extractJsonObject(text) as { relations?: unknown } | null;
  const rows = parsed && Array.isArray(parsed.relations) ? parsed.relations : [];
  const validCids = new Set(relatableConnections(connections).map((c) => connId(ownerRef, c)));
  const seen = new Set<string>();
  const out: SemanticRelation[] = [];
  for (const r of rows) {
    if (!r || typeof r !== "object") continue;
    const cid = (r as Record<string, unknown>).cid;
    if (typeof cid !== "string" || !validCids.has(cid) || seen.has(cid)) continue; // unknown/dup cid -> drop (D2)
    const confidence = normConf((r as Record<string, unknown>).confidence as string);
    const canon = canonRelType((r as Record<string, unknown>).rel_type as string);
    const gated = gateAttribution(canon, confidence); // strong-attribution confidence gate (D1)
    if (gated === null) continue; // low-confidence attribution -> drop
    const evidenceRaw = (r as Record<string, unknown>).evidence;
    seen.add(cid);
    out.push({ cid, relType: gated, confidence, evidence: typeof evidenceRaw === "string" ? evidenceRaw.slice(0, 200) : "" });
  }
  return out;
}
