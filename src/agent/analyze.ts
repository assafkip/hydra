// ca-analyze (INC-3): PURE helpers for the analyze pass — the LLM-generated clusters + typed
// relationships that color the graph (cap-cluster-colors). Port of investigations/analyze.py
// (_build_system / _build_prompt / _salvage_json / _extract_objects / gate_attribution). No vault,
// clock, randomness, LLM, or fetch here — the impure llm.ask lives in session.analyzeCase (the same
// pure-helpers / impure-session split synthesize.ts uses). Deterministic: same input → same output.

import type { CaseSchema, AnalysisCluster, AnalysisRelationship } from "../entity/analysis.js";
import { normalizeRel, slugRel } from "../entity/rel-vocab.js";

// PRD-B (RCA rca-discipline-evaporation-kipi-web-2026-06-23): these were thinned on port — 4096 truncated
// the typed-graph output mid-emit and an 80-rel cap dropped network edges. Restored to the original
// analyze.py floors (ANALYZE_MAX_TOKENS default 16384 — its own scar comment: 8192 already too low;
// ANALYZE_MAX_RELATIONSHIPS default 150).
export const ANALYZE_MAX_TOKENS = 16384; // bounds the one call; floor pinned by depth metric analyze-max-tokens
export const ANALYZE_MAX_RELATIONSHIPS = 150; // == analyze.py default; floor pinned by depth metric analyze-max-rels

/** One entity as presented to the model: an OPAQUE id (e0..eN) + the canonKey kept LOCALLY. The model
 *  never receives a canonKey it could fabricate to reach an unshown entity (consolidate codex D1). */
export interface PresentedEntity {
  id: string; // e0..eN
  canonKey: string; // resolved LOCALLY, never sent to the model
  label: string;
  type: string;
  role: string;
  // analyze-evidence-feed (PRD-B): RETAINED per-entity evidence text — the agent's own finding CLAIMS,
  // the zero-retention analog of analyze.py:106-113's profile dossiers (the client discards report text +
  // the AI dossier is a later Process step, so claims are the richest retained evidence at analyze time).
  // Fed so the model groups crews from EVIDENCE, not just id/label/type/role. Absent for an entity with no
  // retained claim (a pure file-ingest finding) — the prompt then omits its evidence line.
  dossier?: string;
}

// Port of analyze.py _STRONG_ATTRIBUTION + gate_attribution. Strong-attribution rel_types assert
// COMMON CONTROL / shared identity — a claim an analyst must defend. The LLM overclaims them on weak
// signal, so gate by the model's OWN confidence (deterministic, not a prompt plea):
//   low → DROP · medium → DEMOTE to co_listed · high → KEEP.
const STRONG_ATTRIBUTION = new Set([
  "same_operator", "same_actor", "common_operator", "operated_by_same", "same_controller", "same_owner",
]);
const ATTRIBUTION_DEMOTED = "co_listed";

/** The rel_type to actually write for a strong-attribution edge — or null to DROP it. Non-attribution
 *  rel_types pass through unchanged. */
export function gateAttribution(relType: string, confidence: string | null | undefined): string | null {
  if (!STRONG_ATTRIBUTION.has(relType)) return relType;
  const c = (confidence ?? "medium").trim().toLowerCase();
  if (c === "low") return null;
  if (c === "medium") return ATTRIBUTION_DEMOTED;
  return relType;
}

export function buildAnalyzeSystem(schema: CaseSchema | null): string {
  if (!schema || !schema.domain) {
    return (
      "You are an OSINT analyst building a typed entity graph. You receive entities (id, name, type, " +
      "role). 1. Add TYPED relationships (short snake_case rel_type). 2. Give each a confidence " +
      "(high|medium|low). 3. Group entities into CLUSTERS named for what they are. " +
      "Output strict JSON only. No prose. No markdown fences."
    );
  }
  return (
    "You are an OSINT analyst building a typed entity graph for a specific investigation.\n\n" +
    `CASE DOMAIN: ${schema.domain}\n${schema.summary}\n\n` +
    "You receive entities (id, name, type, role). Your job:\n" +
    "1. Add TYPED relationships between entities. Use short snake_case rel_type labels that fit THIS " +
    "domain (e.g. shills, deployed, drains_to, funded_by, same_operator, hosted_on, registered).\n" +
    "2. Give each relationship a confidence: high | medium | low.\n" +
    "3. Group entities into CLUSTERS that fit this case (a scam ring, a wallet cohort, an " +
    "infrastructure block, an affiliate network). Name them for what they ARE.\n\n" +
    "Output strict JSON only. No prose. No markdown fences."
  );
}

export function buildAnalyzePrompt(entities: PresentedEntity[], schema: CaseSchema | null): string {
  // analyze-evidence-feed (PRD-B): append the entity's RETAINED evidence text (its agent-finding claims)
  // under its line when present, so clustering reasons from evidence — the analyze.py dossier feed analog.
  const list = entities
    .map((e) => {
      const head = `${e.id}: ${e.label} [${e.type}/${e.role}]`;
      const dossier = (e.dossier ?? "").trim();
      return dossier ? `${head}\n  evidence: ${dossier}` : head;
    })
    .join("\n");
  const relHint = schema ? "a short snake_case label that fits the domain" : "a short snake_case label";
  const kinds = schema ? "ring|cohort|network|infrastructure_block|venue" : "crew|cohort|infrastructure_block|venue";
  return (
    `ENTITIES (use these ids EXACTLY — e0, e1, …; never invent an id):\n${list}\n\n` +
    'Produce JSON with this exact shape. Emit "clusters" FIRST and in full, THEN typed_relationships:\n' +
    "{\n" +
    '  "clusters": [{"name": "<name>", "kind": "' + kinds + '", "member_ids": ["e0","e1"], "description": "<one line>"}],\n' +
    '  "typed_relationships": [{"src_id": "e0", "dst_id": "e1", "rel_type": "<' + relHint + '>", "confidence": "high|medium|low", "evidence": "<one line>"}]\n' +
    "}\n\n" +
    "Rules:\n- Clusters FIRST: group entities that co-operate / co-locate / share infrastructure.\n" +
    "- Only emit typed_relationships you can justify from the evidence.\n" +
    `- Emit AT MOST ${ANALYZE_MAX_RELATIONSHIPS} typed_relationships.\n` +
    "- Use ids only from the ENTITIES list. Do not invent ids.\n" +
    "Reply with ONLY valid JSON. No prose, no fences."
  );
}

// ---- salvage parse (port of _salvage_json + _extract_objects) ----

/** Brace-match every COMPLETE {...} object inside the array named `key`. Stops at the first
 *  incomplete object (the truncation point), keeping everything before it. Port of _extract_objects. */
function extractObjects(text: string, key: string): unknown[] {
  const m = new RegExp('"' + key + '"\\s*:\\s*\\[').exec(text);
  if (!m) return [];
  let i = m.index + m[0].length;
  const n = text.length;
  const objs: unknown[] = [];
  while (i < n) {
    while (i < n && text[i] !== "{" && text[i] !== "]") i++;
    if (i >= n || text[i] === "]") break;
    const start = i;
    let depth = 0;
    let inStr = false;
    let esc = false;
    let complete = false;
    while (i < n) {
      const ch = text[i];
      if (esc) {
        esc = false;
      } else if (ch === "\\") {
        esc = true;
      } else if (ch === '"') {
        inStr = !inStr;
      } else if (!inStr) {
        if (ch === "{") depth++;
        else if (ch === "}") {
          depth--;
          if (depth === 0) {
            i++;
            complete = true;
            break;
          }
        }
      }
      i++;
    }
    if (!complete) break; // truncated mid-object → stop, keep what survived
    try {
      objs.push(JSON.parse(text.slice(start, i)));
    } catch {
      /* skip an unparseable fragment */
    }
  }
  return objs;
}

export interface AnalyzeRaw {
  clusters: unknown[];
  typed_relationships: unknown[];
}

/** Parse the analyze response; on a truncated / fence-wrapped / quote-broken response, recover whatever
 *  complete clusters / typed_relationships objects survived instead of losing the whole step. Port of
 *  _salvage_json. */
export function salvageAnalyzeJson(text: string): AnalyzeRaw {
  let s = (text ?? "").trim();
  if (s.startsWith("```")) {
    const lines = s.split("\n");
    if (lines[0].startsWith("```")) lines.shift();
    if (lines.length && lines[lines.length - 1].startsWith("```")) lines.pop();
    s = lines.join("\n").trim();
  }
  try {
    const obj = JSON.parse(s);
    if (obj && typeof obj === "object") {
      const o = obj as Record<string, unknown>;
      return {
        clusters: Array.isArray(o.clusters) ? o.clusters : [],
        typed_relationships: Array.isArray(o.typed_relationships) ? o.typed_relationships : [],
      };
    }
  } catch {
    /* fall through to brace-salvage */
  }
  return { clusters: extractObjects(s, "clusters"), typed_relationships: extractObjects(s, "typed_relationships") };
}

// ---- map the model's opaque ids back to canonKeys (the client identity) ----

function asStr(v: unknown): string {
  return typeof v === "string" ? v.trim() : "";
}

/**
 * Resolve the salvaged LLM output's opaque ids (e0..eN) to canonKeys via the presented map, dropping
 * any id NOT in the set (the model can never invent an entity — consolidate codex D1), dropping empty
 * clusters, and applying gateAttribution to every typed relationship (low strong-attribution → drop,
 * medium → co_listed). Deterministic. The output is the EXACT shape persisted in the analysis record.
 */
export function mapAnalyzeToCanonKeys(
  raw: AnalyzeRaw,
  presented: PresentedEntity[],
  allowNovel = false, // INC-4a: schema-APPROVED runs keep a clean per-case rel label; generic runs don't
): { clusters: AnalysisCluster[]; relationships: AnalysisRelationship[] } {
  const idToKey = new Map<string, string>();
  for (const e of presented) idToKey.set(e.id, e.canonKey);

  const clusters: AnalysisCluster[] = [];
  for (const c of raw.clusters) {
    if (!c || typeof c !== "object") continue;
    const cc = c as Record<string, unknown>;
    const name = asStr(cc.name);
    if (!name) continue;
    const idsRaw = Array.isArray(cc.member_ids) ? cc.member_ids : [];
    const memberKeys: string[] = [];
    for (const id of idsRaw) {
      const key = typeof id === "string" ? idToKey.get(id) : undefined;
      if (key && !memberKeys.includes(key)) memberKeys.push(key);
    }
    if (!memberKeys.length) continue; // a cluster of zero known members is noise
    clusters.push({ name, kind: asStr(cc.kind), description: asStr(cc.description), memberKeys });
  }

  const relationships: AnalysisRelationship[] = [];
  for (const r of raw.typed_relationships) {
    if (!r || typeof r !== "object") continue;
    const rr = r as Record<string, unknown>;
    const srcKey = typeof rr.src_id === "string" ? idToKey.get(rr.src_id) : undefined;
    const dstKey = typeof rr.dst_id === "string" ? idToKey.get(rr.dst_id) : undefined;
    if (!srcKey || !dstKey || srcKey === dstKey) continue; // unknown id / self-loop → drop
    const confidence = (asStr(rr.confidence) || "medium").toLowerCase();
    const evidence = asStr(rr.evidence);
    // codex S2: SLUG before gateAttribution so a strong-attribution variant ("Same Operator",
    // "same-operator") normalizes to "same_operator" and is gated by confidence — not slipped past the
    // raw-string check to later become same_operator via normalizeRel.
    const gated = gateAttribution(slugRel(rr.rel_type), confidence);
    if (!gated) continue; // evidence-free strong attribution → drop
    // INC-4a: the vocab gate runs AFTER gate_attribution (parity with analyze.py apply order) — a
    // co-occurrence flag / empty slug drops; an unknown label → linked_to (generic) or a clean schema
    // label is kept (allowNovel). No raw rel_type reaches the persisted record.
    const norm = normalizeRel(gated, evidence, allowNovel);
    if (!norm) continue;
    relationships.push({ srcKey, dstKey, relType: norm, confidence, evidence });
  }

  return { clusters, relationships };
}
