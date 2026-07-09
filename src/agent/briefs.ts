// sf-briefs: client port of investigations/briefs.py — cross-report relatedness grouping.
//
// PURE module (no vault reads, no LLM, no writes): given the case's file-ingest reports already
// extracted into ReportInput[], it computes pairwise relatedness (Jaccard over filtered per-report
// entity-key sets + shared analyze-cluster count), groups by union-find, and FORMATS each group +
// the standalone bucket as the SAME markdown the original /briefs viewer parses (briefs.html regexes).
// The per-group LLM summary is a SEPARATE seam (synthesizeGroupSummary); this module produces the
// deterministic scaffold and accepts the summary text.
//
// Kept session-free (imports only canonKey from entity/db) so it never circular-imports session.ts —
// the vault extraction (buildReportInputs) + orchestration (generateGroupBriefs) live in session.ts.

import { canonKey } from "../entity/db.js";

// Stoplist ported VERBATIM from briefs.py:42-45 — entities so generic that a shared occurrence is
// incidental, not evidence of relatedness. They never count toward Jaccard (else grouping over-fires).
export const INCIDENTAL_NAMES = new Set<string>([
  "t.me", "telegram", "https", "http", "twitter.com", "x.com",
  "youtube.com", "google.com", "facebook.com",
]);

export const DEFAULT_THRESHOLD = 0.15; // briefs.py:37

export type Verdict = "strong" | "weak" | "disjoint" | "standalone";

export interface ReportMeta {
  objective: string; // the client report identity (the file-ingest run objective) — server uses an int id
  title: string;
  ingestedAt?: string;
  sourceType?: string;
}

export interface ReportInput {
  meta: ReportMeta;
  entityKeys: Set<string>; // FILTERED canonKeys (incidental/noise/person_candidate-no-role removed)
  clusterNames: Set<string>; // analyze-cluster names whose members touch this report
}

export interface Edge {
  a: string;
  b: string;
  verdict: Verdict;
  jaccard: number;
  sharedClusters: number;
}

export interface CrossEntity {
  name: string;
  type: string;
  role: string;
  inReports: number;
}

export interface GroupContext {
  reports: ReportMeta[];
  crossEntities: CrossEntity[];
  clusters: { name: string; kind?: string; inReports: number }[];
  timeWindow: [string | null, string | null];
}

/** The three-way per-report entity filter (briefs.py:66-84), applied to raw run entities joined with
 *  their analysis-overlaid role. Returns the filtered set of canonKeys. role comes from the entityDbFor
 *  store (runEntities itself has no role) — the caller supplies it. */
export function filterReportEntities(raw: { value: string; type: string; role: string }[]): Set<string> {
  const keep = new Set<string>();
  for (const e of raw) {
    const name = (e.value || "").trim().toLowerCase();
    if (INCIDENTAL_NAMES.has(name)) continue; // generic shared surface — incidental
    if (e.type === "person_candidate" && !e.role) continue; // person_candidate with no role tag (briefs.py:46,79)
    if (e.role === "noise") continue; // role:noise (briefs.py:81)
    keep.add(canonKey(e.type, e.value));
  }
  return keep;
}

/** Pairwise relatedness — Jaccard over filtered entity sets + shared analyze-cluster count, with the
 *  EXACT verdict thresholds (briefs.py:105-130). */
export function relatedness(a: ReportInput, b: ReportInput): Edge {
  const id = (x: ReportInput) => x.meta.objective;
  if (!a.entityKeys.size || !b.entityKeys.size) {
    return { a: id(a), b: id(b), verdict: "disjoint", jaccard: 0, sharedClusters: 0 };
  }
  let overlap = 0;
  for (const k of a.entityKeys) if (b.entityKeys.has(k)) overlap++;
  const union = new Set([...a.entityKeys, ...b.entityKeys]).size;
  const jaccard = overlap / Math.max(1, union);
  let shared = 0;
  for (const c of a.clusterNames) if (b.clusterNames.has(c)) shared++;
  let verdict: Verdict;
  if (jaccard >= DEFAULT_THRESHOLD || shared >= 1) verdict = "strong";
  else if (jaccard >= 0.03) verdict = "weak";
  else verdict = "disjoint";
  return { a: id(a), b: id(b), verdict, jaccard, sharedClusters: shared };
}

/** Union-find grouping (briefs.py:133-172). The union gate is COMPOUND: verdict==='strong' AND
 *  (jaccard >= threshold OR a shared cluster) — NOT just verdict==='strong' (briefs.py:162). */
export function groupReports(reports: ReportInput[], threshold = DEFAULT_THRESHOLD): { groups: string[][]; edges: Edge[] } {
  const ids = reports.map((r) => r.meta.objective);
  const byId = new Map(reports.map((r) => [r.meta.objective, r] as const));
  const parent = new Map(ids.map((i) => [i, i] as const));
  const find = (x: string): string => {
    let cur = x;
    while (parent.get(cur) !== cur) {
      parent.set(cur, parent.get(parent.get(cur)!)!); // path compression
      cur = parent.get(cur)!;
    }
    return cur;
  };
  const union = (x: string, y: string) => {
    const rx = find(x);
    const ry = find(y);
    if (rx !== ry) parent.set(rx, ry);
  };
  const edges: Edge[] = [];
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const rel = relatedness(byId.get(ids[i])!, byId.get(ids[j])!);
      edges.push(rel);
      if (rel.verdict === "strong" && (rel.jaccard >= threshold || rel.sharedClusters >= 1)) union(ids[i], ids[j]);
    }
  }
  const groupsMap = new Map<string, string[]>();
  for (const id of ids) {
    const root = find(id);
    const arr = groupsMap.get(root) ?? [];
    arr.push(id);
    groupsMap.set(root, arr);
  }
  const groups = [...groupsMap.values()].map((g) => g.slice().sort());
  groups.sort((a, b) => b.length - a.length || a[0].localeCompare(b[0])); // largest first, then first id (briefs.py:171)
  return { groups, edges };
}

/** Per-group verdict from the in-group edges (briefs.py:227-237). */
export function verdictForGroup(groupIds: string[], edges: Edge[]): Verdict {
  if (groupIds.length === 1) return "standalone";
  const set = new Set(groupIds);
  const inGroup = edges.filter((e) => set.has(e.a) && set.has(e.b));
  if (inGroup.some((e) => e.verdict === "strong")) return "strong";
  if (inGroup.some((e) => e.verdict === "weak")) return "weak";
  return "disjoint";
}

/** Collect the LLM/format context for a group (briefs.py:177-224). crossEntities = entities in >=2 of
 *  the group's reports (role:noise excluded); clusters = analyze-clusters touching >=2 group reports;
 *  timeWindow = (min,max) ingestedAt over the group. `entities` is the case's allEntities projection. */
export function groupContext(
  groupIds: string[],
  reportsById: Map<string, ReportInput>,
  entities: { label: string; type: string; role: string; runs: string[] }[],
  clusterKinds?: Map<string, string>, // cluster name → kind, for the brief body (briefs.py emits "(kind)")
): GroupContext {
  const groupSet = new Set(groupIds);
  const reports = groupIds.map((id) => reportsById.get(id)!.meta);

  const crossEntities: CrossEntity[] = [];
  if (groupIds.length > 1) {
    for (const e of entities) {
      if (e.role === "noise") continue;
      const inReports = e.runs.filter((r) => groupSet.has(r)).length;
      if (inReports >= 2) crossEntities.push({ name: e.label, type: e.type, role: e.role, inReports });
    }
    crossEntities.sort((a, b) => b.inReports - a.inReports || a.name.localeCompare(b.name));
  }

  const clusterCounts = new Map<string, number>();
  if (groupIds.length > 1) {
    for (const id of groupIds) for (const c of reportsById.get(id)!.clusterNames) clusterCounts.set(c, (clusterCounts.get(c) ?? 0) + 1);
  }
  const clusters = [...clusterCounts.entries()]
    .filter(([, n]) => n >= 2)
    .map(([name, inReports]) => ({ name, kind: clusterKinds?.get(name), inReports }))
    .sort((a, b) => b.inReports - a.inReports)
    .slice(0, 15);

  const dates = reports.map((r) => r.ingestedAt).filter((d): d is string => !!d).sort();
  const timeWindow: [string | null, string | null] = dates.length ? [dates[0], dates[dates.length - 1]] : [null, null];

  return { reports, crossEntities: crossEntities.slice(0, 50), clusters, timeWindow };
}

// ---- markdown formatting (the viewer parses these — STRUCTURALLY faithful to briefs.py:277-336;
//      the report identity is the objective string, not the server's integer id) ----

function reportLine(m: ReportMeta): string {
  const src = m.sourceType ? ` (${m.sourceType})` : "";
  return `- ${m.title || m.objective}${src}`;
}

/** Port of _format_group_brief (briefs.py:277-320). Summary is ALWAYS followed by a `## ` section so the
 *  viewer's `## Summary\n\n…(\n\n##|$)` preview regex bounds the preview (review finding 8). */
export function formatGroupBrief(groupIdx: number, ctx: GroupContext, verdict: Verdict, summary: string): string {
  const lines: string[] = [];
  lines.push(`# Brief: group ${groupIdx}`, "");
  lines.push(`**Relatedness verdict:** ${verdict}`);
  lines.push(`**Reports in group:** ${ctx.reports.length}`);
  if (ctx.timeWindow[0]) lines.push(`**Time window:** ${ctx.timeWindow[0]} → ${ctx.timeWindow[1]}`);
  lines.push("");
  lines.push("## Reports", "");
  for (const m of ctx.reports) lines.push(reportLine(m));
  lines.push("");
  lines.push("## Summary", "");
  lines.push(summary || "(no summary)");
  lines.push("");
  if (ctx.crossEntities.length) {
    lines.push(`## Cross-cutting entities (${ctx.crossEntities.length})`, "");
    lines.push("Entities that appear in ≥2 reports in this group:", "");
    for (const e of ctx.crossEntities.slice(0, 25)) {
      lines.push(`- **${e.name}** (${e.type}/${e.role || "?"}) — in ${e.inReports} reports`);
    }
    lines.push("");
  } else {
    lines.push("## Cross-cutting entities", "");
    lines.push("None — no entity appears in more than one report in this group.", "");
  }
  if (ctx.clusters.length) {
    lines.push(`## Clusters spanning this group (${ctx.clusters.length})`, "");
    for (const c of ctx.clusters) lines.push(`- **${c.name}** (${c.kind || "?"}) — in ${c.inReports} reports`); // briefs.py:318 emits the kind
    lines.push("");
  }
  return lines.join("\n") + "\n";
}

/** Port of _format_standalone (briefs.py:323-336). One markdown blob; the viewer counts its `- ` lines. */
export function formatStandalone(orphans: { meta: ReportMeta; entityCount: number; summary: string }[]): string {
  const lines: string[] = [];
  lines.push("# Standalone reports", "");
  lines.push("These reports do NOT meet the relatedness threshold with any other ingested report. Treat each as its own case.", "");
  for (const o of orphans) {
    lines.push(`- **${o.meta.title || o.meta.objective}** (${o.entityCount} entities). ${o.summary}`);
  }
  lines.push("");
  return lines.join("\n") + "\n";
}
