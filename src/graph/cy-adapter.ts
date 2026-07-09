// PRD cytoscape-graph cyg-adapter: the PURE bridge from the gate-faithful client GraphModel
// (src/graph/model.ts) to Cytoscape element JSON, in investigations/webapp/templates/graph.html's
// EXACT data vocabulary. No DOM, no clock, no randomness — node-testable, byte-identical per model.
//
// Why this is the seam (locked decision): model.ts stays the data feed; cy-graph.ts owns the
// render. This adapter is the ONLY place the run-centric client model (objective / finding / lead)
// is translated into the entity-centric vocabulary graph.html's style() reads (role / shape /
// clusterColor / borderStyle / score; edge color / width / confidence). It emits ONLY honest
// client-available fields — no fake clusters, no server-only data. The `thumbnail` (favicon) is set
// for web-host nodes (founder reinstated favicons 2026-06-24, reversing the F3/D12 drop — see favicon.ts).

import type { GraphModel, GraphNode, GraphEdge } from "./model.js";
import { faviconUrl } from "./favicon.js"; // domain-node favicons (founder decision 2026-06-24 — see favicon.ts egress note)
import { gloss } from "../entity/rel-vocab.js"; // sp-ce526e44: human-readable edge label from the gated rel_type slug

// favicon eligibility: ONLY web-host entity types get a favicon face (the original PRD's {domain,url} rule,
// widened to subdomain). An email/ip/wallet/handle never triggers a favicon fetch.
const WEB_HOST_TYPES = new Set(["domain", "url", "subdomain"]);

export interface CyNodeData {
  id: string;
  label: string; // short canvas label
  full_name: string; // full value (drawer / search)
  kind: GraphNode["kind"];
  promoted: boolean;
  role: string; // graph.html role bucket (operator/channel/ioc/infra/source) | 'seed'
  sub_role?: string; // A1: operator network FUNCTION (leadership/recruiter/…) — drawer display, no shape effect
  type: string; // entity type
  surface_type: string; // = type (graph.html reads both)
  origin: string; // 'osint' (agent-discovered) | 'seed'
  shape: string;
  color: string; // role border color (data(color))
  clusterColor: string; // node fill (data(clusterColor))
  borderStyle: string; // origin border style (data(borderStyle))
  score: number; // sizing (mapData score 0..100) + the min_score filter — INC-4a: real threatScore when set
  report_count: number; // = source count
  grade?: string;
  reason?: string;
  sourceCount?: number;
  infraSourceCount?: number;
  // INC-4a graph analytics (undefined until the score/graph_metrics Process steps run) — drawer + filter
  threat_score?: number;
  degree_centrality?: number;
  betweenness?: number;
  eigenvector?: number;
  community?: number;
  // A4: the analyze cluster NAME (drives clusterColor) — exposed so the Cluster facet can filter on it
  // (the fill color alone is not a filterable handle). Empty when the node is in no analytic cluster.
  cluster?: string;
  // favicon (founder decision 2026-06-24): the Google s2 favicon URL for a domain/url node face. Set ONLY
  // for web-host types (the one deliberate egress — see favicon.ts). node[thumbnail] in cy-graph renders it.
  thumbnail?: string;
}
export interface CyEdgeData {
  id: string;
  source: string;
  target: string;
  kind: GraphEdge["kind"];
  confidence: string; // high|medium|low (graph.html confColor / width)
  color: string;
  width: number;
  lineStyle: string; // solid (promoted/typed_rel) | dotted (lead)
  rel_type: string; // INC-4a: the vocab-gated rel_type SLUG (e.g. "linked_to") — identity for tap/logic, NOT display
  rel_label: string; // sp-ce526e44: the human-readable gloss of rel_type — what the edge label actually renders
}
export interface CyElements {
  nodes: { data: CyNodeData }[];
  edges: { data: CyEdgeData }[];
}

// Type aliases — mirrors model.ts TYPE_ALIASES (D11) so ip_address≡ip, crypto_wallet≡wallet,
// hash_md5/hash_sha256≡hash dedup/style identically to the canonical graph.
const TYPE_ALIASES: Record<string, string> = {
  ip_address: "ip",
  crypto_wallet: "wallet",
  hash_md5: "hash",
  hash_sha256: "hash",
};
function canonType(entityType: string | undefined): string {
  const k = (entityType ?? "").trim().toLowerCase();
  return TYPE_ALIASES[k] ?? k;
}

// Canonical entity type -> graph.html role bucket. Unknown -> 'source' (graph.html's neutral).
const ROLE_BY_TYPE: Record<string, string> = {
  person: "operator", username: "operator", handle: "operator", operator: "operator",
  telegram_channel: "channel", channel: "channel",
  wallet: "ioc", hash: "ioc", email: "ioc", indicator: "ioc", ioc: "ioc",
  domain: "infra", ip: "infra", url: "infra", asn: "infra", host: "infra", infra: "infra",
};
export function roleFor(entityType: string | undefined): string {
  return ROLE_BY_TYPE[canonType(entityType)] ?? "source";
}

// graph.html shapeMap (reload): role -> cytoscape shape.
const SHAPE_BY_ROLE: Record<string, string> = {
  operator: "ellipse", channel: "diamond", ioc: "octagon", infra: "rectangle", source: "triangle",
};
// graph.html roleColor: role -> border color; default accent for unknown.
const ROLE_COLOR: Record<string, string> = {
  operator: "#C2410C", channel: "#7E22CE", ioc: "#B91C1C", infra: "#15803D", source: "#475569",
};
const ACCENT = "#0F766E";
const SEED_COLOR = "#7E22CE"; // _layout.html `seed`
const CLUSTER_SLATE = "#475569"; // graph.html clusterColor no-cluster fallback (a node in no analytic cluster)

// ca-analyze (INC-3): a DETERMINISTIC fill color per analytic cluster NAME. A stable FNV-1a hash →
// hue; fixed saturation/lightness keep every cluster readable on the dark canvas. Pure: the same
// cluster name always yields the same color (so a re-render never reshuffles cluster colors).
export function clusterHsl(name: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  const hue = (h >>> 0) % 360;
  return `hsl(${hue}, 65%, 50%)`; // clu-graph-node-parity: match the original graph.html clusterColor sat/lightness
}

// clu-graph-node-parity: provenance → border style, verbatim from graph.html (solid=from intake,
// dashed=detective-investigated/osint, dotted=added manually).
const BORDER_BY_ORIGIN: Record<string, string> = {
  intake: "solid",
  osint: "dashed",
  manual: "dotted",
};

// graph.html confColor: confidence -> edge color.
const CONF_COLOR: Record<string, string> = { high: "#15803D", medium: "#B45309", low: "#8A847D" };
function confColor(c: string): string {
  return CONF_COLOR[c] ?? "#57534E";
}

// A4 legend (graph.html:134-161): the node/edge ENCODING, derived FROM the same maps the renderer uses
// so the legend can never drift from the actual render. Each entry is the single source of truth — a new
// role added to SHAPE_BY_ROLE/ROLE_COLOR appears in the legend automatically (drift-checked by a test).
export interface LegendSpec {
  roles: { role: string; shape: string; color: string }[]; // role bucket → shape + border color
  origins: { origin: string; borderStyle: string }[]; // provenance → border style
  confidences: { confidence: string; color: string }[]; // edge confidence → line color
}
export function legendSpec(): LegendSpec {
  return {
    roles: [
      ...Object.keys(SHAPE_BY_ROLE).map((role) => ({
        role, shape: SHAPE_BY_ROLE[role], color: ROLE_COLOR[role] ?? ACCENT,
      })),
      // the objective/seed node is special-cased in nodeData() (not in SHAPE_BY_ROLE) — surface it so the
      // legend explains the round purple node a single-run view shows (codex: legend-vs-render drift).
      { role: "seed", shape: "round-rectangle", color: SEED_COLOR },
    ],
    origins: Object.keys(BORDER_BY_ORIGIN).map((origin) => ({ origin, borderStyle: BORDER_BY_ORIGIN[origin] })),
    confidences: Object.keys(CONF_COLOR).map((confidence) => ({ confidence, color: CONF_COLOR[confidence] })),
  };
}

// Grade -> a 0..100 score for node sizing (mapData in the style). Unknown grade -> mid.
function gradeScore(grade: string | undefined): number {
  return ({ A: 90, B: 70, C: 50, D: 30 } as Record<string, number>)[(grade ?? "").toUpperCase()] ?? 40;
}

// Node label shortening (UX 2026-06-24, node-graph-prd-audit). The original graph.html shortLabel
// just dropped the scheme + trailing slash then BLIND-sliced at 26 — so a long URL kept its noisy
// path/query and a long domain got its TLD cut off, making the graph read as a mess. The fix is
// IDENTITY-PRESERVING: for a url/domain the HOST is what the analyst recognises, so we strip the
// scheme/www/query/fragment and ellipsize the PATH (never the host); a host that is itself too long
// gets a middle-ellipsis that keeps the head + the registrable tail. A wallet/hash gets a
// middle-ellipsis (0x5290…69ee7 — the standard crypto display, showing the distinctive tail).
const LABEL_MAX = 26;

// keep head + tail, total length === max (hashes, wallets, over-long hosts)
function middleEllipsis(s: string, max: number): string {
  if (s.length <= max) return s;
  const keep = max - 1; // room for the …
  const head = Math.ceil(keep / 2);
  const tail = Math.floor(keep / 2);
  return s.slice(0, head) + "…" + s.slice(s.length - tail);
}

export function shortLabel(val: string | undefined, entityType?: string): string {
  let s = String(val ?? "").replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  const t = (entityType ?? "").toLowerCase();
  // url / domain: the host is the identity — strip www + query/fragment noise, never blind-cut the host.
  if (t === "url" || t === "domain" || t === "subdomain" || s.includes("/") || /^www\./i.test(s)) {
    s = s.replace(/^www\./i, "").split("?")[0].split("#")[0].replace(/\/+$/, "");
    if (s.length <= LABEL_MAX) return s;
    const slash = s.indexOf("/");
    const host = slash === -1 ? s : s.slice(0, slash);
    if (host.length >= LABEL_MAX) return middleEllipsis(host, LABEL_MAX); // host alone too long → keep head + TLD
    return host + "/…"; // host fits; the path is the overflow → collapse it to one marker
  }
  // wallet / hash / long hex (tx ids, addresses): middle-ellipsis surfaces the distinctive tail.
  if (t === "wallet" || t === "crypto_wallet" || t === "hash" || t === "tx" || /^(0x)?[0-9a-f]{20,}$/i.test(s)) {
    return middleEllipsis(s, LABEL_MAX);
  }
  // everything else (email, handle, name…): end-ellipsis (the original behavior).
  if (s.length > LABEL_MAX) s = s.slice(0, LABEL_MAX - 1) + "…";
  return s;
}

// Deterministic stable edge id (D10) so repeated grow() calls dedup/update instead of duplicating.
// INC-4a: a typed_rel edge includes its rel_type so two different relations between the same pair stay
// distinct edges (and never collide with the objective→entity spoke edge).
export function edgeId(edge: GraphEdge): string {
  const rel = edge.relType ? `__${edge.relType}` : "";
  return `e:${edge.from}__${edge.to}__${edge.kind}${rel}`;
}

// graph.html-style edge width by confidence (a stronger edge reads heavier).
function confWidth(c: string): number {
  return ({ high: 2.5, medium: 1.8, low: 1 } as Record<string, number>)[c] ?? 1.5;
}

function nodeData(node: GraphNode): CyNodeData {
  const full = node.label ?? "";
  if (node.kind === "objective") {
    // The run's seed: distinct from any entity. Purple fill + border, big, solid, round.
    return {
      id: node.id, label: shortLabel(full), full_name: full, kind: "objective", promoted: false,
      role: "seed", type: "objective", surface_type: "objective", origin: "seed",
      shape: "round-rectangle", color: SEED_COLOR, clusterColor: SEED_COLOR, borderStyle: "solid",
      score: 100, report_count: 0,
    };
  }
  const role = node.role ?? roleFor(node.entityType); // ca-core D1: an analyst role correction wins over the derived role
  return {
    id: node.id,
    label: shortLabel(full, node.entityType), // type-aware: preserve host for url/domain, middle-ellipsis for wallet/hash
    full_name: full,
    kind: node.kind,
    promoted: node.promoted,
    role,
    sub_role: node.subRole, // A1: present on operator nodes the AI classified; drawer shows the network function
    type: node.entityType ?? "",
    surface_type: node.entityType ?? "",
    // clu-graph-node-parity: real provenance (intake from a report vs osint agent-discovered), driving the
    // border style like the original — NOT hardcoded. Unknown → osint (the agent-run default).
    origin: node.origin ?? "osint",
    shape: SHAPE_BY_ROLE[role] ?? "ellipse",
    color: ROLE_COLOR[role] ?? ACCENT,
    clusterColor: node.cluster ? clusterHsl(node.cluster) : CLUSTER_SLATE, // ca-analyze: real cluster fill
    borderStyle: BORDER_BY_ORIGIN[node.origin ?? "osint"] ?? "dashed",
    // INC-4a: size by the REAL threat score when scored (it also drives the min_score filter), else the
    // grade proxy. threatScore is raw (can exceed 100) — mapData clamps sizing; the filter compares raw.
    score: node.threatScore ?? gradeScore(node.grade),
    report_count: node.sourceCount ?? 0,
    grade: node.grade,
    reason: node.reason,
    sourceCount: node.sourceCount,
    infraSourceCount: node.infraSourceCount,
    threat_score: node.threatScore,
    degree_centrality: node.degreeCentrality,
    betweenness: node.betweenness,
    eigenvector: node.eigenvector,
    community: node.community,
    cluster: node.cluster ?? "", // A4: analyze cluster name for the Cluster facet
    // favicon: ONLY web-host types (domain/url/subdomain) — an email/wallet/handle must never trigger a fetch.
    // faviconUrl returns null for a dotless/unusable host, so a bad value draws no thumbnail (graceful).
    // kweb-live-graph (keep-all): ONLY a CONFIRMED domain (promoted finding) or an INTAKE seed gets a
    // favicon. An osint-discovered LEAD domain (a live dead-end the analyst hasn't confirmed) draws no
    // favicon — so the dig never leaks an un-confirmed discovered domain to Google, and osint dead-ends read
    // visually distinct from confirmed nodes (the live-real-graph-build "osint-origin" distinction).
    thumbnail:
      (node.promoted || node.origin === "intake") && WEB_HOST_TYPES.has((node.entityType ?? "").toLowerCase())
        ? (faviconUrl(full) ?? undefined)
        : undefined,
  };
}

function edgeData(edge: GraphEdge): CyEdgeData {
  if (edge.kind === "typed_rel") {
    // INC-4a: a semantic entity↔entity edge — confidence-styled, labeled with the gated rel_type.
    const confidence = edge.confidence || "medium";
    return {
      id: edgeId(edge), source: edge.from, target: edge.to, kind: "typed_rel",
      confidence, color: confColor(confidence), width: confWidth(confidence), lineStyle: "solid",
      rel_type: edge.relType ?? "",
      rel_label: gloss(edge.relType ?? ""), // sp-ce526e44: render the human gloss, not the raw slug
    };
  }
  if (edge.kind === "co_occurs" || edge.kind === "linked") {
    // clu-graph-topology: the entity↔entity NETWORK edges. Undirected, subtle — they make the graph read
    // as a web. linked (explicit cross-edge) reads a touch heavier/solid; co_occurs is a faint dotted tie.
    const linked = edge.kind === "linked";
    return {
      id: edgeId(edge), source: edge.from, target: edge.to, kind: edge.kind,
      confidence: edge.confidence || "low",
      color: linked ? "#78716C" : "#A8A29E",
      width: linked ? 1.6 : 1,
      lineStyle: linked ? "solid" : "dotted",
      rel_type: "",
      rel_label: "",
    };
  }
  const promoted = edge.kind === "promoted";
  const confidence = promoted ? "high" : "low";
  return {
    id: edgeId(edge),
    source: edge.from,
    target: edge.to,
    kind: edge.kind,
    confidence,
    color: confColor(confidence),
    width: promoted ? 2.5 : 1,
    lineStyle: promoted ? "solid" : "dotted",
    rel_type: "",
    rel_label: "",
  };
}

/**
 * Map a client GraphModel to Cytoscape element JSON. Pure + deterministic: two calls on the same
 * model produce byte-identical output. A hostile entity value stays a literal data string (the
 * caller renders labels as Cytoscape canvas text / via textContent — never innerHTML).
 */
export function modelToElements(model: GraphModel | null | undefined): CyElements {
  const nodes = Array.isArray(model?.nodes) ? model!.nodes : [];
  const edges = Array.isArray(model?.edges) ? model!.edges : [];
  const ids = new Set(nodes.map((n) => n.id));
  return {
    nodes: nodes.map((n) => ({ data: nodeData(n) })),
    // Drop any edge whose endpoints are not both present (cytoscape throws on a dangling edge).
    edges: edges.filter((e) => ids.has(e.from) && ids.has(e.to)).map((e) => ({ data: edgeData(e) })),
  };
}
