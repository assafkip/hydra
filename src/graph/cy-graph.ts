// PRD cytoscape-graph cyg-render-wire: the real Cytoscape clone of
// investigations/webapp/templates/graph.html's graph render, BUNDLED (no CDN — leak F1).
// The sole graph renderer (the interim own-SVG renderer was deleted in the cleanup chunk); fed by the gate-faithful client model via
// src/graph/cy-adapter.ts. The style() array + _layoutOpts() are ported verbatim from
// graph.html so the canvas is visually identical; the interactions are the subset the client
// model can drive (a few node-drawer actions — the properties table / per-entity page — are not yet built client-side).
//
// Security/scar notes:
//  - ONE deliberate egress: data(thumbnail) is a domain favicon the browser fetches from Google
//    (founder decision 2026-06-24, reversing the F3 drop — see src/graph/favicon.ts + the CSP img-src
//    allow). It exposes a case domain to Google for an icon; no case content, key, or finding leaves.
//  - Labels are Cytoscape data() rendered as CANVAS text, never innerHTML — a hostile entity is
//    literal text. DOM surfaces (drawer/menu/chip) that show entity values live in app.ts and use
//    textContent (D9).
//  - grow() updates existing element data() IN PLACE and adds new nodes at a free slot near their
//    anchor with NO relayout/refit (D1, the ride-along "grow not re-pop" lesson). Ported from
//    graph.html growGraph()/freeSpot()/_anchorFor()/_visibleObstacles()/_placeAndReveal().

import cytoscape, { type Core, type NodeSingular, type Position } from "cytoscape";
import dagre from "cytoscape-dagre";
import fcose from "cytoscape-fcose";
import expandCollapse from "cytoscape-expand-collapse";
import { modelToElements, type CyNodeData } from "./cy-adapter.js";
import type { GraphModel } from "./model.js";
import { cappedZoom } from "./zoom.js";
import { GraphSurface } from "./surface.js"; // Light Table bench: the panning grid + ruler ticks behind the graph

// Register the extensions once per page. cytoscape.use() throws if a name is already
// registered (re-import under HMR), so each is guarded — a failure just disables that option.
let DAGRE_REG = false, FCOSE_REG = false, EC_REG = false;
try { cytoscape.use(dagre as never); DAGRE_REG = true; } catch { DAGRE_REG = false; }
try { cytoscape.use(fcose as never); FCOSE_REG = true; } catch { FCOSE_REG = false; }
try { cytoscape.use(expandCollapse as never); EC_REG = true; } catch { EC_REG = false; }

export interface SetMember { id: string; name: string; }
export interface GraphStats { nodes: number; edges: number; }

export interface CyGraphCallbacks {
  onSelectNode(data: CyNodeData): void;
  onBackground(): void;
  onSetChange(set: SetMember[]): void;
  onMenu?(data: CyNodeData, clientX: number, clientY: number): void;
  onStats?(stats: GraphStats): void;
  onEdgeTap?(data: { src_id: string; dst_id: string; src_name: string; dst_name: string; rel_type: string }): void;
}

const COLLECTION_MIN = 15;

export class CyGraph {
  readonly cy: Core;
  layoutName = "cose";
  dagreOk = false;
  fcoseOk = false;
  collectionsOk = false;
  pathMode = false;
  pathSource: string | null = null;
  selectedSet: SetMember[] = [];
  private ec: { collapse(e: unknown): void; expand(e: unknown): void } | null = null;
  private cb: CyGraphCallbacks;
  private spreadBusy = false;
  private spineFocusOn = false; // G2a: "Focus threats" — dim every non-promoted node so the spine pops
  private surface: GraphSurface | null = null; // Light Table bench (grid + ruler ticks)
  private themeHandler = (): void => this.applyTheme(); // re-style the canvas on light↔dark toggle

  constructor(container: HTMLElement, cb: CyGraphCallbacks) {
    this.cb = cb;
    this.cy = cytoscape({
      container,
      style: this.style(),
      // multi-select (founder 2026-07-03): the GROUP is cytoscape's NATIVE selection. additive = clicking a
      // node adds/removes it from the group (no modifier needed), and shift+drag rubber-bands a box over many.
      // Both paths set :selected → the `select`/`unselect` listeners mirror it into selectedSet. boxSelection
      // stays ON (its shift-drag is the box); we no longer intercept clicks, so nothing hijacks the gesture.
      selectionType: "additive",
      boxSelectionEnabled: true,
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 4,
    });
    // Feature-checks (graph.html pattern): an unavailable layout/extension hides its option,
    // never blanks the canvas.
    try { this.dagreOk = DAGRE_REG && !!this.cy.layout({ name: "dagre" } as never); } catch { this.dagreOk = false; }
    try { this.fcoseOk = FCOSE_REG && !!this.cy.layout({ name: "fcose" } as never); } catch { this.fcoseOk = false; }
    try {
      // cytoscape-expand-collapse augments Core with expandCollapse() at runtime; @types
      // doesn't know it, so reach it via a local cast (the d.ts stays a pure ambient script).
      const cyEC = this.cy as Core & { expandCollapse?(opts?: Record<string, unknown>): { collapse(e: unknown): void; expand(e: unknown): void } };
      this.collectionsOk = EC_REG && typeof cyEC.expandCollapse === "function";
      if (this.collectionsOk && cyEC.expandCollapse) {
        this.ec = cyEC.expandCollapse({
          layoutBy: null, animate: false, undoable: false, fisheye: false,
          edgeTypeInfo: () => "meta", groupEdgesOfSameTypeOnCollapse: true,
        });
      }
    } catch { this.collectionsOk = false; }
    this.bindEvents();
    // Light Table: lay the graph on the bench (grid + ruler ticks that pan/zoom with it) and re-style
    // the whole canvas when the theme toggles.
    try { this.surface = new GraphSurface(container, this.cy); } catch { this.surface = null; }
    try { window.addEventListener("kipi-theme", this.themeHandler); } catch { /* no window in a headless import */ }
  }

  // Re-read the [data-theme] tokens and repaint the canvas + bench (light↔dark toggle).
  private applyTheme(): void {
    this.cy.style(this.style() as never);
    this.surface?.themeChanged();
  }

  // ----- LIGHT TABLE style() (Hydra redesign 2026-07-06). The calm ink-and-light bench: role color IS
  // the node fill; leads (unconfirmed) render faint + dotted; operators wear a soft halo (the people the
  // web is about); size reads BROKER importance (betweenness centrality, score fallback); edges are ink,
  // weighted + dashed by confidence. Theme-aware — every color is read from the live [data-theme] tokens
  // (src/styles/app.css) so light↔dark re-styles the whole canvas. The cy-adapter's node.data (shape/
  // color/clusterColor/borderStyle/label/score) is UNTOUCHED, so the parity harness stays byte-identical;
  // the redesign lives entirely in this render layer. Every class the interaction logic toggles
  // (selected/neighbor/dimmed/frontier/off-spine/facet-match/in-set/path-*/just-added/hidden) is preserved.
  private tk(): {
    label: string; labelOutline: string; edge: string; edgeStrong: string; ring: string; lead: string;
    accent: string; accentInk: string; muted: string; faint: string; err: string; seed: string;
    role: { operator: string; channel: string; ioc: string; infra: string; source: string };
  } {
    // Headless (node test / parity runner) has no getComputedStyle — fall back to the built-in defaults so
    // CyGraph still instantiates; the real browser reads the live [data-theme] tokens.
    const cs = (typeof getComputedStyle !== "undefined" && typeof document !== "undefined")
      ? getComputedStyle(document.documentElement)
      : null;
    // v(): a token that already holds a cytoscape-parseable color (hex, or a comma-rgba literal).
    const v = (n: string, f: string): string => { const x = cs?.getPropertyValue(n).trim() ?? ""; return x || f; };
    // rgbc(): read a --c-* RGB TRIPLET ("194 65 12") and format it COMMA-separated ("rgb(194, 65, 12)").
    // Critical: the triplet-backed semantic vars compute to SPACE-separated rgb() ("rgb(194 65 12)"), which
    // cytoscape's color parser REJECTS — it silently falls back to its default #999 grey (the monochrome bug
    // that made every role look the same). Reading the raw triplet and re-joining with commas fixes it.
    const rgbc = (n: string, f: string): string => {
      const x = cs?.getPropertyValue(n).trim() ?? "";
      const p = x.split(/\s+/).filter(Boolean);
      return p.length >= 3 ? `rgb(${p[0]}, ${p[1]}, ${p[2]})` : f;
    };
    return {
      label: v("--node-label", "#1A1A19"),
      labelOutline: v("--node-label-outline", "#FBF9F4"),
      edge: v("--edge", "rgba(46,40,30,.42)"),
      edgeStrong: v("--edge-strong", "rgba(30,26,18,.62)"),
      ring: v("--node-ring", "rgba(26,22,16,.30)"),
      lead: v("--node-lead", "rgba(160,150,128,.55)"),
      accent: rgbc("--c-accent", "#0F766E"),
      accentInk: rgbc("--c-accent-ink", "#0B4F49"),
      muted: rgbc("--c-ink-muted", "#5B554B"),
      faint: rgbc("--c-ink-faint", "#6B655E"),
      err: rgbc("--c-sev-high", "#B91C1C"),
      seed: rgbc("--c-seed", "#7E22CE"),
      role: {
        operator: rgbc("--c-role-operator", "#C2410C"),
        channel: rgbc("--c-role-channel", "#7E22CE"),
        ioc: rgbc("--c-role-ioc", "#B91C1C"),
        infra: rgbc("--c-role-infra", "#15803D"),
        source: rgbc("--c-role-source", "#475569"),
      },
    };
  }

  // Node size = broker importance. Betweenness centrality (0..1) maps 26..66 so the brokers read biggest;
  // an un-scored graph (metrics not yet run) falls back to the grade/threat score so nodes are never 0-sized.
  private static nodeSize(ele: NodeSingular): number {
    const d = ele.data() as { betweenness?: number; score?: number };
    const clamp = (x: number): number => (x < 0 ? 0 : x > 1 ? 1 : x);
    const base = typeof d.betweenness === "number" ? clamp(d.betweenness) : clamp((d.score ?? 40) / 100);
    return 26 + base * 40;
  }

  private style(): cytoscape.Stylesheet[] {
    const t = this.tk();
    const size = (ele: NodeSingular): number => CyGraph.nodeSize(ele);
    return [
      { selector: "node", style: {
        "background-color": t.role.source, // role selectors below set the real fill; this is the neutral fallback
        "background-opacity": 1,
        "label": "data(label)",
        "color": t.label,
        "font-size": "mapData(score, 0, 100, 8, 13)",
        "font-family": "Inter, sans-serif",
        "font-weight": 500,
        "text-margin-y": -10,
        "text-outline-color": t.labelOutline,
        "text-outline-width": 2.5,
        "width": size as never,
        "height": size as never,
        "border-width": 1.5,
        "border-color": t.ring, // Light Table: a soft ring, not a loud role border — the FILL carries role
        "border-style": "data(borderStyle)", // provenance: solid=intake / dashed=osint / dotted=manual
        "shape": "data(shape)",
      } },
      // role -> node FILL (theme-aware; the calm bench colors). The adapter still emits data(color) for parity.
      { selector: "node[role = 'operator']", style: { "background-color": t.role.operator } },
      { selector: "node[role = 'channel']", style: { "background-color": t.role.channel } },
      { selector: "node[role = 'ioc']", style: { "background-color": t.role.ioc } },
      { selector: "node[role = 'infra']", style: { "background-color": t.role.infra } },
      { selector: "node[role = 'source']", style: { "background-color": t.role.source } },
      { selector: "node[role = 'seed']", style: { "background-color": t.seed } },
      // operator -> a soft figure glow: the people the web is about get a faint warm pool so the eye finds
      // them (a wide, low-opacity underlay reads as a glow, not a highlight box).
      { selector: "node[role = 'operator']", style: { "underlay-color": t.role.operator, "underlay-opacity": 0.07, "underlay-padding": 22 } },
      // ux (brief §Home #1): the objective/query node is SUBORDINATE to its findings — smallest + muted.
      { selector: "node[kind = 'objective']", style: { "font-size": 8, "color": t.muted, "font-weight": 400, "background-opacity": 1 } },
      // leads (collected != confirmed): faint fill + dotted ring + muted label until a finding promotes them.
      // Excludes the objective/seed (always solid), favicon nodes, and collections (own styling below).
      { selector: "node[!promoted][kind != 'objective'][!thumbnail][!isCollection]", style: {
        "background-opacity": 0.22, "border-style": "dotted", "border-color": t.lead, "color": t.muted,
      } },
      { selector: "node[?is_bridge]", style: { "border-width": 4, "border-style": "double", "border-color": t.edgeStrong } },
      { selector: "node[thumbnail]", style: {
        "background-image": "data(thumbnail)", "background-fit": "cover", "background-opacity": 1,
        // favicon (2026-06-24): "null" = load WITHOUT a CORS request. Google's gstatic favicon sends no
        // Access-Control-Allow-Origin, so "anonymous" would block the canvas draw. No-CORS loads + displays;
        // it taints the canvas, which is harmless here (the app never calls toDataURL/cy.png — verified).
        "background-image-crossorigin": "null", "border-width": 2,
      } },
      { selector: "node[?isCollection]", style: {
        "background-color": t.labelOutline, "background-opacity": 0.5, "border-width": 1.5,
        "border-style": "dashed", "border-color": t.lead, "label": "data(label)",
        "font-size": 10, "color": t.muted, "text-valign": "top", "shape": "round-rectangle",
      } },
      { selector: "node.cy-expand-collapse-collapsed-node", style: {
        "background-color": t.lead, "background-opacity": 0.4, "border-width": 2, "border-style": "double",
        "border-color": t.muted, "width": 46, "height": 46, "shape": "round-rectangle", "font-weight": 600,
      } },
      { selector: "node.selected", style: { "border-width": 3, "border-color": t.accent } },
      { selector: "node.neighbor", style: { "underlay-color": t.accent, "underlay-opacity": 0.28, "underlay-padding": 6 } },
      { selector: "node.dimmed", style: { "opacity": 0.15 } },
      // ux-frontier: an isolated node with a connected core present is an un-investigated "frontier" lead —
      // de-emphasized but still visible + clickable, so the eye lands on the web (markFrontier()).
      { selector: "node.frontier", style: { "opacity": 0.5 } },
      // G2a "Focus threats": recede every node that is NOT a promoted finding so the threat SPINE pops.
      { selector: "node.off-spine", style: { "opacity": 0.12 } },
      { selector: "edge.off-spine", style: { "opacity": 0.05 } },
      { selector: ".hidden", style: { "display": "none" } },
      { selector: "node.facet-match", style: {
        "underlay-color": t.accentInk, "underlay-opacity": 0.30, "underlay-padding": 7, "font-weight": "bold", "z-index": 900,
      } },
      { selector: "node.in-set", style: {
        "underlay-color": t.seed, "underlay-opacity": 0.30, "underlay-padding": 7,
        "border-width": 3, "border-color": t.seed, "z-index": 910,
      } },
      // edges are INK on the bench — weight + dash carry confidence, not color (calm, not rainbow).
      { selector: "edge", style: {
        "curve-style": "bezier",
        "line-color": t.edge,
        "line-style": "data(lineStyle)", // held-lead edges stay dotted (adapter)
        "target-arrow-color": t.edge,
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.8,
        "width": "data(width)",
        "label": "data(rel_label)", // sp-ce526e44: render the human gloss, not the raw rel_type slug
        "font-size": 9,
        "font-family": "Inter, sans-serif",
        "color": t.muted,
        "text-rotation": "autorotate",
        "text-background-color": t.labelOutline,
        "text-background-opacity": 0.85,
        "text-background-padding": 2,
      } },
      // confidence -> ink weight: high reads as stronger ink; low is a faint dashed tie.
      { selector: "edge[confidence = 'high']", style: { "line-color": t.edgeStrong, "target-arrow-color": t.edgeStrong } },
      { selector: "edge[confidence = 'low']", style: { "line-style": "dashed" } },
      // the ALERT edges keep their tint — the exception that pops on the calm bench (broker / cross-cluster).
      { selector: "edge[?bridge_edge]", style: { "line-color": t.role.operator, "target-arrow-color": t.role.operator, "width": 2.5, "opacity": 0.95 } },
      { selector: "edge[?cross_cluster]", style: { "line-color": t.err, "target-arrow-color": t.err, "line-style": "dashed", "width": 3, "opacity": 1 } },
      { selector: "edge[?co_occurrence]", style: {
        "line-color": t.lead, "line-style": "dotted", "target-arrow-shape": "none",
        "width": 1, "opacity": 0.4, "label": "", "curve-style": "haystack",
      } },
      { selector: "edge[kind = 'co_occurs']", style: {
        "line-color": t.lead, "line-style": "dotted", "target-arrow-shape": "none",
        "width": 1, "opacity": 0.5, "label": "", "curve-style": "bezier",
      } },
      { selector: "edge[kind = 'linked']", style: {
        "line-color": t.edge, "target-arrow-shape": "none",
        "width": 1.6, "opacity": 0.8, "label": "", "curve-style": "bezier",
      } },
      { selector: "edge.selected", style: { "line-color": t.accent, "target-arrow-color": t.accent, "width": 3.5, "opacity": 1, "z-index": 999 } },
      { selector: "edge.edge-out", style: { "line-color": t.role.operator, "target-arrow-color": t.role.operator, "width": 3, "opacity": 1, "z-index": 950 } },
      { selector: "edge.edge-in", style: { "line-color": t.accentInk, "target-arrow-color": t.accentInk, "width": 3, "opacity": 1, "z-index": 950 } },
      { selector: "edge.dimmed", style: { "opacity": 0.1 } },
      { selector: ".path-dim", style: { "opacity": 0.12 } },
      { selector: "node.path-highlight", style: { "border-width": 3, "border-color": t.accent, "opacity": 1, "z-index": 998 } },
      { selector: "edge.path-highlight", style: { "line-color": t.accent, "target-arrow-color": t.accent, "width": 4, "opacity": 1, "z-index": 998, "line-style": "solid" } },
      { selector: "node.path-endpoint", style: { "border-width": 4, "border-color": t.role.infra, "opacity": 1, "z-index": 999 } },
      // F9: a halo on nodes a dig JUST added, so the change is visible in a dense graph. Cleared after ~3s.
      { selector: "node.just-added", style: { "underlay-color": t.accent, "underlay-opacity": 0.55, "underlay-padding": 8, "border-width": 4, "border-color": t.accent, "opacity": 1, "z-index": 1000 } },
    ] as cytoscape.Stylesheet[];
  }

  // ----- graph.html _layoutOpts() — the layout switcher. -----
  private layoutOpts(): Record<string, unknown> {
    const base = { animate: "end", animationDuration: 600, fit: true, padding: 50 };
    if (this.layoutName === "fcose" && this.fcoseOk)
      return { name: "fcose", quality: "default", randomize: true, idealEdgeLength: 110, nodeRepulsion: 8000, nodeDimensionsIncludeLabels: true, ...base };
    if (this.layoutName === "dagre" && this.dagreOk)
      return { name: "dagre", rankDir: "TB", nodeSep: 40, rankSep: 90, ...base };
    if (this.layoutName === "concentric") {
      const ego = this.egoNode();
      const depths = this.hopDepths(ego);
      let maxD = 1;
      for (const k in depths) if (depths[k] > maxD) maxD = depths[k];
      return {
        name: "concentric", minNodeSpacing: 28, ...base,
        concentric: (n: NodeSingular) => maxD + 1 - (depths[n.id()] !== undefined ? depths[n.id()] : maxD + 1),
        levelWidth: () => 1,
      };
    }
    if (this.layoutName === "circle") return { name: "circle", ...base };
    return { name: "cose", randomize: true, idealEdgeLength: 110, nodeRepulsion: 8000, nodeDimensionsIncludeLabels: true, ...base };
  }

  private egoNode(): NodeSingular | undefined {
    const sel = this.cy.nodes(".selected");
    if (sel.length) return sel[0];
    const max = this.cy.nodes().max((n) => n.degree(false));
    return max.ele as NodeSingular | undefined;
  }
  private hopDepths(ego: NodeSingular | undefined): Record<string, number> {
    const depths: Record<string, number> = {};
    if (!ego || !ego.length) return depths;
    this.cy.elements().bfs({ roots: ego, directed: false, visit: (v, _e, _u, _i, depth) => { depths[v.id()] = depth; } });
    return depths;
  }

  // ----- render a fresh model (a new top-level run replaces the graph). -----
  render(model: GraphModel): void {
    const { nodes, edges } = modelToElements(model);
    this.clearPath();
    this.selectedSet = [];
    this.cb.onSetChange([]);
    this.cy.elements().remove();
    this.cy.add(nodes);
    this.cy.add(edges);
    this.buildCollections();
    if (this.cy.nodes().length > 0) {
      const opts = (this.layoutName === "cose" || this.layoutName === "fcose")
        ? Object.assign(this.layoutOpts(), { idealEdgeLength: 150, nodeRepulsion: 16000, gravity: 0.25 })
        : this.layoutOpts();
      opts.stop = () => this.frame(); // clu-graph-topology: fit AND cap zoom ≤1.1 (a raw fit on a few nodes
      this.cy.layout(opts as never).run(); // zoomed to ~3x → giant blob nodes; frame() is the capped fit.
    }
    this.markFrontier();
    this.emitStats();
  }

  // ----- grow IN PLACE (D1): add new elements at a free slot, refresh changed existing data,
  // NO relayout, NO refit. Ported from graph.html growGraph(). -----
  grow(model: GraphModel, fromId: string): void {
    const { nodes, edges } = modelToElements(model);
    const newNodes: NodeSingular[] = [];
    for (const n of nodes) {
      const ex = this.cy.getElementById(n.data.id);
      if (ex.length) { ex.data(n.data); continue; } // update in place — keep position (an upgraded lead->finding restyles)
      newNodes.push(this.cy.add({ group: "nodes", data: n.data, position: { x: 0, y: 0 } }) as NodeSingular);
    }
    for (const e of edges) {
      const ex = this.cy.getElementById(e.data.id);
      if (ex.length) { ex.data(e.data); continue; }
      if (!this.cy.getElementById(e.data.source).length || !this.cy.getElementById(e.data.target).length) continue;
      this.cy.add({ group: "edges", data: e.data });
    }
    if (newNodes.length) {
      const obstacles = this.visibleObstacles();
      for (const node of newNodes) {
        const anchor = this.anchorFor(node.id(), edges, fromId);
        const pos = this.freeSpot(anchor.x, anchor.y, 40, obstacles);
        this.placeAndReveal(node, pos);
        obstacles.push({ x: pos.x, y: pos.y, r: 20 });
      }
      this.flashNewNodes(newNodes); // F9: highlight + pan to what just appeared
    }
    this.markFrontier();
    this.applySpineFocus(this.spineFocusOn); // G2a: re-derive the spine dim so newly-dug nodes recede too
    this.emitStats();
    // grow in place: existing positions + viewport untouched (no relayout / no refit).
  }

  // F9 (video-review 2026-06-25): ring the nodes a dig just added so the change is visible in a dense graph
  // ("dig one hop… I don't know what it does"). The ring clears after ~3s. Deliberately does NOT move the
  // viewport — grow is "in place" (existing positions + pan/zoom untouched, enforced by graph-interactive.spec);
  // new nodes are placed next to their anchor (the just-dug node, already on-screen), so the ring is seen
  // without yanking the analyst's view. No-op when nothing new was added.
  private flashNewNodes(nodes: NodeSingular[]): void {
    if (!nodes.length) return;
    const coll = this.cy.collection(nodes);
    coll.addClass("just-added");
    setTimeout(() => coll.removeClass("just-added"), 3000);
  }

  // ----- ux-frontier (discovery-grow Option 3): when a connected core exists, mark the isolated
  // (degree-0) nodes as "frontier" so they read as un-investigated leads (dimmed but visible + clickable)
  // and the eye lands on the web. When NO node is connected (a fresh file-only intake graph), keep every
  // node full-weight — there is no core to favor, and the founder must still see every lonely dot to scan
  // it for an OSINT call. Idempotent: clears + recomputes from the current edge topology. -----
  private markFrontier(): void {
    this.cy.nodes().removeClass("frontier");
    const anyConnected = this.cy.nodes().some((n) => (n as NodeSingular).degree(false) > 0);
    if (anyConnected) this.cy.nodes().filter((n) => (n as NodeSingular).degree(false) === 0).addClass("frontier");
  }

  // ----- freeSpot placement helpers (ported verbatim from graph.html). -----
  private freeSpot(ax: number, ay: number, size: number, obstacles: { x: number; y: number; r: number }[]): Position {
    const obs = obstacles || this.visibleObstacles();
    const half = size / 2;
    for (let ring = 0; ring < 14; ring++) {
      const rad = 90 + ring * 52;
      const steps = 8 + ring * 2;
      for (let s = 0; s < steps; s++) {
        const a = (2 * Math.PI * s) / steps + ring * 0.5;
        const x = ax + rad * Math.cos(a), y = ay + rad * Math.sin(a);
        let ok = true;
        for (let i = 0; i < obs.length; i++) {
          const o = obs[i], need = o.r + half + 16;
          if ((o.x - x) * (o.x - x) + (o.y - y) * (o.y - y) < need * need) { ok = false; break; }
        }
        if (ok) return { x, y };
      }
    }
    const rad = 90 + 14 * 52;
    const a = (2 * Math.PI * (obs.length % 16)) / 16;
    return { x: ax + rad * Math.cos(a), y: ay + rad * Math.sin(a) };
  }
  private visibleObstacles(): { x: number; y: number; r: number }[] {
    return this.cy.nodes(":visible").map((n) => { const p = n.position(); return { x: p.x, y: p.y, r: n.width() / 2 }; });
  }
  private anchorFor(id: string, edges: { data: { source: string; target: string } }[], fromId: string): Position {
    const parent = this.cy.getElementById(fromId);
    if (parent.length) return parent.position();
    for (const e of edges) {
      const ed = e.data;
      if (ed.source !== id && ed.target !== id) continue;
      const otherId = ed.source === id ? ed.target : ed.source;
      const other = this.cy.getElementById(otherId);
      if (other.length) return other.position();
    }
    const nodes = this.cy.nodes(":visible");
    if (!nodes.length) return { x: 0, y: 0 };
    const bb = nodes.boundingBox();
    return { x: (bb.x1 + bb.x2) / 2, y: (bb.y1 + bb.y2) / 2 };
  }
  private placeAndReveal(node: NodeSingular, pos: Position): void {
    node.position(pos);
    node.style({ opacity: 0 } as never);
    node.animate({ style: { opacity: 1 } } as never, { duration: 340, easing: "ease-out-cubic" } as never);
  }

  // ----- collection folding (port; feature-checked; only fires on >=15 same-type leaves). -----
  private buildCollections(): void {
    if (!this.collectionsOk || !this.ec) return;
    const made: string[] = [];
    this.cy.nodes("[!isCollection]").forEach((hub) => {
      if (hub.isChild()) return;
      const byType: Record<string, NodeSingular[]> = {};
      hub.connectedEdges().connectedNodes().forEach((n) => {
        if (n.id() === hub.id() || n.isChild() || n.degree(false) !== 1) return;
        const t = (n.data("type") as string) || "node";
        (byType[t] = byType[t] || []).push(n as NodeSingular);
      });
      for (const [type, kids] of Object.entries(byType)) {
        if (kids.length < COLLECTION_MIN) continue;
        const pid = `grp-${hub.id()}-${type}`;
        if (this.cy.getElementById(pid).length) continue;
        this.cy.add({ group: "nodes", data: {
          id: pid, isCollection: true, label: `${kids.length} ${type}s`,
          full_name: `${kids.length} ${type}s via ${hub.data("label") || hub.id()}`,
          type, surface_type: type, origin: kids[0].data("origin") || "intake", role: "",
        } });
        kids.forEach((n) => n.move({ parent: pid }));
        made.push(pid);
      }
    });
    if (made.length && this.ec) this.ec.collapse(this.cy.nodes(made.map((id) => `#${CSS.escape(id)}`).join(", ")));
  }

  // ----- interactions. -----
  private bindEvents(): void {
    // multi-select (founder 2026-07-03): shift/ctrl-click and shift+drag-box are driven by cytoscape's
    // NATIVE selection (additive selectionType) — the old custom tap-shift branch never fired because
    // box-select intercepts a shift+click before a node `tap` is emitted (repro: set stayed empty). Mirror
    // cy's `:selected` into selectedSet on every select/unselect so the group forms reliably for BOTH gestures.
    this.cy.on("select unselect", "node", () => this.syncGroupFromSelection());
    // Multi-select gestures (founder 2026-07-03): SHIFT is cytoscape's box-drag modifier (rubber-band a box
    // over many nodes), so a shift+CLICK would go to box-select and REPLACE — it can't accumulate. Cmd/Ctrl
    // is free, so Cmd/Ctrl+click TOGGLES one node into the group (fires a real node tap, then we set native
    // :selected → the select/unselect listeners sync the group). A plain tap is the deictic focus.
    this.cy.on("tap", "node", (evt) => {
      const oe = (evt.originalEvent || {}) as MouseEvent;
      const node = evt.target as NodeSingular;
      if (oe.metaKey || oe.ctrlKey) {
        if (node.data("isCollection") || node.hasClass("cy-expand-collapse-collapsed-node")) return;
        if (node.selected()) node.unselect(); else node.select();
        return;
      }
      this.onNodeTap(node);
    });
    this.cy.container()?.addEventListener("contextmenu", (e) => e.preventDefault());
    this.cy.on("cxttap", "node", (evt) => {
      const node = evt.target as NodeSingular;
      if (this.pathMode || node.data("isCollection") || node.hasClass("cy-expand-collapse-collapsed-node")) return;
      this.onNodeTap(node);
      const oe = (evt.originalEvent || {}) as MouseEvent;
      this.cb.onMenu?.(node.data() as CyNodeData, oe.clientX || 120, oe.clientY || 120);
    });
    // box-drag selection is now native: cytoscape sets :selected on the boxed nodes, which fires `select`
    // → syncGroupFromSelection. (The old boxend unselect wiped the box selection immediately — the bug that
    // made box-select not persist.)
    // Edge tap → open the connection as a card in the chat (cd-ui: graph → chat, __kipiChat.showEdge).
    // Emits the source/target NODE IDS (ed-wire D1) so edgeView can resolve canonical endpoints
    // via lastGraphModel — a display value alone is ambiguous after dedup/alias folding.
    this.cy.on("tap", "edge", (evt) => {
      const e = evt.target as cytoscape.EdgeSingular;
      const s = this.cy.getElementById(e.data("source") as string);
      const t = this.cy.getElementById(e.data("target") as string);
      this.cb.onEdgeTap?.({
        src_id: s.id(),
        dst_id: t.id(),
        src_name: (s.data("full_name") as string) || s.id(),
        dst_name: (t.data("full_name") as string) || t.id(),
        rel_type: (e.data("rel_type") as string) || "",
      });
    });
    this.cy.on("tap", (evt) => {
      if (evt.target === this.cy) {
        const oe = (evt.originalEvent || {}) as MouseEvent;
        if (oe.shiftKey || oe.metaKey || oe.ctrlKey) return; // mid multi-select: a modifier-click on empty space keeps the group
        this.cy.nodes(":selected").unselect(); // clear the multi-select group on a plain background click
        this.cy.elements().removeClass("selected neighbor dimmed facet-match edge-in edge-out in-set");
        this.applySpineFocus(this.spineFocusOn); // G2a: a tap on empty space restores the spine dim
        this.clearPath();
        this.cb.onBackground();
      }
    });
  }

  private onNodeTap(node: NodeSingular): void {
    if (this.pathMode) { this.pathTap(node); return; }
    if (this.collectionsOk && this.ec && node.hasClass("cy-expand-collapse-collapsed-node")) {
      this.ec.expand(node);
      this.spreadAndFit();
      this.emitStats();
      return;
    }
    if (node.data("isCollection")) return;
    // highlight the tapped node (deictic focus). It does NOT touch native :selected — that IS the group,
    // managed by additive click + shift-drag box via the select/unselect listeners.
    this.cy.elements().removeClass("selected neighbor dimmed edge-in edge-out");
    node.addClass("selected");
    node.outgoers("edge").addClass("edge-out"); // D5: own-edge direction tint from topology
    node.incomers("edge").addClass("edge-in");
    // G2a: a node the analyst TAPPED (+ its immediate web) is always fully visible, even under Focus-threats —
    // they pointed at it on purpose. The dim is re-derived on a background tap (clearSelectionSpine).
    if (this.spineFocusOn) node.closedNeighborhood().removeClass("off-spine");
    this.cb.onSelectNode(node.data() as CyNodeData);
  }

  // Drive the same selection path the smoke / a chat-name-click uses (no canvas hit-test needed).
  selectById(id: string): boolean {
    const n = this.cy.getElementById(id);
    if (!n.length) return false;
    this.onNodeTap(n as NodeSingular);
    return true;
  }

  // Drive the SAME group-toggle the shift/ctrl-click tap path uses, by node id (no canvas hit-test). The
  // event path is proven to detect the modifier; this seam lets a smoke exercise the toggle+sync directly.
  toggleGroupNode(id: string): boolean {
    const n = this.cy.getElementById(id);
    if (!n.length || n.data("isCollection") || n.hasClass("cy-expand-collapse-collapsed-node")) return false;
    if ((n as NodeSingular).selected()) (n as NodeSingular).unselect();
    else (n as NodeSingular).select();
    return true;
  }
  // multi-select: rebuild the group from cytoscape's native :selected (the reliable signal for shift-click
  // AND ctrl/cmd-click). Skips group/collection pseudo-nodes. Mirrors :selected as the `in-set` visual and
  // emits the set to app.ts (renderSetChip). Deictic "current node" is owned separately by onNodeTap.
  private syncGroupFromSelection(): void {
    const sel = this.cy.nodes(":selected").filter((n) => {
      const nm = (n.data("full_name") as string) || (n.data("label") as string) || n.id();
      return !nm.startsWith("grp-") && !n.data("isCollection") && !n.hasClass("cy-expand-collapse-collapsed-node");
    });
    this.cy.nodes(".in-set").removeClass("in-set");
    sel.addClass("in-set");
    this.selectedSet = sel.map((n) => ({ id: n.id(), name: (n.data("full_name") as string) || (n.data("label") as string) || n.id() }));
    this.cb.onSetChange(this.selectedSet.slice());
  }
  clearSelection(): void {
    this.cy.nodes(":selected").unselect(); // fires unselect → syncGroupFromSelection → empty group
    this.cy.nodes(".in-set").removeClass("in-set");
    if (this.selectedSet.length) { this.selectedSet = []; this.cb.onSetChange([]); }
  }

  // Spotlight (focus a node's web): dim the rest, light the node + neighbours + its edges.
  spotlightNode(id: string): void {
    const n = this.cy.getElementById(id);
    if (!n.length) return;
    this.cy.elements().removeClass("facet-match");
    this.cy.elements().addClass("dimmed");
    n.closedNeighborhood().removeClass("dimmed");
    n.connectedEdges().removeClass("dimmed");
  }

  // Search by name → spotlight matches (exact wins; else substring). Returns a status message.
  searchNode(query: string): { hits: number; msg: string } {
    const q = (query || "").trim().toLowerCase();
    if (!q) { this.clearSearch(); return { hits: 0, msg: "" }; }
    const all = this.cy.nodes();
    const exact = all.filter((n) => ((n.data("full_name") as string) || "").toLowerCase() === q);
    const hits = exact.length ? exact : all.filter((n) => ((n.data("full_name") as string) || "").toLowerCase().includes(q));
    this.cy.elements().removeClass("dimmed facet-match selected neighbor");
    if (!hits.length) return { hits: 0, msg: `no node named "${query.trim()}" on the graph` };
    this.cy.elements().addClass("dimmed");
    hits.removeClass("dimmed").addClass("facet-match");
    hits.connectedEdges().removeClass("dimmed");
    this.cy.animate({ fit: { eles: hits, padding: 90 } } as never, { duration: 400 } as never);
    if (hits.length === 1) { this.onNodeTap(hits[0] as NodeSingular); hits.addClass("facet-match"); return { hits: 1, msg: "" }; }
    return { hits: hits.length, msg: `${hits.length} matches highlighted` };
  }
  clearSearch(): void { this.cy.elements().removeClass("dimmed facet-match"); }

  // Typed-command filter (cd-ui): dim nodes that don't match an entity type and/or a min score,
  // light the matches + their edges. etype canonicalization mirrors the adapter's TYPE_ALIASES
  // (ip_address≡ip, crypto_wallet≡wallet, hash_*≡hash) so "only wallets" matches a crypto_wallet
  // node. A filter that matches NOTHING is a no-op (it un-dims) rather than blanking the canvas.
  applyFilter(filter: { etype?: string; minScore?: number; role?: string; origin?: string; cluster?: string }): void {
    const canon = (t: string): string =>
      ({ ip_address: "ip", crypto_wallet: "wallet", hash_md5: "hash", hash_sha256: "hash" } as Record<string, string>)[
        (t || "").trim().toLowerCase()
      ] ?? (t || "").trim().toLowerCase();
    const wantType = filter.etype ? canon(filter.etype) : null;
    const minScore = typeof filter.minScore === "number" ? filter.minScore : null;
    // A4 (graph.html:67-109): role / origin / cluster facets, alongside the existing type + minScore.
    // Matched on the same node.data the adapter emits (role/origin/cluster) — exact, case-insensitive.
    const wantRole = filter.role ? filter.role.trim().toLowerCase() : null;
    const wantOrigin = filter.origin ? filter.origin.trim().toLowerCase() : null;
    const wantCluster = filter.cluster ? filter.cluster.trim().toLowerCase() : null;
    const nodes = this.cy.nodes("[!isCollection]");
    const hits = nodes.filter((n) => {
      if (wantType && canon((n.data("type") as string) || "") !== wantType) return false;
      if (minScore !== null && Number(n.data("score") ?? 0) < minScore) return false;
      if (wantRole && String(n.data("role") ?? "").trim().toLowerCase() !== wantRole) return false;
      if (wantOrigin && String(n.data("origin") ?? "").trim().toLowerCase() !== wantOrigin) return false;
      if (wantCluster && String(n.data("cluster") ?? "").trim().toLowerCase() !== wantCluster) return false;
      return true;
    });
    this.cy.elements().removeClass("facet-match");
    if (!hits.length) { this.cy.elements().removeClass("dimmed"); return; } // no match → show all, never blank
    this.cy.elements().addClass("dimmed");
    hits.removeClass("dimmed").addClass("facet-match");
    hits.connectedEdges().removeClass("dimmed");
  }
  clearFilter(): void { this.cy.elements().removeClass("dimmed facet-match"); }

  // A4 visibility toggles (graph.html:112-131): a real HIDE (display:none), not a dim — "hide unconnected
  // junk" / "only nodes in a cluster" / co-occurrence edges on/off. showAll clears every hide+dim. The
  // original re-queried the server (reload()); the web is client-side, so this hides cytoscape elements.
  setVisibility(modes: { meaningfulOnly?: boolean; inClusterOnly?: boolean; coOccurrence?: boolean; showAll?: boolean }): void {
    if (modes.showAll) {
      this.cy.elements().removeClass("hidden dimmed facet-match");
      return;
    }
    this.cy.nodes("[!isCollection]").forEach((n) => {
      let hide = false;
      if (modes.meaningfulOnly && n.degree(false) === 0) hide = true; // an unconnected node = junk
      if (modes.inClusterOnly && !String(n.data("cluster") ?? "").trim()) hide = true;
      n.toggleClass("hidden", hide);
    });
    // co-occurrence edges (kind co_occurs) shown only when the toggle is on (default off = a cleaner web).
    this.cy.edges('[kind = "co_occurs"]').toggleClass("hidden", !modes.coOccurrence);
  }

  // G2a (video-review 2026-06-25): "Focus threats" — toggle the spine-focus dim. Public entry; the toolbar
  // toggle + hydrateCaseGraph (default ON) call this, and grow()/tap re-derive from this.spineFocusOn.
  setSpineFocus(on: boolean): void {
    this.spineFocusOn = on;
    this.applySpineFocus(on);
  }

  // G2a test seam: how many nodes are currently receded (off-spine) — lets a smoke prove the dim applies +
  // clears, without reaching into cytoscape internals.
  offSpineCount(): number {
    return this.cy.nodes(".off-spine").length;
  }

  // Recede every node that is NOT a promoted finding (+ any edge not BETWEEN two promoted nodes) so the
  // threat spine reads in ~3s. NON-DESTRUCTIVE: only adds/removes the off-spine class — keep-all DATA is
  // untouched. No-op + cleared when the case has no promoted node (dimming all = a blank graph; honest
  // fallback to the full view). isCollection (a collapsed cluster) is never receded.
  private applySpineFocus(on: boolean): void {
    const nodes = this.cy.nodes("[!isCollection]");
    const promoted = nodes.filter((n) => !!n.data("promoted"));
    if (!on || promoted.length === 0) {
      this.cy.elements().removeClass("off-spine");
      return;
    }
    promoted.removeClass("off-spine");
    nodes.difference(promoted).addClass("off-spine");
    // an edge stays lit only when BOTH endpoints are promoted (a finding-to-finding link); else it recedes.
    this.cy.edges().forEach((e) => {
      const lit = !!e.source().data("promoted") && !!e.target().data("promoted");
      e.toggleClass("off-spine", !lit);
    });
  }

  // A4: the role / origin / cluster facet OPTIONS with counts, read from the live graph (graph.html
  // roleFacet/originFacet/clusters). Only values actually present become options — no empty selects.
  getFacets(): { roles: { key: string; n: number }[]; origins: { key: string; n: number }[]; clusters: { key: string; n: number }[] } {
    const tally = (field: string): { key: string; n: number }[] => {
      const counts = new Map<string, number>();
      this.cy.nodes("[!isCollection]").forEach((n) => {
        const v = String(n.data(field) ?? "").trim();
        if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
      });
      return [...counts.entries()].map(([key, n]) => ({ key, n })).sort((a, b) => b.n - a.n || a.key.localeCompare(b.key));
    };
    return { roles: tally("role"), origins: tally("origin"), clusters: tally("cluster") };
  }

  // showDirection — computed from CYTOSCAPE TOPOLOGY (D5), not server detail.connections.
  showDirection(dir: "in" | "out" | "all"): void {
    const sel = this.cy.nodes(".selected");
    if (!sel.length) return;
    const node = sel[0];
    const neighbors = dir === "in" ? node.incomers("node") : dir === "out" ? node.outgoers("node") : node.openNeighborhood("node");
    let keep = node.union(neighbors);
    this.cy.elements().addClass("dimmed");
    keep.removeClass("dimmed");
    keep.edgesWith(keep).removeClass("dimmed");
    node.connectedEdges().removeClass("dimmed");
    this.cy.animate({ fit: { eles: keep, padding: 70 } } as never, { duration: 400 } as never);
  }

  // Shortest-path mode: pick two nodes, highlight the path (Dijkstra over visible, undirected).
  togglePathMode(): boolean { this.pathMode = !this.pathMode; this.clearPath(false); return this.pathMode; }
  clearPath(disarm = true): void {
    this.cy.elements().removeClass("path-highlight path-dim path-endpoint");
    this.pathSource = null;
    if (disarm) this.pathMode = false;
  }
  private pathTap(node: NodeSingular): string {
    if (!this.pathSource) {
      this.pathSource = node.id();
      this.cy.elements().removeClass("path-highlight path-dim path-endpoint");
      node.addClass("path-endpoint");
      return `source: ${node.data("label") || node.id()} — pick the target…`;
    }
    const src = this.cy.getElementById(this.pathSource);
    if (node.id() === this.pathSource) return "";
    const dij = this.cy.elements(":visible").dijkstra({ root: src, directed: false });
    const path = dij.pathTo(node);
    this.cy.elements().removeClass("path-highlight path-dim path-endpoint");
    if (!path || !path.length || dij.distanceTo(node) === Infinity) { this.pathSource = null; return "no path between those two nodes"; }
    path.addClass("path-highlight");
    src.union(node).addClass("path-endpoint");
    this.cy.elements().difference(path).addClass("path-dim");
    const hops = path.edges().length;
    this.pathSource = null;
    return `${hops} hop${hops === 1 ? "" : "s"} — esc clears`;
  }

  private spreadAndFit(): void {
    if (this.spreadBusy || !this.cy.nodes().length) { this.frame(); return; }
    this.spreadBusy = true;
    const opts = Object.assign(this.layoutOpts(), { fit: false, stop: () => { this.spreadBusy = false; this.frame(); } });
    this.cy.layout(opts as never).run();
  }
  private frame(): void {
    if (!this.cy.nodes().length) return;
    this.cy.fit(undefined, 70);
    const z = this.cy.zoom();
    const capped = cappedZoom(z); // clu-graph-fit-cap: single zoom-cap guard (no giant blobs)
    if (capped !== z) this.cy.zoom({ level: capped, renderedPosition: { x: this.cy.width() / 2, y: this.cy.height() / 2 } });
  }

  setLayout(name: string): void { this.layoutName = name; this.reLayout(); }
  reLayout(): void { this.cy.layout(this.layoutOpts() as never).run(); }
  // clu-graph-fit-cap: route the public Fit (toolbar button + chat `fit`) through the SAME capped path
  // as render()'s frame(), so a sparse graph never zooms past the giant-blob threshold.
  fit(): void { this.frame(); }
  resize(): void { this.cy.resize(); }

  stats(): GraphStats {
    return {
      nodes: this.cy.nodes("[!isCollection]").length,
      edges: this.cy.edges().length,
    };
  }
  private emitStats(): void { this.cb.onStats?.(this.stats()); }

  // Hooks the Playwright proof reads (deterministic, JSON-serializable).
  counts(): { nodes: number; edges: number } {
    return { nodes: this.cy.nodes("[!isCollection]").length, edges: this.cy.edges().length };
  }
  // How many nodes a typed filter/search dimmed — the cd-smoke proof that a chat command
  // actually drove the canvas (not just posted an aside).
  dimmedCount(): number {
    return this.cy.nodes(".dimmed").length;
  }
  positions(): Record<string, { x: number; y: number }> {
    const out: Record<string, { x: number; y: number }> = {};
    this.cy.nodes().forEach((n) => { const p = n.position(); out[n.id()] = { x: p.x, y: p.y }; });
    return out;
  }
  viewport(): { zoom: number; pan: Position } { return { zoom: this.cy.zoom(), pan: this.cy.pan() }; }
  // The node's position in rendered (on-screen, relative to the canvas) pixels — the drag proof
  // computes a screen coordinate from this to drive a real Playwright mouse drag.
  renderedPos(id: string): { x: number; y: number } | null {
    const n = this.cy.getElementById(id);
    return n.length ? n.renderedPosition() : null;
  }
  // Center the camera on a node (keeps it in the viewport) — the drag proof centers first so
  // the node's rendered position is guaranteed on-canvas before driving a real mouse drag.
  centerOn(id: string): void {
    const n = this.cy.getElementById(id);
    if (n.length) this.cy.center(n);
  }

  destroy(): void {
    try { window.removeEventListener("kipi-theme", this.themeHandler); } catch { /* no window */ }
    this.surface?.destroy();
    this.surface = null;
    this.cy.destroy();
  }
}
