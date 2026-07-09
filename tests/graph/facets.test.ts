import { describe, it, expect, beforeEach } from "vitest";
import { CyGraph } from "../../src/graph/cy-graph.js";
import { legendSpec } from "../../src/graph/cy-adapter.js";

// A4 (graph.html:67-161): the facet filters, visibility toggles, and the legend. The render itself is
// proven by the browser smoke; here we prove the FILTER LOGIC (data matching) + the legend drift-check
// against a HEADLESS cytoscape Core (undefined container → cytoscape runs headless) — no canvas needed,
// the methods only touch node.data + classes/style.

const CB = {
  onNodeTap: () => {}, onEdgeTap: () => {}, onBackgroundTap: () => {}, onStats: () => {},
  onSelectionChange: () => {}, onNodeRightClick: () => {},
} as unknown as ConstructorParameters<typeof CyGraph>[1];

function mkGraph(): CyGraph {
  // headless: no DOM container (this repo has no jsdom; the render is covered by the browser smoke).
  const g = new CyGraph(undefined as unknown as HTMLElement, CB);
  // a small case: two operators (one clustered, one intake), one infra leaf, one isolated node.
  g.cy.add([
    { data: { id: "n1", label: "fiffa.com", full_name: "fiffa.com", type: "domain", role: "operator", origin: "osint", cluster: "Spoofs", score: 80 } },
    { data: { id: "n2", label: "fifa.com", full_name: "fifa.com", type: "domain", role: "infra", origin: "intake", cluster: "", score: 40 } },
    { data: { id: "n3", label: "@crew", full_name: "@crew", type: "handle", role: "operator", origin: "intake", cluster: "Spoofs", score: 60 } },
    { data: { id: "iso", label: "lonely.io", full_name: "lonely.io", type: "domain", role: "infra", origin: "osint", cluster: "", score: 10 } },
    { data: { id: "e1", source: "n1", target: "n3", kind: "typed_rel" } },
    { data: { id: "e2", source: "n1", target: "n2", kind: "co_occurs" } },
  ]);
  return g;
}

describe("A4 — facet filters (role/origin/cluster)", () => {
  let g: CyGraph;
  beforeEach(() => { g = mkGraph(); });

  it("role facet lights only matching nodes, dims the rest", () => {
    g.applyFilter({ role: "operator" });
    expect(g.cy.getElementById("n1").hasClass("facet-match")).toBe(true); // operator
    expect(g.cy.getElementById("n3").hasClass("facet-match")).toBe(true); // operator
    expect(g.cy.getElementById("n2").hasClass("dimmed")).toBe(true); // infra dimmed
  });

  it("origin facet narrows by provenance", () => {
    g.applyFilter({ origin: "intake" });
    expect(g.cy.getElementById("n2").hasClass("facet-match")).toBe(true);
    expect(g.cy.getElementById("n3").hasClass("facet-match")).toBe(true);
    expect(g.cy.getElementById("n1").hasClass("dimmed")).toBe(true); // osint dimmed
  });

  it("cluster facet filters by the analyze cluster name", () => {
    g.applyFilter({ cluster: "Spoofs" });
    expect(g.cy.getElementById("n1").hasClass("facet-match")).toBe(true);
    expect(g.cy.getElementById("n3").hasClass("facet-match")).toBe(true);
    expect(g.cy.getElementById("n2").hasClass("dimmed")).toBe(true);
  });

  it("combined facets AND together (operator AND in cluster Spoofs)", () => {
    g.applyFilter({ role: "operator", cluster: "Spoofs" });
    expect(g.cy.getElementById("n1").hasClass("facet-match")).toBe(true);
    expect(g.cy.getElementById("n2").hasClass("facet-match")).toBe(false);
  });

  it("a facet that matches NOTHING un-dims (never blanks the canvas)", () => {
    g.applyFilter({ role: "nonexistent" });
    expect(g.cy.nodes(".dimmed").length).toBe(0);
  });

  it("getFacets tallies the present role/origin/cluster values with counts", () => {
    const f = g.getFacets();
    expect(f.roles).toEqual(expect.arrayContaining([{ key: "operator", n: 2 }, { key: "infra", n: 2 }]));
    expect(f.origins).toEqual(expect.arrayContaining([{ key: "intake", n: 2 }, { key: "osint", n: 2 }]));
    expect(f.clusters).toEqual([{ key: "Spoofs", n: 2 }]); // only non-empty clusters
  });
});

describe("A4 — visibility toggles", () => {
  let g: CyGraph;
  beforeEach(() => { g = mkGraph(); });

  it("meaningfulOnly hides the unconnected node, keeps connected ones", () => {
    g.setVisibility({ meaningfulOnly: true });
    expect(g.cy.getElementById("iso").hasClass("hidden")).toBe(true); // isolated → hidden
    expect(g.cy.getElementById("n1").hasClass("hidden")).toBe(false); // connected → shown
  });

  it("inClusterOnly hides nodes with no cluster", () => {
    g.setVisibility({ inClusterOnly: true });
    expect(g.cy.getElementById("n2").hasClass("hidden")).toBe(true); // no cluster
    expect(g.cy.getElementById("n1").hasClass("hidden")).toBe(false); // clustered
  });

  it("co-occurrence edges are hidden by default, shown when toggled", () => {
    g.setVisibility({ coOccurrence: false });
    expect(g.cy.getElementById("e2").hasClass("hidden")).toBe(true);
    g.setVisibility({ coOccurrence: true });
    expect(g.cy.getElementById("e2").hasClass("hidden")).toBe(false);
  });

  it("showAll clears every hide", () => {
    g.setVisibility({ meaningfulOnly: true });
    g.setVisibility({ showAll: true });
    expect(g.cy.getElementById("iso").hasClass("hidden")).toBe(false);
  });
});

describe("ux-frontier — isolated nodes de-emphasized only when a core exists (discovery-grow Option 3)", () => {
  // markFrontier() is the private pass render()/grow() call; we drive it directly on the headless graph
  // so we test the topology logic without the canvas-bound layout path.
  const mark = (g: CyGraph) => (g as unknown as { markFrontier(): void }).markFrontier();

  it("marks the isolated node as frontier, leaves connected nodes unmarked", () => {
    const g = mkGraph(); // n1-n2-n3 connected, iso has no edge
    mark(g);
    expect(g.cy.getElementById("iso").hasClass("frontier")).toBe(true);
    expect(g.cy.getElementById("n1").hasClass("frontier")).toBe(false);
    expect(g.cy.getElementById("n2").hasClass("frontier")).toBe(false);
  });

  it("NEGATIVE: when every node is isolated (a fresh file-only intake graph), nothing is frontier", () => {
    const g = new CyGraph(undefined as unknown as HTMLElement, CB);
    g.cy.add([
      { data: { id: "a", label: "a.com", full_name: "a.com", type: "domain", role: "infra", origin: "intake", score: 30 } },
      { data: { id: "b", label: "b.com", full_name: "b.com", type: "domain", role: "infra", origin: "intake", score: 30 } },
    ]); // no edges → no core → keep every dot full-weight so the analyst can scan them all
    mark(g);
    expect(g.cy.nodes(".frontier").length).toBe(0);
  });

  it("is idempotent — re-marking after an edge appears moves a node out of frontier", () => {
    const g = mkGraph();
    mark(g);
    expect(g.cy.getElementById("iso").hasClass("frontier")).toBe(true);
    g.cy.add({ data: { id: "e3", source: "iso", target: "n1", kind: "co_occurs" } }); // iso now connects
    mark(g);
    expect(g.cy.getElementById("iso").hasClass("frontier")).toBe(false);
  });
});

describe("A4 — legend drift-check (legendSpec is the single source)", () => {
  it("lists every role the renderer can emit (a new role can't silently miss the legend)", () => {
    const spec = legendSpec();
    const roles = spec.roles.map((r) => r.role);
    // the canonical render roles (graph.html shapeMap) — if cy-adapter adds one, this must include it.
    for (const r of ["operator", "channel", "ioc", "infra", "source"]) expect(roles).toContain(r);
    expect(roles).toContain("seed"); // the objective node is special-cased in nodeData() — must be in the legend
    // each role carries a concrete shape + color (no blanks reach the legend).
    for (const r of spec.roles) { expect(r.shape).toBeTruthy(); expect(r.color).toMatch(/^#|hsl/); }
  });

  it("covers origins (border styles) and edge confidences", () => {
    const spec = legendSpec();
    expect(spec.origins.map((o) => o.origin)).toEqual(expect.arrayContaining(["intake", "osint", "manual"]));
    expect(spec.confidences.map((c) => c.confidence)).toEqual(expect.arrayContaining(["high", "medium", "low"]));
  });
});
