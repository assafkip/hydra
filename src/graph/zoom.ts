// clu-graph-fit-cap: the single zoom-cap guard for the graph canvas. render()'s frame() AND the public
// fit() (Fit toolbar button + chat `fit` command) both route through this, so NO fit path can leave a
// sparse graph zoomed to ~3x → giant-blob nodes (the defect the graph-topology issue set out to kill;
// codex on f8c2d845 caught that fit() still called a raw cy.fit() and bypassed the cap). Pure + tiny so
// it is unit-testable without a cytoscape viewport.

/** The giant-blob threshold: a fit on a few nodes must never zoom past this. */
export const MAX_GRAPH_ZOOM = 1.1;

/** Cap a zoom level at MAX_GRAPH_ZOOM. Never forces a zoom-IN (values <= max pass through). */
export function cappedZoom(current: number, max: number = MAX_GRAPH_ZOOM): number {
  return current > max ? max : current;
}
