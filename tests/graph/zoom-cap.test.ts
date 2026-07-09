import { describe, it, expect } from "vitest";
import { cappedZoom, MAX_GRAPH_ZOOM } from "../../src/graph/zoom.js";

// clu-graph-fit-cap: the single zoom-cap guard. render()'s frame() AND the public fit() (Fit toolbar
// button + chat `fit` command) both route through this so no fit path can leave a sparse graph zoomed
// to ~3x → giant-blob nodes (the defect the parent graph-topology issue set out to kill; codex caught
// that fit() still bypassed the cap).
describe("cappedZoom (clu-graph-fit-cap)", () => {
  it("caps any zoom above the max down to the max", () => {
    expect(cappedZoom(3)).toBe(MAX_GRAPH_ZOOM);
    expect(cappedZoom(1.5)).toBe(MAX_GRAPH_ZOOM);
    expect(cappedZoom(MAX_GRAPH_ZOOM + 1e-6)).toBe(MAX_GRAPH_ZOOM);
  });
  it("leaves a zoom at or below the max unchanged (no forced zoom-in)", () => {
    expect(cappedZoom(0.74)).toBe(0.74);
    expect(cappedZoom(MAX_GRAPH_ZOOM)).toBe(MAX_GRAPH_ZOOM);
    expect(cappedZoom(0.1)).toBe(0.1);
  });
  it("the max is 1.1 (the giant-blob threshold)", () => {
    expect(MAX_GRAPH_ZOOM).toBe(1.1);
  });
});
