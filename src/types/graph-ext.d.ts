// Ambient declarations for the bundled Cytoscape extensions, which ship no .d.ts.
// cytoscape itself is typed via @types/cytoscape; these are the registerable extensions
// + dagre's layout backend. All bundled (no CDN) — see scripts/leakgate.mjs.
// NOTE: this file is a SCRIPT (no top-level import/export) so `declare module` blocks are
// ambient. The cytoscape Core's expandCollapse() factory is reached via a local cast in
// src/graph/cy-graph.ts rather than a module augmentation (which would require turning this
// file into a module and lose the ambient extension declarations).

declare module "cytoscape-dagre" {
  const ext: unknown;
  export default ext;
}
declare module "cytoscape-fcose" {
  const ext: unknown;
  export default ext;
}
declare module "cytoscape-expand-collapse" {
  const ext: unknown;
  export default ext;
}
declare module "dagre";
declare module "layout-base";
declare module "cose-base";
