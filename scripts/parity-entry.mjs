// parity-entry — the kipi-web side of the parity harness (issue prd-pv3-kipi-runner).
//
// PURE stdin-fixture -> stdout-boundary-JSON, over the REAL src modules. No server, no new
// logic: it imports the SAME functions the live app renders with (graph/cy-adapter
// modelToElements, which produces the cytoscape node.data — shape/color/clusterColor/
// borderStyle/label — and graph/model + entity/scoring), and emits their output so the
// Python kipi_runner can diff it against the original Hydra's post-JS node.data.
//
// Run with vite-node so the .ts modules resolve without a build:
//   node_modules/.bin/vite-node scripts/parity-entry.mjs  < fixture.json
//
// Contract: stdin is a JSON GraphModel {nodes:[GraphNode], edges:[GraphEdge]}; stdout is
// {B2:{nodes,edges}, B3:{nodes,edges}} where B3 carries the rendered cytoscape data attrs.
// Any error exits non-zero with a message on stderr (fail-closed: the runner asserts exit 0).

import { modelToElements } from "../src/graph/cy-adapter.ts";

function readStdin() {
  return new Promise((resolve, reject) => {
    let buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (d) => (buf += d));
    process.stdin.on("end", () => resolve(buf));
    process.stdin.on("error", reject);
  });
}

async function main() {
  const raw = await readStdin();
  let model;
  try {
    model = JSON.parse(raw);
  } catch (e) {
    process.stderr.write(`parity-entry: invalid JSON fixture: ${e.message}\n`);
    process.exit(2);
  }
  if (!model || !Array.isArray(model.nodes)) {
    process.stderr.write("parity-entry: fixture must be {nodes:[...], edges:[...]}\n");
    process.exit(2);
  }
  // The REAL render: modelToElements is what the live cy-graph renders from, so its node.data
  // IS the post-JS render the user sees (shape/color/clusterColor/borderStyle/label/score).
  const elements = modelToElements(model);
  const out = {
    B2: {
      nodes: model.nodes.map((n) => ({ id: n.id, label: n.label, role: n.role, type: n.entityType,
                                       cluster: n.cluster, origin: n.origin, score: n.threatScore })),
      edges: (model.edges || []).map((e) => ({ from: e.from, to: e.to, rel: e.relType ?? e.kind })),
    },
    B3: {
      nodes: elements.nodes.map((n) => n.data),
      edges: elements.edges.map((e) => e.data),
    },
  };
  process.stdout.write(JSON.stringify(out));
}

main().catch((e) => {
  process.stderr.write(`parity-entry: ${e?.stack || e}\n`);
  process.exit(1);
});
