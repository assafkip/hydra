// parity-case-entry — the clone side of the REAL-CASE model diff (FIFA smoke).
//
// Unlike parity-entry.mjs (which renders a HAND-BUILT GraphModel and so BYPASSES the model
// builder under suspicion), this entry drives the REAL clone path the live app uses on mount:
//
//   vault.put("run:<objective>", record)  ->  graphModelForCase(vault)  ->  modelToElements(model)
//
// i.e. it exercises emptyObjectiveGraphModel (the objective hub) + mergeGraphModel (the star
// spokes) + withEntityNetworkEdges (the co-occurrence network) + finalizeModel — exactly what
// the home/case graph builds. So its output IS the graph the user sees, and the Python diff can
// compare it against the original Hydra's api_graph on identical FIFA input.
//
// Run with vite-node so the .ts modules resolve without a build:
//   node_modules/.bin/vite-node scripts/parity-case-entry.mjs  < run-records.json
//
// stdin: { objective: string, record: RunRecord }   (one agent run; promoted = the FIFA entities)
// stdout: { model: {nodes,edges}, rendered: {nodes,edges} }   model = graphModelForCase output,
//         rendered = modelToElements(model) (the post-JS cytoscape node.data the user sees).
// Any error exits non-zero with a message on stderr (fail-closed: the runner asserts exit 0).

import { Vault } from "../src/vault/vault.ts";
import { memoryStorage } from "../src/vault/store.ts";
import { graphModelForCase, putAnalysis } from "../src/agent/session.ts";
import { emptyAnalysis } from "../src/entity/analysis.ts";
import { canonKey } from "../src/entity/db.ts";
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
  let input;
  try {
    input = JSON.parse(raw);
  } catch (e) {
    process.stderr.write(`parity-case-entry: invalid JSON: ${e.message}\n`);
    process.exit(2);
  }
  if (!input || typeof input.objective !== "string" || !input.record) {
    process.stderr.write("parity-case-entry: input must be {objective, record}\n");
    process.exit(2);
  }

  // A real in-memory vault — the SAME class the live app uses, so graphModelForCase runs its
  // real key-redaction + objectivesUnder enumeration (no test doubles).
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await vault.put(`run:${input.objective}`, input.record);

  // A1 role/shape parity: seed the analysis roles a real Process consolidate would assign, via the SAME
  // putAnalysis + canonKey the app uses, so graphModelForCase → applyAnalysisToModel overlays them onto
  // node.role (and the cy-adapter derives the SHAPE). input.analysis_roles: [{value, type, role}].
  if (Array.isArray(input.analysis_roles) && input.analysis_roles.length) {
    const rec = emptyAnalysis("default");
    for (const r of input.analysis_roles) {
      if (r && typeof r.value === "string" && typeof r.role === "string") {
        rec.roles[canonKey(r.type, r.value)] = r.role;
      }
    }
    await putAnalysis(vault, rec);
  }

  const model = graphModelForCase(vault);
  if (!model) {
    process.stderr.write("parity-case-entry: graphModelForCase returned null (no runs)\n");
    process.exit(1);
  }
  const rendered = modelToElements(model);

  const out = {
    model: {
      nodes: model.nodes.map((n) => ({ id: n.id, label: n.label, kind: n.kind,
                                       entityType: n.entityType, role: n.role, origin: n.origin })),
      edges: model.edges.map((e) => ({ from: e.from, to: e.to, kind: e.kind, relType: e.relType ?? "" })),
    },
    rendered: {
      nodes: rendered.nodes.map((n) => n.data),
      edges: rendered.edges.map((e) => e.data),
    },
  };
  process.stdout.write(JSON.stringify(out));
}

main().catch((e) => {
  process.stderr.write(`parity-case-entry: ${e?.stack || e}\n`);
  process.exit(1);
});
