import { describe, it, expect } from "vitest";
import { extractRelationships } from "../../src/agent/loop.js";
import { agentRelationshipsToLinks } from "../../src/agent/session.js";
import { runRecordToIngest, buildEntityDb, canonKey } from "../../src/entity/db.js";
import { mergeNetworkModel, type GraphModel } from "../../src/graph/model.js";
import type { Finding } from "../../src/agent/gate.js";

// PRD-B (RCA rca-discipline-evaporation item 3): the agent emits entity<->entity relationships AS it
// digs, and they build the graph as TYPED edges — not reconstructed blind by all-pairs co-occurrence.
// Each assertion carries its negative proof.
describe("live relationship emission (PRD-B RCA item 3)", () => {
  it("extracts relationships from the SAME findings JSON block, dropping malformed/self-loop/missing-endpoint", () => {
    const out =
      'reasoning the human reads...\n```json\n{"findings":[{"entity":"scam.com","entity_type":"domain"},' +
      '{"entity":"9.9.9.9","entity_type":"ip"}],"relationships":[' +
      '{"src":"scam.com","dst":"9.9.9.9","rel_type":"resolves to","confidence":"high"},' +
      '{"src":"x","dst":"x","rel_type":"self","confidence":"low"},' +
      '{"src":"","dst":"y"}]}\n```';
    const rels = extractRelationships(out);
    expect(rels).toHaveLength(1); // the self-loop + the missing-endpoint entry are dropped
    expect(rels[0]).toMatchObject({ src: "scam.com", dst: "9.9.9.9", relType: "resolves_to", confidence: "high" });
  });

  it("no relationships key -> empty (graceful), and a non-json body -> empty", () => {
    expect(extractRelationships('```json\n{"findings":[]}\n```')).toEqual([]); // negative: no relationships array
    expect(extractRelationships("just prose, no json")).toEqual([]);
  });

  it("an emitted relationship LANDS on the live graph as a TYPED edge (built as it digs, not co-occurrence)", () => {
    const promoted: Finding[] = [
      { entity: "scam.com", entity_type: "domain", infra_source_count: 1, source_count: 1 },
      { entity: "9.9.9.9", entity_type: "ip", infra_source_count: 1, source_count: 1 },
    ];
    const rels = [{ src: "scam.com", dst: "9.9.9.9", relType: "resolves_to", confidence: "high" }];

    // WITH the agent's emitted relationship: the pair is a TYPED `linked` edge.
    const ingest = runRecordToIngest("run:x", promoted, []);
    ingest.links = agentRelationshipsToLinks(rels, ingest.entities); // endpoints resolved against the ADMITTED set
    expect(ingest.links).toHaveLength(1);
    const store = buildEntityDb([ingest]);
    const conn = (store.connections[canonKey("domain", "scam.com")] ?? []).find((c) => c.other.value === "9.9.9.9");
    expect(conn).toBeDefined();
    expect(conn!.relType).toBe("linked"); // the agent-established typed edge

    // NEGATIVE proof: WITHOUT the emitted relationship the same pair only ever appears as a reconstructed
    // co-occurrence edge (the all-pairs fallback) — never the typed `linked` edge.
    const blind = runRecordToIngest("run:x", promoted, []); // links stays []
    const blindStore = buildEntityDb([blind]);
    const blindConn = (blindStore.connections[canonKey("domain", "scam.com")] ?? []).find((c) => c.other.value === "9.9.9.9");
    expect(blindConn?.relType).not.toBe("linked");
  });

  it("codex C1: a relationship to a NON-admitted endpoint is DROPPED (no phantom node/edge)", () => {
    const admitted = [{ value: "scam.com", type: "domain", promoted: true }];
    // dst "ghost.example" is NOT in the admitted set → the whole relationship is dropped.
    const links = agentRelationshipsToLinks([{ src: "scam.com", dst: "ghost.example", relType: "linked", confidence: "high" }], admitted);
    expect(links).toEqual([]);
    // a both-admitted relationship still maps.
    const ok = agentRelationshipsToLinks(
      [{ src: "scam.com", dst: "9.9.9.9", relType: "resolves_to", confidence: "high" }],
      [...admitted, { value: "9.9.9.9", type: "ip", promoted: true }],
    );
    expect(ok).toHaveLength(1);
  });

  it("codex C2: growCaseNetwork's merge folds the relationship as a TYPED `linked` edge live", () => {
    const promoted: Finding[] = [
      { entity: "scam.com", entity_type: "domain", infra_source_count: 1, source_count: 1 },
      { entity: "9.9.9.9", entity_type: "ip", infra_source_count: 1, source_count: 1 },
    ];
    const result = {
      steps: [], promoted, leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" as const, worked: true,
      relationships: [{ src: "scam.com", dst: "9.9.9.9", relType: "resolves_to", confidence: "high" }],
    };
    const base: GraphModel = { objective: "case", nodes: [], edges: [] };
    const grown = mergeNetworkModel(base, result, { maxNetworkEdges: 500 });
    const edge = grown.edges.find((e) => e.kind === "linked");
    expect(edge).toBeDefined(); // the live grow paints the typed edge, not only a remount
    // NEGATIVE: with no relationships the same pair is a co_occurs edge, never `linked`.
    const noRels = mergeNetworkModel(base, { ...result, relationships: [] }, { maxNetworkEdges: 500 });
    expect(noRels.edges.some((e) => e.kind === "linked")).toBe(false);
  });
});
