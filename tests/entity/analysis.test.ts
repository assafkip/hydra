import { describe, it, expect } from "vitest";
import { canonKey, type EntityStore, type EntityRecord } from "../../src/entity/db.js";
import type { GraphModel } from "../../src/graph/model.js";
import { applyCorrections, applyCorrectionsToModel, type CorrectionMap } from "../../src/entity/corrections.js";
import {
  applyAnalysis,
  applyAnalysisToModel,
  applyClustersToModel,
  applyScoresToModel,
  applyMetricsToModel,
  applyRelationshipsToModel,
  validateCaseSchema,
  validateAnalysisRecord,
  emptyAnalysis,
  type AnalysisRecord,
} from "../../src/entity/analysis.js";

// ca-analysis (PRD D1/D7): the pure Process-output projection. applyAnalysis overlays role / (display)
// type of an EXISTING entity by canonKey; it never rekeys identity, never changes grade/promotion, never
// adds a node. The CRUX test: a correction layered ABOVE analysis WINS (analyst is top authority).

const rec = (type: string, value: string, role: string): EntityRecord => ({
  ref: { type, value },
  label: value,
  type,
  role,
  promoted: true,
  grade: "A",
  sourceCount: 2,
  infraSourceCount: 2,
  runs: ["run:x"],
  reasons: [],
});
function store(recs: EntityRecord[]): EntityStore {
  const entities: Record<string, EntityRecord> = {};
  for (const r of recs) entities[canonKey(r.ref.type, r.ref.value)] = r;
  return { entities, connections: {}, cooccurTruncated: false };
}
function analysis(over: Partial<AnalysisRecord>): AnalysisRecord {
  return { ...emptyAnalysis("default"), ...over };
}

describe("ca-analysis — Process-output projection", () => {
  it("applyAnalysis overlays record.role/type by canonKey — ref/grade/promoted untouched, store not mutated", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const key = canonKey("domain", "example.com");
    const out = applyAnalysis(s, analysis({ roles: { [key]: "source" }, types: { [key]: "url" } }));
    const r = out.entities[key];
    expect(r.role).toBe("source");
    expect(r.type).toBe("url");
    expect(r.ref).toEqual({ type: "domain", value: "example.com" }); // identity unchanged (same key)
    expect(r.grade).toBe("A");
    expect(r.promoted).toBe(true);
    expect(r.sourceCount).toBe(2);
    expect(s.entities[key].role).toBe("ioc"); // pure: input not mutated
  });

  it("a non-allowlisted overlay value is ignored (the role/type stays original)", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const key = canonKey("domain", "example.com");
    const out = applyAnalysis(s, analysis({ roles: { [key]: "banana" }, types: { [key]: "banana" } }));
    expect(out.entities[key].role).toBe("ioc"); // banana is not a CONSOLIDATE_ROLE -> ignored
    expect(out.entities[key].type).toBe("domain"); // banana is not a SURFACE_TYPE -> ignored
  });

  it("PRD-B typing-case-type: caseTypes overlays EntityRecord.caseType (analytic type applied, not just emitted)", () => {
    const s = store([rec("domain", "scam.example", "ioc")]);
    const key = canonKey("domain", "scam.example");
    // caseTypes ALONE (no role/type change) is a real overlay — hasOverlay must fire on it.
    const out = applyAnalysis(s, analysis({ caseTypes: { [key]: "scam_domain" } }));
    expect(out.entities[key].caseType).toBe("scam_domain"); // re-bucketing APPLIED onto the record
    expect(out.entities[key].type).toBe("domain"); // surface type untouched (case_type is distinct)
    expect(s.entities[key].caseType).toBeUndefined(); // pure: input not mutated
  });

  it("an overlay for an entity not in the store invents nothing (no rekey/add)", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const out = applyAnalysis(s, analysis({ roles: { [canonKey("ip", "9.9.9.9")]: "infra" } }));
    expect(Object.keys(out.entities)).toHaveLength(1);
    expect(out.entities[canonKey("domain", "example.com")].role).toBe("ioc");
  });

  it("an empty/null analysis returns the SAME store reference (no needless copy)", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    expect(applyAnalysis(s, null)).toBe(s);
    expect(applyAnalysis(s, emptyAnalysis("default"))).toBe(s);
  });

  // THE crux (PRD D1): analyst correction layered ABOVE analysis wins — top-authority invariant.
  it("a correction on the SAME entity WINS over the analysis role (layered below corrections)", () => {
    const s = store([rec("domain", "example.com", "ioc")]);
    const key = canonKey("domain", "example.com");
    const analyzed = applyAnalysis(s, analysis({ roles: { [key]: "source" } }));
    expect(analyzed.entities[key].role).toBe("source"); // AI role applied first
    const map: CorrectionMap = { [key]: { role: "operator" } };
    const corrected = applyCorrections(analyzed, map); // analyst override runs LAST
    expect(corrected.entities[key].role).toBe("operator"); // analyst wins, not the AI 'source'
  });

  it("applyAnalysisToModel overlays node.role ONLY (type stays original to keep correction keys stable); adds no node", () => {
    const model: GraphModel = {
      objective: "dig",
      nodes: [
        { id: "objective", label: "dig", kind: "objective", promoted: false },
        { id: "finding:0:domain:example.com", label: "example.com", kind: "finding", promoted: true, entityType: "domain" },
      ],
      edges: [],
    };
    const key = canonKey("domain", "example.com");
    const analyzed = applyAnalysisToModel(model, analysis({ roles: { [key]: "source" }, types: { [key]: "url" } }));
    const n0 = analyzed.nodes.find((x) => x.label === "example.com")!;
    expect(n0.role).toBe("source"); // role overlaid on the graph
    expect(n0.entityType).toBe("domain"); // type NOT changed on the model (store-only; avoids correction key drift)
    expect(analyzed.nodes).toHaveLength(2);
    expect(analyzed.nodes[0].kind).toBe("objective"); // objective untouched
  });

  // THE crux on the graph (PRD D1): a correction keyed by the ORIGINAL type still matches + wins,
  // because applyAnalysisToModel left entityType untouched (no key drift).
  it("a role correction WINS on the graph over the analysis role (no key drift)", () => {
    const model: GraphModel = {
      objective: "dig",
      nodes: [
        { id: "objective", label: "dig", kind: "objective", promoted: false },
        { id: "finding:0:domain:example.com", label: "example.com", kind: "finding", promoted: true, entityType: "domain" },
      ],
      edges: [],
    };
    const key = canonKey("domain", "example.com");
    const analyzed = applyAnalysisToModel(model, analysis({ roles: { [key]: "source" }, types: { [key]: "url" } }));
    const corrected = applyCorrectionsToModel(analyzed, { [key]: { role: "operator" } });
    expect(corrected.nodes.find((x) => x.label === "example.com")!.role).toBe("operator");
  });
});

describe("ca-analysis — schema validation (understand.py:_validate parity)", () => {
  it("guarantees a 'noise' role + at least one actor role + a non-empty sub_role list", () => {
    const s = validateCaseSchema({ domain: "crypto rug-pull", roles: [{ name: "Promoter", actor: true, weight: 9 }, { name: "Token", actor: false }] })!;
    expect(s.domain).toBe("crypto rug-pull");
    expect(s.roles.some((r) => r.name === "noise")).toBe(true); // noise guaranteed
    expect(s.roles.some((r) => r.actor)).toBe(true); // actor guaranteed
    expect(s.roles.find((r) => r.name === "promoter")!.weight).toBe(5); // weight clamped 0-5
    expect(s.subRoles.length).toBeGreaterThan(0); // never empty
  });

  it("promotes a role to actor when none is marked (so sub_roles work)", () => {
    const s = validateCaseSchema({ roles: [{ name: "outlet", actor: false }] })!;
    expect(s.roles.find((r) => r.name === "outlet")!.actor).toBe(true);
  });

  it("accepts snake_case keys (entity_types / sub_roles / noise_notes) from the python-shaped LLM output", () => {
    const s = validateCaseSchema({ entity_types: [{ name: "wallet" }], sub_roles: [{ name: "launderer" }], noise_notes: "fragments" })!;
    expect(s.entityTypes[0].name).toBe("wallet");
    expect(s.subRoles.some((r) => r.name === "launderer")).toBe(true);
    expect(s.noiseNotes).toBe("fragments");
  });

  it("guarantees an actor role even for an EMPTY schema (the autoModelSchema fallback path)", () => {
    const s = validateCaseSchema({})!; // {} -> no roles to promote: a default actor must be ADDED
    expect(s.roles.some((r) => r.actor)).toBe(true);
    expect(s.roles.some((r) => r.name === "noise")).toBe(true);
    expect(s.subRoles.length).toBeGreaterThan(0);
  });

  it("returns null for a non-object schema (negative)", () => {
    expect(validateCaseSchema(null)).toBeNull();
    expect(validateCaseSchema("not a schema")).toBeNull();
  });
});

describe("ca-analysis — record validation (the putAnalysis chokepoint, D7)", () => {
  it("drops overlay entries with a non-allowlisted value; keeps valid ones", () => {
    const key = canonKey("domain", "example.com");
    const out = validateAnalysisRecord({ case: "default", roles: { [key]: "source", bad: "banana" }, types: { [key]: "url" } }, "default");
    expect(out.roles[key]).toBe("source");
    expect(out.roles.bad).toBeUndefined(); // banana not allowlisted -> dropped
    expect(out.types[key]).toBe("url");
  });

  it("A1: subRoles SURVIVE the persist chokepoint (codex High — were silently dropped)", () => {
    const key = canonKey("handle", "@crewlead");
    const out = validateAnalysisRecord(
      { case: "default", roles: { [key]: "operator" }, subRoles: { [key]: "Leadership", notakey: "x" } },
      "default",
    );
    expect(out.subRoles?.[key]).toBe("Leadership"); // free-form label kept (canonical key), not stripped
    expect(out.subRoles?.notakey).toBeUndefined(); // non-canonical key dropped
  });

  it("PRD-B: pathConfidence SURVIVES the persist chokepoint (graph-path-confidence wiring)", () => {
    const key = canonKey("ip", "9.9.9.9");
    const out = validateAnalysisRecord(
      { case: "default", nodeMetrics: { [key]: { degreeCentrality: 0.5, betweenness: 0.1, eigenvector: 0.2, community: 1, pathConfidence: 0.85 } } },
      "default",
    );
    expect(out.nodeMetrics[key].pathConfidence).toBe(0.85); // carried through (not stripped)
    // NEGATIVE: a node with no pathConfidence (unreachable from a seed) stays undefined, never 0-faked.
    const noPath = validateAnalysisRecord(
      { case: "default", nodeMetrics: { [key]: { degreeCentrality: 0.5, betweenness: 0.1, eigenvector: 0.2, community: 1 } } },
      "default",
    );
    expect(noPath.nodeMetrics[key].pathConfidence).toBeUndefined();
  });

  it("PRD-B: caseTypes SURVIVE the persist chokepoint (codex issue-3 BLOCKER — were stripped end-to-end)", () => {
    const key = canonKey("domain", "scam.example");
    const out = validateAnalysisRecord(
      { case: "default", caseTypes: { [key]: "scam_domain", notakey: "x" } },
      "default",
    );
    // NEGATIVE proof: before the fix validateAnalysisRecord never read caseTypes, so this was undefined
    // (the overlay applied in isolation but was dropped the moment it round-tripped through putAnalysis).
    expect(out.caseTypes?.[key]).toBe("scam_domain"); // free-text label kept (canonical key)
    expect(out.caseTypes?.notakey).toBeUndefined(); // non-canonical key dropped
  });

  it("drops overlay entries whose KEY is not canonical (codex D7), keeps canonKey-built keys", () => {
    const good = canonKey("domain", "example.com");
    const out = validateAnalysisRecord(
      {
        roles: {
          [good]: "source", // canonical -> kept
          notakey: "operator", // not a JSON tuple -> dropped
          '["DOMAIN","Example.com"]': "channel", // non-canonical (uppercase type / value) -> dropped
          '["ip","1.2.3.4","extra"]': "infra", // wrong arity -> dropped
        },
      },
      "default",
    );
    expect(out.roles[good]).toBe("source");
    expect(out.roles.notakey).toBeUndefined();
    expect(out.roles['["DOMAIN","Example.com"]']).toBeUndefined();
    expect(out.roles['["ip","1.2.3.4","extra"]']).toBeUndefined();
    expect(Object.keys(out.roles)).toEqual([good]); // ONLY the canonical key survived
  });

  it("coerces a malformed record to a safe empty shape (never throws, never breaks load)", () => {
    const out = validateAnalysisRecord("garbage", "default");
    expect(out.case).toBe("default");
    expect(out.schema).toBeNull();
    expect(out.roles).toEqual({});
    expect(out.types).toEqual({});
    expect(out.clusters).toEqual([]);
    expect(out.relationships).toEqual([]);
  });

  it("validates clusters: drops non-canonical memberKeys, requires a name (INC-3)", () => {
    const good = canonKey("person", "alice");
    const out = validateAnalysisRecord(
      {
        clusters: [
          { name: "Ring A", kind: "ring", description: "crew", memberKeys: [good, "notakey", '["PERSON","Alice"]'] },
          { kind: "ring", memberKeys: [good] }, // no name -> dropped
        ],
      },
      "default",
    );
    expect(out.clusters).toHaveLength(1);
    expect(out.clusters[0].name).toBe("Ring A");
    expect(out.clusters[0].memberKeys).toEqual([good]); // only the canonical key survived
  });

  it("dedupes cluster memberKeys (codex adversarial: a hostile record can't repeat a member)", () => {
    const good = canonKey("person", "alice");
    const out = validateAnalysisRecord(
      { clusters: [{ name: "Dupes", kind: "ring", memberKeys: [good, good, good] }] },
      "default",
    );
    expect(out.clusters[0].memberKeys).toEqual([good]); // deduped to one
  });

  it("validates relationships: drops non-canonical endpoints, clamps confidence (INC-3)", () => {
    const a = canonKey("person", "alice");
    const b = canonKey("domain", "evil.com");
    const out = validateAnalysisRecord(
      {
        relationships: [
          { srcKey: a, dstKey: b, relType: "hosted_on", confidence: "banana", evidence: "x" }, // bad conf -> medium
          { srcKey: a, dstKey: "notakey", relType: "shills", confidence: "high" }, // bad dst -> dropped
          { srcKey: a, dstKey: b, confidence: "high" }, // no relType -> dropped
        ],
      },
      "default",
    );
    expect(out.relationships).toHaveLength(1);
    expect(out.relationships[0]).toMatchObject({ srcKey: a, dstKey: b, relType: "hosted_on", confidence: "medium" });
  });
});

describe("ca-analyze — cluster coloring projection (applyClustersToModel, INC-3)", () => {
  const model = (): GraphModel => ({
    objective: "dig",
    nodes: [
      { id: "objective", label: "dig", kind: "objective", promoted: false },
      { id: "finding:0:person:alice", label: "Alice", kind: "finding", promoted: true, entityType: "person" },
      { id: "finding:1:domain:evil.com", label: "evil.com", kind: "finding", promoted: true, entityType: "domain" },
    ],
    edges: [],
  });

  it("sets node.cluster by canonKey membership; objective + unlisted nodes untouched", () => {
    const aliceKey = canonKey("person", "alice");
    const out = applyClustersToModel(
      model(),
      analysis({ clusters: [{ name: "Ring A", kind: "ring", description: "", memberKeys: [aliceKey] }] }),
    );
    expect(out.nodes.find((n) => n.label === "Alice")!.cluster).toBe("Ring A");
    expect(out.nodes.find((n) => n.label === "evil.com")!.cluster).toBeUndefined(); // not a member
    expect(out.nodes.find((n) => n.kind === "objective")!.cluster).toBeUndefined(); // objective never clustered
  });

  it("first cluster wins when an entity is listed in two (a fill is one color, deterministic)", () => {
    const aliceKey = canonKey("person", "alice");
    const out = applyClustersToModel(
      model(),
      analysis({
        clusters: [
          { name: "Ring A", kind: "ring", description: "", memberKeys: [aliceKey] },
          { name: "Ring B", kind: "ring", description: "", memberKeys: [aliceKey] },
        ],
      }),
    );
    expect(out.nodes.find((n) => n.label === "Alice")!.cluster).toBe("Ring A");
  });

  it("no clusters → model returned unchanged (slate fallback honored downstream)", () => {
    const m = model();
    expect(applyClustersToModel(m, analysis({ clusters: [] }))).toBe(m);
    expect(applyClustersToModel(m, null)).toBe(m);
  });

  it("CLEARS a stale node.cluster on a non-match (codex adversarial: grow/expand base carries old fills)", () => {
    // a base model node already carries a cluster from a prior finalize; the current record excludes it
    const m = model();
    const stale = { ...m.nodes[1], cluster: "Old Ring" }; // Alice was clustered before
    const withStale: GraphModel = { ...m, nodes: [m.nodes[0], stale, m.nodes[2]] };
    const out = applyClustersToModel(
      withStale,
      // the new record clusters only evil.com — Alice is NOT a member anymore
      analysis({ clusters: [{ name: "New", kind: "ring", description: "", memberKeys: [canonKey("domain", "evil.com")] }] }),
    );
    expect(out.nodes.find((n) => n.label === "Alice")!.cluster).toBeUndefined(); // stale cleared
    expect(out.nodes.find((n) => n.label === "evil.com")!.cluster).toBe("New"); // fresh set
  });
});

describe("INC-4a — score / metrics / typed-edge projections", () => {
  const aliceKey = canonKey("person", "alice");
  const evilKey = canonKey("domain", "evil.com");
  const model = (): GraphModel => ({
    objective: "dig",
    nodes: [
      { id: "objective", label: "dig", kind: "objective", promoted: false },
      { id: "finding:0:person:alice", label: "Alice", kind: "finding", promoted: true, entityType: "person" },
      { id: "finding:1:domain:evil.com", label: "evil.com", kind: "finding", promoted: true, entityType: "domain" },
    ],
    edges: [],
  });

  it("applyScoresToModel sets node.threatScore by canonKey; objective untouched; stale cleared", () => {
    const out = applyScoresToModel(model(), analysis({ entityScores: { [aliceKey]: { threatScore: 91, degree: 1, reportCount: 2 } } }));
    expect(out.nodes.find((n) => n.label === "Alice")!.threatScore).toBe(91);
    expect(out.nodes.find((n) => n.label === "evil.com")!.threatScore).toBeUndefined();
    expect(out.nodes.find((n) => n.kind === "objective")!.threatScore).toBeUndefined();
    // a record with no scores clears a stale value carried by a prior finalized base
    const seeded = { ...model(), nodes: model().nodes.map((n) => (n.label === "Alice" ? { ...n, threatScore: 5 } : n)) };
    expect(applyScoresToModel(seeded, emptyAnalysis("default")).nodes.find((n) => n.label === "Alice")!.threatScore).toBeUndefined();
  });

  it("applyMetricsToModel sets centrality + community by canonKey", () => {
    const out = applyMetricsToModel(model(), analysis({ nodeMetrics: { [aliceKey]: { degreeCentrality: 1, betweenness: 0.5, eigenvector: 0.7, community: 2 } } }));
    const a = out.nodes.find((n) => n.label === "Alice")!;
    expect(a.degreeCentrality).toBe(1);
    expect(a.betweenness).toBe(0.5);
    expect(a.community).toBe(2);
    expect(out.nodes.find((n) => n.label === "evil.com")!.community).toBeUndefined();
  });

  it("applyRelationshipsToModel adds an entity↔entity typed_rel edge between the matching nodes", () => {
    const out = applyRelationshipsToModel(model(), analysis({ relationships: [{ srcKey: aliceKey, dstKey: evilKey, relType: "operates", confidence: "high", evidence: "x" }] }));
    const e = out.edges.find((x) => x.kind === "typed_rel");
    expect(e).toBeTruthy();
    expect(e!.relType).toBe("operates");
    expect(e!.from).toBe("finding:0:person:alice");
    expect(e!.to).toBe("finding:1:domain:evil.com");
  });

  it("applyRelationshipsToModel skips a relationship whose endpoint is not on the graph (no dangling edge)", () => {
    const out = applyRelationshipsToModel(model(), analysis({ relationships: [{ srcKey: aliceKey, dstKey: canonKey("domain", "ghost.com"), relType: "operates", confidence: "high", evidence: "" }] }));
    expect(out.edges.some((x) => x.kind === "typed_rel")).toBe(false);
  });

  it("applyRelationshipsToModel REBUILDS — a stale typed_rel from a prior finalize is cleared (codex A4)", () => {
    // an already-finalized base carrying a stale typed_rel edge (grow/expand re-finalize path)
    const withStale = { ...model(), edges: [{ from: "finding:0:person:alice", to: "finding:1:domain:evil.com", kind: "typed_rel" as const, relType: "old_rel", confidence: "high" }] };
    // an EMPTY relationship record clears the stale edge entirely
    expect(applyRelationshipsToModel(withStale, emptyAnalysis("default")).edges.some((e) => e.kind === "typed_rel")).toBe(false);
    // a CHANGED record leaves only the new edge — the stale "old_rel" is gone
    const rebuilt = applyRelationshipsToModel(withStale, analysis({ relationships: [{ srcKey: aliceKey, dstKey: evilKey, relType: "operates", confidence: "high", evidence: "" }] }));
    const typed = rebuilt.edges.filter((e) => e.kind === "typed_rel");
    expect(typed).toHaveLength(1);
    expect(typed[0].relType).toBe("operates");
  });

  it("validateAnalysisRecord coerces entityScores + nodeMetrics; drops a non-canonical key", () => {
    const out = validateAnalysisRecord(
      {
        entityScores: { [aliceKey]: { threatScore: "91", degree: 1, reportCount: 2 }, "not-a-key": { threatScore: 5 } },
        nodeMetrics: { [aliceKey]: { degreeCentrality: 0.5, betweenness: "x", eigenvector: 0.7, community: 1 } },
      },
      "default",
    );
    expect(out.entityScores[aliceKey]).toEqual({ threatScore: 91, degree: 1, reportCount: 2 }); // "91" coerced
    expect(out.entityScores["not-a-key"]).toBeUndefined(); // non-canonical key dropped
    expect(out.nodeMetrics[aliceKey]).toEqual({ degreeCentrality: 0.5, betweenness: 0, eigenvector: 0.7, community: 1 }); // bad number -> 0
  });

  it("validateRelationships drops an out-of-vocab junk relType but keeps a clean schema label (codex P1)", () => {
    const a = canonKey("person", "alice");
    const b = canonKey("domain", "evil.com");
    const out = validateAnalysisRecord(
      { relationships: [
        { srcKey: a, dstKey: b, relType: "operates", confidence: "high" }, // vocab -> kept
        { srcKey: a, dstKey: b, relType: "deployed", confidence: "high" }, // clean schema label -> kept
        { srcKey: a, dstKey: b, relType: "!!! junk %%%", confidence: "high" }, // not vocab + not clean -> dropped
      ] },
      "default",
    );
    const types = out.relationships.map((r) => r.relType).sort();
    expect(types).toEqual(["deployed", "operates"]);
  });
});
