import { describe, it, expect } from "vitest";
import {
  buildEntityDb,
  runRecordToIngest,
  graphModelToIngest,
  getEntity,
  connectionsFor,
  coOccurrencesFor,
  edgeEvidence,
  buildDossier,
  allEntities,
  crossRunEntities,
  computeAliasLinks,
  aliasLinksFor,
  entityKey,
  ALIAS_MAX_PERSONS,
  MAX_COOCCUR_ENTITIES,
  type IngestRun,
  type IngestEntity,
  type EntityStore,
} from "../../src/entity/db.js";
import type { Finding, GateVerdict } from "../../src/agent/gate.js";
import type { GraphModel } from "../../src/graph/model.js";

// The entity DB is a PURE, GATE-FAITHFUL projection over runs. It must mirror
// src/graph/model.ts's fidelity (re-run isAdmissible + promotionGate; never trust a
// supplied verdict), accumulate across runs, and NEVER fabricate a connection or a
// dossier line that does not trace to a real gated finding.

function ie(value: string, type: string, promoted: boolean, extra: Partial<IngestEntity> = {}): IngestEntity {
  return { value, type, promoted, ...extra };
}
function run(objective: string, entities: IngestEntity[], links: IngestRun["links"] = []): IngestRun {
  return { objective, entities, links };
}

describe("buildEntityDb — entities + surfaced_in + co_occurs", () => {
  it("one run: two entities each get a surfaced_in (in) connection + a co_occurs (undirected) pair", () => {
    const store = buildEntityDb([
      run("Investigate example.com", [
        ie("93.184.216.34", "ip", true, { grade: "A", sourceCount: 2, infraSourceCount: 2 }),
        ie("ns1.example.com", "domain", true, { grade: "B", sourceCount: 1, infraSourceCount: 1 }),
      ]),
    ]);

    const ip = getEntity(store, "ip", "93.184.216.34")!;
    expect(ip).toBeTruthy();
    expect(ip.promoted).toBe(true);
    expect(ip.role).toBe("infra");

    const conns = connectionsFor(store, "ip", "93.184.216.34");
    const surfaced = conns.find((c) => c.relType === "surfaced_in")!;
    expect(surfaced.direction).toBe("in");
    expect(surfaced.otherRole).toBe("seed");
    expect(surfaced.otherLabel).toBe("Investigate example.com");

    const co = conns.find((c) => c.relType === "co_occurs")!;
    expect(co.direction).toBe("undirected");
    expect(co.other.value).toBe("ns1.example.com");
    expect(co.runs).toEqual(["Investigate example.com"]);
  });

  it("the objective is NEVER an entity record (codex D4)", () => {
    const store = buildEntityDb([run("acme.io", [ie("1.2.3.4", "ip", true, { infraSourceCount: 2 })])]);
    expect(getEntity(store, "objective", "acme.io")).toBeNull();
    // and the seed value is not in entities even by its real-looking type
    expect(Object.keys(store.entities)).toHaveLength(1);
  });
});

describe("buildEntityDb — cross-run accumulation (dedup, union runs)", () => {
  it("the same entity in two runs is ONE record with both objectives + max counts + best grade", () => {
    const store = buildEntityDb([
      run("run A", [ie("evil.com", "domain", false, { grade: "C", sourceCount: 1, infraSourceCount: 0 })]),
      run("run B", [ie("evil.com", "domain", true, { grade: "A", sourceCount: 3, infraSourceCount: 2 })]),
    ]);
    const e = getEntity(store, "domain", "evil.com")!;
    expect(e.runs.sort()).toEqual(["run A", "run B"]);
    expect(e.promoted).toBe(true); // promoted in ANY run
    expect(e.grade).toBe("A"); // best across appearances
    expect(e.sourceCount).toBe(3);
    expect(e.infraSourceCount).toBe(2);
  });

  it("alias-folds ip_address≡ip and wallet≡crypto_wallet into one entity", () => {
    const store = buildEntityDb([
      run("r1", [ie("9.9.9.9", "ip_address", true, { infraSourceCount: 2 })]),
      run("r2", [ie("9.9.9.9", "ip", true, { infraSourceCount: 2 })]),
    ]);
    expect(Object.keys(store.entities)).toHaveLength(1); // ip_address + ip fold to ONE record
    const e = getEntity(store, "ip", "9.9.9.9")!;
    expect(e.runs.sort()).toEqual(["r1", "r2"]);
    expect(getEntity(store, "ip_address", "9.9.9.9")).toBe(e); // same record via the alias
  });
});

describe("buildEntityDb — GATE FAITHFUL (mirrors model.ts)", () => {
  it("runRecordToIngest drops inadmissible junk and demotes a no-infra promoted-claim to a lead", () => {
    const promoted: Finding[] = [
      { entity: "20240101", entity_type: "date" }, // junk: YYYYMMDD placeholder -> inadmissible
      { entity: "naked.com", entity_type: "domain", source_count: 2, infra_source_count: 0 }, // grade B but no infra -> lead
      { entity: "1.1.1.1", entity_type: "ip", source_count: 2, infra_source_count: 2 }, // promotes
    ];
    const store = buildEntityDb([runRecordToIngest("obj", promoted, [])]);
    expect(getEntity(store, "date", "20240101")).toBeNull(); // junk never lands
    const dom = getEntity(store, "domain", "naked.com")!;
    expect(dom.promoted).toBe(false); // re-gated to a lead despite being in the promoted list
    expect(dom.reasons[0]).toMatch(/infra/i);
    expect(getEntity(store, "ip", "1.1.1.1")!.promoted).toBe(true);
  });

  it("a FORGED HIGH source/infra count is trusted by the same gate (documented boundary, codex D3)", () => {
    // The gate re-checks the STORED counts (exactly as src/graph/model.ts). A forged
    // high count promotes — that requires WRITE access to the encrypted vault (data
    // key already compromised). This test PINS that boundary, it does not endorse it.
    const promoted: Finding[] = [
      { entity: "forged.com", entity_type: "domain", source_count: 9, infra_source_count: 9, grade: "A" },
    ];
    const store = buildEntityDb([runRecordToIngest("obj", promoted, [])]);
    expect(getEntity(store, "domain", "forged.com")!.promoted).toBe(true);
  });
});

describe("graphModelToIngest — model -> linked cross-edges (codex D4/D5)", () => {
  function model(): GraphModel {
    // objective + two entity nodes + a cross-edge between the two entities
    return {
      objective: "dig acme.io",
      nodes: [
        { id: "objective", label: "dig acme.io", kind: "objective", promoted: false },
        { id: "finding:0:ip:5.5.5.5", label: "5.5.5.5", kind: "finding", promoted: true, entityType: "ip", grade: "A", sourceCount: 2, infraSourceCount: 2 },
        { id: "finding:1:domain:acme.io", label: "acme.io", kind: "finding", promoted: true, entityType: "domain", grade: "B", sourceCount: 1, infraSourceCount: 1 },
      ],
      edges: [
        { from: "objective", to: "finding:0:ip:5.5.5.5", kind: "promoted" },
        { from: "objective", to: "finding:1:domain:acme.io", kind: "promoted" },
        { from: "finding:1:domain:acme.io", to: "finding:0:ip:5.5.5.5", kind: "promoted" }, // cross-edge
      ],
    };
  }

  it("skips the objective node and turns the cross-edge into a directed linked connection", () => {
    const store = buildEntityDb([graphModelToIngest(model())]);
    expect(getEntity(store, "objective", "dig acme.io")).toBeNull(); // D4

    const domConns = connectionsFor(store, "domain", "acme.io");
    const linked = domConns.find((c) => c.relType === "linked")!;
    expect(linked.direction).toBe("out"); // domain -> ip
    expect(linked.other.value).toBe("5.5.5.5");

    const ipConns = connectionsFor(store, "ip", "5.5.5.5");
    expect(ipConns.find((c) => c.relType === "linked")!.direction).toBe("in"); // ip <- domain
  });
});

describe("edgeEvidence — symmetric (codex D5)", () => {
  it("resolves the same record whichever endpoint order is asked", () => {
    const store = buildEntityDb([
      run("r", [ie("a.com", "domain", true, { infraSourceCount: 2 }), ie("b.com", "domain", true, { infraSourceCount: 2 })]),
    ]);
    const ab = edgeEvidence(store, { type: "domain", value: "a.com" }, { type: "domain", value: "b.com" });
    const ba = edgeEvidence(store, { type: "domain", value: "b.com" }, { type: "domain", value: "a.com" });
    expect(ab).toBeTruthy();
    expect(ba).toBeTruthy();
    expect(ab!.relType).toBe("co_occurs");
    expect(ab!.relType).toBe(ba!.relType);
    expect(ab!.runs).toEqual(["r"]);
  });

  it("prefers a stronger relType when two entities are both linked and co_occurring", () => {
    const store = buildEntityDb([
      run(
        "r",
        [ie("x.com", "domain", true, { infraSourceCount: 2 }), ie("9.9.9.9", "ip", true, { infraSourceCount: 2 })],
        [{ fromValue: "x.com", fromType: "domain", toValue: "9.9.9.9", toType: "ip", promoted: true }],
      ),
    ]);
    const ev = edgeEvidence(store, { type: "domain", value: "x.com" }, { type: "ip", value: "9.9.9.9" });
    expect(ev!.relType).toBe("linked"); // linked beats co_occurs
  });

  it("returns null for two unrelated entities", () => {
    const store = buildEntityDb([
      run("r1", [ie("a.com", "domain", true, { infraSourceCount: 2 })]),
      run("r2", [ie("z.com", "domain", true, { infraSourceCount: 2 })]),
    ]);
    expect(edgeEvidence(store, { type: "domain", value: "a.com" }, { type: "domain", value: "z.com" })).toBeNull();
  });
});

describe("coOccurrencesFor + buildDossier (derived, no fabrication)", () => {
  it("coOccurrencesFor is exactly the co_occurs subset", () => {
    const store = buildEntityDb([
      run("r", [ie("a.com", "domain", true, { infraSourceCount: 2 }), ie("b.com", "domain", true, { infraSourceCount: 2 })]),
    ]);
    const co = coOccurrencesFor(store, "domain", "a.com");
    expect(co).toHaveLength(1);
    expect(co[0].relType).toBe("co_occurs");
  });

  it("a single-run entity's dossier reports exactly 1 run (no fabrication)", () => {
    const store = buildEntityDb([run("only run", [ie("a.com", "domain", true, { sourceCount: 2, infraSourceCount: 2, grade: "A" })])]);
    const d = buildDossier(store, "domain", "a.com")!;
    expect(d.headline).toContain("a.com");
    expect(d.headline).toContain("promoted");
    expect(d.lines.some((l) => l.includes("Seen in 1 run(s)"))).toBe(true);
    expect(d.lines.some((l) => l.includes("Sources: 2 (infra 2)"))).toBe(true);
  });

  it("a held lead's dossier carries the held reason; unknown entity -> null", () => {
    const store = buildEntityDb([runRecordToIngest("obj", [], [{ finding: { entity: "Jane Roe", entity_type: "person" }, verdict: {} as GateVerdict }])]);
    const d = buildDossier(store, "person", "Jane Roe")!;
    expect(d.headline).toContain("lead");
    expect(d.lines.some((l) => l.startsWith("Held:"))).toBe(true);
    expect(buildDossier(store, "domain", "nope.com")).toBeNull();
  });
});

describe("computeAliasLinks (INC-2: port of auto_link_aliases + _similar)", () => {
  it("links two person entities whose names share >= 0.8 token overlap (reorder = 1.0), symmetric", () => {
    const store = buildEntityDb([
      run("r", [ie("John Smith", "person", true), ie("Smith John", "person", true)]),
    ]);
    const links = computeAliasLinks(store);
    const ka = entityKey({ type: "person", value: "john smith" });
    const kb = entityKey({ type: "person", value: "smith john" });
    expect(links[ka]).toEqual(["Smith John"]); // a knows b
    expect(links[kb]).toEqual(["John Smith"]); // and b knows a (symmetric)
  });

  it("links by STABLE ref.type, not the mutable display type (codex: a retyped person keeps its aliases)", () => {
    // Simulate a typing/correction overlay: display type is "url" but the identity ref.type stays person.
    const mk = (name: string) => ({
      ref: { type: "person", value: name.toLowerCase() }, label: name, type: "url", // display overlaid
      role: "operator", promoted: false, sourceCount: 1, infraSourceCount: 0, runs: ["r"], reasons: [],
    });
    const store: EntityStore = {
      entities: {
        [entityKey({ type: "person", value: "john smith" })]: mk("John Smith"),
        [entityKey({ type: "person", value: "smith john" })]: mk("Smith John"),
      },
      connections: {}, cooccurTruncated: false,
    };
    const links = computeAliasLinks(store);
    expect(links[entityKey({ type: "person", value: "john smith" })]).toEqual(["Smith John"]);
  });

  it("does NOT link across types (a person and a same-named domain are not aliases)", () => {
    const store = buildEntityDb([
      run("r", [ie("acme labs", "person", true), ie("acme labs", "domain", true)]),
    ]);
    // person↔person only; the domain is never a person, and the person has no person twin.
    expect(computeAliasLinks(store)).toEqual({});
  });

  it("does NOT link byte-identical canonical names (same actor, just typed twice)", () => {
    // person + person_candidate with the SAME value → two store rows, identical ref.value → skipped
    const store = buildEntityDb([
      run("r", [ie("Jane Roe", "person", true), ie("Jane Roe", "person_candidate", true)]),
    ]);
    expect(computeAliasLinks(store)).toEqual({});
  });

  it("does NOT link person names below the 0.8 threshold", () => {
    const store = buildEntityDb([
      run("r", [ie("John Smith", "person", true), ie("John Doe", "person", true)]), // overlap 0.5
    ]);
    expect(computeAliasLinks(store)).toEqual({});
  });

  it("returns {} above ALIAS_MAX_PERSONS (codex D6 bound — the synchronous pass can't freeze)", () => {
    const big: EntityStore = { entities: {}, connections: {}, cooccurTruncated: false };
    for (let i = 0; i <= ALIAS_MAX_PERSONS; i++) {
      const name = `Person ${i}`;
      big.entities[entityKey({ type: "person", value: name.toLowerCase() })] = {
        ref: { type: "person", value: name.toLowerCase() }, label: name, type: "person",
        role: "operator", promoted: false, sourceCount: 1, infraSourceCount: 0, runs: ["r"], reasons: [],
      };
    }
    expect(Object.keys(big.entities).length).toBeGreaterThan(ALIAS_MAX_PERSONS);
    expect(computeAliasLinks(big)).toEqual({});
  });

  it("aliasLinksFor memoizes per store object (same reference returned across calls)", () => {
    const store = buildEntityDb([
      run("r", [ie("John Smith", "person", true), ie("Smith John", "person", true)]),
    ]);
    expect(aliasLinksFor(store)).toBe(aliasLinksFor(store)); // cached, not recomputed
  });
});

describe("hostile delimiter (codex D7) + degenerate inputs", () => {
  it("{type:'a', value:'b|c'} and {type:'a|b', value:'c'} stay DISTINCT entities", () => {
    const store = buildEntityDb([run("r", [ie("b|c", "a", true), ie("c", "a|b", true)])]);
    const e1 = getEntity(store, "a", "b|c")!;
    const e2 = getEntity(store, "a|b", "c")!;
    expect(e1).toBeTruthy();
    expect(e2).toBeTruthy();
    expect(e1).not.toBe(e2);
    expect(Object.keys(store.entities)).toHaveLength(2);
  });

  it("empty input does not throw and yields an empty store", () => {
    const store = buildEntityDb([]);
    expect(Object.keys(store.entities)).toHaveLength(0);
    expect(store.cooccurTruncated).toBe(false);
    expect(connectionsFor(store, "domain", "x.com")).toEqual([]);
    expect(coOccurrencesFor(store, "domain", "x.com")).toEqual([]);
  });
});

describe("page accessors: allEntities + crossRunEntities", () => {
  it("allEntities sorts promoted-first then by grade, and excludes the objective", () => {
    const store = buildEntityDb([
      run("r", [
        ie("lead.com", "domain", false, { grade: "C" }),
        ie("1.1.1.1", "ip", true, { grade: "A", infraSourceCount: 2 }),
      ]),
    ]);
    const list = allEntities(store);
    expect(list.map((e) => e.label)).toEqual(["1.1.1.1", "lead.com"]); // promoted A before lead C
    expect(list.some((e) => e.type === "objective")).toBe(false);
  });

  it("crossRunEntities returns only entities seen in >1 run", () => {
    const store = buildEntityDb([
      run("r1", [ie("shared.com", "domain", true, { infraSourceCount: 2 }), ie("only1.com", "domain", true, { infraSourceCount: 2 })]),
      run("r2", [ie("shared.com", "domain", true, { infraSourceCount: 2 }), ie("only2.com", "domain", true, { infraSourceCount: 2 })]),
    ]);
    const cross = crossRunEntities(store);
    expect(cross.map((e) => e.label)).toEqual(["shared.com"]);
    expect(cross[0].runs.sort()).toEqual(["r1", "r2"]);
  });
});

describe("co-occurrence cap (codex D6 — bounded, no silent truncation)", () => {
  it("a 500-entity run sets cooccurTruncated, bounds co_occurs pairing, keeps surfaced_in for ALL", () => {
    const ents: IngestEntity[] = [];
    for (let i = 0; i < 500; i++) ents.push(ie(`e${i}.com`, "domain", true, { infraSourceCount: 2 }));
    const store = buildEntityDb([run("huge", ents)]);

    expect(store.cooccurTruncated).toBe(true);

    // an entity inside the cap pairs with the other (cap-1) capped entities
    const inCap = coOccurrencesFor(store, "domain", "e0.com");
    expect(inCap).toHaveLength(MAX_COOCCUR_ENTITIES - 1);

    // an entity beyond the cap has NO co_occurs but STILL its surfaced_in (every entity is in the run)
    const beyond = connectionsFor(store, "domain", "e400.com");
    expect(beyond.some((c) => c.relType === "co_occurs")).toBe(false);
    expect(beyond.some((c) => c.relType === "surfaced_in")).toBe(true);

    // every one of the 500 entities landed
    expect(Object.keys(store.entities)).toHaveLength(500);

    // the dossier honestly surfaces the sampling
    const d = buildDossier(store, "domain", "e0.com")!;
    expect(d.lines.some((l) => l.includes("sampled"))).toBe(true);
  });
});
