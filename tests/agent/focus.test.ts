import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, focusFor, focusItemsFor, focusGapsFor } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";

// sf-focus: focusFor (focusItemsFor + focusGapsFor) is a PURE deterministic projection over the persisted
// analyze clusters + typed_relationships + entityScores — a faithful port of focus.py _gather_top +
// compute_gaps. No LLM, no fetch, no vault write. These tests build the analysis record directly
// (bypassing putAnalysis) so they also prove read-side ranking, cluster/rel resolution, and the gap rules.

const KEY = "sk-ant-FOCUS-secret-7373";

// A small case:
//   operator "john smith"  : role operator, score 90, degree 2, 2 reports, promoted (SEED), cluster Ring,
//                            typed rel deployed -> alpha.example.com (a cross-cluster edge)
//   domain "alpha.example.com" : role infra,  score 50, degree 1, 2 reports, cluster Infra
//   ioc "bad.example.org"  : role ioc, score 30, degree 0, 1 report (uncorroborated + uninvestigated)
//   noise "junk"           : role noise (excluded from ranking + gaps)
//   person_candidate "j. s.": unresolved (drives the unconsolidated gap; excluded from ranking)
const OP = { type: "person", value: "john smith" };
const DOM = { type: "domain", value: "alpha.example.com" };
const IOC = { type: "ip", value: "203.0.113.9" };
const NOISE = { type: "url", value: "broken'fragment" };
const PC = { type: "person_candidate", value: "j. s." };

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  return vault;
}

// Seed one run so the entities exist in the store, then write the analysis record with roles + clusters +
// rels + scores. The store role comes from the analysis `roles` overlay (applyAnalysis), so set them there.
async function vaultWithCase(): Promise<Vault> {
  const vault = await freshVault();
  await vault.put("run:Investigate the ring", {
    objective: "Investigate the ring",
    steps: [],
    promoted: [
      { entity: OP.value, entity_type: OP.type, grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: DOM.value, entity_type: DOM.type, grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: IOC.value, entity_type: IOC.type, grade: "B", source_count: 1, infra_source_count: 1 },
      { entity: NOISE.value, entity_type: NOISE.type, grade: "D", source_count: 1, infra_source_count: 0 },
      { entity: PC.value, entity_type: PC.type, grade: "D", source_count: 1, infra_source_count: 0 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  await vault.put("analysis:default", {
    ...emptyAnalysis("default"),
    roles: {
      [canonKey(OP.type, OP.value)]: "operator",
      [canonKey(DOM.type, DOM.value)]: "infra",
      [canonKey(IOC.type, IOC.value)]: "ioc",
      [canonKey(NOISE.type, NOISE.value)]: "noise",
    },
    clusters: [
      { name: "Operator Ring", kind: "ring", description: "the crew", memberKeys: [canonKey(OP.type, OP.value)] },
      { name: "Drainer Infra", kind: "infrastructure_block", description: "front domains", memberKeys: [canonKey(DOM.type, DOM.value)] },
    ],
    relationships: [
      { srcKey: canonKey(OP.type, OP.value), dstKey: canonKey(DOM.type, DOM.value), relType: "deployed", confidence: "high", evidence: "deployed the drainer" },
    ],
    entityScores: {
      [canonKey(OP.type, OP.value)]: { threatScore: 90, degree: 2, reportCount: 2 },
      [canonKey(DOM.type, DOM.value)]: { threatScore: 50, degree: 1, reportCount: 2 },
      [canonKey(IOC.type, IOC.value)]: { threatScore: 30, degree: 0, reportCount: 1 },
    },
  });
  return vault;
}

describe("focusItemsFor (sf-focus: top-N threat-ranked items)", () => {
  it("ranks the scored entities by threat score, descending", async () => {
    const vault = await vaultWithCase();
    const items = focusItemsFor(vault);
    expect(items.map((i) => i.name)).toEqual(["john smith", "alpha.example.com", "203.0.113.9"]);
    expect(items.map((i) => i.rank)).toEqual([1, 2, 3]);
    expect(items.map((i) => i.score)).toEqual([90, 50, 30]);
  });

  it("excludes noise + person_candidate + un-scored entities (the focus.py WHERE)", async () => {
    const vault = await vaultWithCase();
    const labels = focusItemsFor(vault).map((i) => i.name);
    expect(labels).not.toContain("broken'fragment"); // role:noise
    expect(labels).not.toContain("j. s."); // person_candidate
  });

  it("carries the SEED flag (promoted), cluster chips, and the top typed-rel chip", async () => {
    const vault = await vaultWithCase();
    const op = focusItemsFor(vault).find((i) => i.name === "john smith")!;
    expect(op.promoted).toBe(true); // SEED
    expect(op.role).toBe("operator");
    expect(op.clusters.map((c) => c.name)).toContain("Operator Ring");
    expect(op.topRelationships.length).toBe(1);
    expect(op.topRelationships[0].relType).toBe("deployed");
    expect(op.topRelationships[0].direction).toBe("out");
    expect(op.topRelationships[0].otherLabel).toBe("alpha.example.com");
    // the deterministic _build_why sentence mentions the seed + cluster + the relationship.
    expect(op.why).toContain("known-bad");
    expect(op.why).toContain("Operator Ring");
    expect(op.why).toContain("deployed");
  });

  it("is honest-empty pre-Process (no analysis record → no scored entities → no items)", async () => {
    const vault = await freshVault();
    await vault.put("run:x", {
      objective: "x", steps: [],
      promoted: [{ entity: OP.value, entity_type: OP.type, grade: "A", source_count: 2, infra_source_count: 0 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    expect(focusItemsFor(vault)).toEqual([]);
  });
});

describe("focusGapsFor (sf-focus: deterministic gaps — focus.py compute_gaps)", () => {
  it("fires the uninvestigated gap for a top actor with degree 0", async () => {
    const vault = await vaultWithCase();
    const gaps = focusGapsFor(vault);
    const uninv = gaps.find((g) => g.kind === "uninvestigated")!;
    expect(uninv, "uninvestigated gap fires").toBeTruthy();
    expect(uninv.severity).toBe("medium");
    expect(uninv.entities.map((e) => e.name)).toContain("203.0.113.9"); // degree 0
    expect(uninv.title).toContain("not investigated yet");
  });

  it("fires the uncorroborated gap for a top actor seen in <= 1 report", async () => {
    const vault = await vaultWithCase();
    const uncorr = focusGapsFor(vault).find((g) => g.kind === "uncorroborated")!;
    expect(uncorr, "uncorroborated gap fires").toBeTruthy();
    expect(uncorr.entities.map((e) => e.name)).toContain("203.0.113.9"); // 1 report
    // the 2-report actors are NOT in the uncorroborated sample.
    expect(uncorr.entities.map((e) => e.name)).not.toContain("john smith");
    expect(uncorr.title).toContain("only one report");
  });

  it("fires the unconsolidated gap counting unresolved person_candidate entities", async () => {
    const vault = await vaultWithCase();
    const unc = focusGapsFor(vault).find((g) => g.kind === "unconsolidated")!;
    expect(unc, "unconsolidated gap fires").toBeTruthy();
    expect(unc.count).toBe(1); // the one person_candidate "j. s."
    expect(unc.severity).toBe("low");
    expect(unc.title).toContain("person candidate");
  });

  it("treats an actor never enriched as uninvestigated ONCE enrichment exists", async () => {
    const vault = await vaultWithCase();
    // give john smith degree-2 already (not degree-0), then add an enrich run for the DOMAIN only.
    // hasEnr becomes true → john smith (never enriched) now qualifies for the merged uninvestigated gap.
    await vault.put("run:enrich: dns alpha.example.com", {
      objective: "enrich: dns alpha.example.com",
      provider: "dns",
      target: "alpha.example.com",
      sourceKind: "enrich",
      at: new Date().toISOString(),
      steps: [], promoted: [], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    const uninv = focusGapsFor(vault).find((g) => g.kind === "uninvestigated")!;
    const names = uninv.entities.map((e) => e.name);
    expect(names).toContain("john smith"); // never enriched, enrichment exists → uninvestigated
    expect(names).not.toContain("alpha.example.com"); // it WAS enriched (the dns run target)
  });

  it("returns [] gaps + items pre-Process (focusFor honest empty)", async () => {
    const vault = await freshVault();
    const focus = focusFor(vault);
    expect(focus.items).toEqual([]);
    expect(focus.gaps).toEqual([]);
  });
});

describe("focusFor: read-only + key-safe", () => {
  it("issues no vault write", async () => {
    const vault = await vaultWithCase();
    const putSpy = vi.spyOn(vault, "put");
    focusFor(vault);
    expect(putSpy).not.toHaveBeenCalled();
  });

  it("never surfaces the live key (a forged cluster name / rel evidence is redacted on read)", async () => {
    const vault = await freshVault();
    await vault.put("run:r", {
      objective: "r", steps: [],
      promoted: [
        { entity: OP.value, entity_type: OP.type, grade: "A", source_count: 2, infra_source_count: 0 },
        { entity: DOM.value, entity_type: DOM.type, grade: "A", source_count: 2, infra_source_count: 2 },
      ],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    await vault.put("analysis:default", {
      ...emptyAnalysis("default"),
      roles: { [canonKey(OP.type, OP.value)]: "operator", [canonKey(DOM.type, DOM.value)]: "infra" },
      clusters: [{ name: `leaked-${KEY}-ring`, kind: "ring", description: "", memberKeys: [canonKey(OP.type, OP.value)] }],
      relationships: [
        { srcKey: canonKey(OP.type, OP.value), dstKey: canonKey(DOM.type, DOM.value), relType: "deployed", confidence: "high", evidence: `secret ${KEY} here` },
      ],
      entityScores: { [canonKey(OP.type, OP.value)]: { threatScore: 90, degree: 1, reportCount: 1 } },
    });
    const json = JSON.stringify(focusFor(vault));
    expect(json).not.toContain(KEY); // the raw key never reaches /focus
  });
});
