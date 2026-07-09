import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  putAnalysis,
  applyCorrection,
  entityDbFor,
  entityScoreBreakdownFor,
  typedRelationshipsFor,
  entityCorrectionsFor,
  entityAppearancesFor,
  getEntityDossierOverride,
  setEntityDossierOverride,
} from "../../src/agent/session.js";
import { getEntity, canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";

// sf-entity-detail: the per-entity DETAIL-fold projections (the entity.html depth) that BOTH folds
// (the /entities page fold + the graph drawer) read. All READ-ONLY + key-redacted, except the editable
// dossier override. The score breakdown's invariant is the headline: the displayed total ALWAYS equals
// the stored threatScore (propPts is the exact residual), so the fold can never drift from the graph.

const LEAK_KEY = "sk-ant-LEAKVALUE0001";

async function seededVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, LEAK_KEY);

  // A run that surfaces two entities (so the entity DB builds records for both endpoints).
  await vault.put("run:Investigate acme.io", {
    objective: "Investigate acme.io",
    steps: [],
    promoted: [
      { entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "1.2.3.4", entity_type: "ip", grade: "B", source_count: 1, infra_source_count: 1 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });

  const keyAcme = canonKey("domain", "acme.io");
  const keyIp = canonKey("ip", "1.2.3.4");
  const keyGhost = canonKey("domain", "ghost.example"); // NOT in the store → its relationship must drop

  const analysis = emptyAnalysis("default");
  analysis.schema = { caseType: "intrusion-apt", types: [], roles: [{ name: "operator", weight: 1.0 }], subRoles: [], noiseRules: [] } as never;
  analysis.roles = { [keyAcme]: "operator" };
  analysis.entityScores = {
    [keyAcme]: { threatScore: 57, degree: 1, reportCount: 1 },
  };
  analysis.nodeMetrics = {
    [keyAcme]: { degreeCentrality: 1, betweenness: 0, eigenvector: 0.5, community: 0 },
  };
  analysis.relationships = [
    { srcKey: keyAcme, dstKey: keyIp, relType: "hosted_on", confidence: "high", evidence: "A record points to 1.2.3.4" },
    { srcKey: keyAcme, dstKey: keyGhost, relType: "linked_to", confidence: "low", evidence: "forged endpoint" },
  ];
  await putAnalysis(vault, analysis);
  return vault;
}

describe("sf-entity-detail — score breakdown", () => {
  it("the displayed total ALWAYS equals the stored threatScore (propPts is the exact residual)", async () => {
    const vault = await seededVault();
    const store = entityDbFor(vault);
    const acme = getEntity(store, "domain", "acme.io")!;
    const b = entityScoreBreakdownFor(vault, acme.ref, acme.role, acme.promoted)!;
    expect(b).toBeTruthy();
    expect(b.total).toBe(57);
    // the parts sum to the stored total — the fold can never show a number the graph doesn't
    expect(b.rolePts + b.reportPts + b.degreePts + b.priorPts + b.propPts).toBe(b.total);
    expect(b.reportPts).toBe(b.reportCount * 5);
    expect(b.degreePts).toBe(b.degree * 1);
    expect(b.metrics).not.toBeNull();
    expect(b.metrics!.eigenvector).toBe(0.5);
  });

  it("returns null when the entity has no stored score (un-Processed / didn't score)", async () => {
    const vault = await seededVault();
    const store = entityDbFor(vault);
    const ip = getEntity(store, "ip", "1.2.3.4")!;
    expect(entityScoreBreakdownFor(vault, ip.ref, ip.role, ip.promoted)).toBeNull();
  });
});

describe("sf-entity-detail — typed relationships", () => {
  it("resolves the other endpoint + direction, and DROPS a relationship to a non-existent entity", async () => {
    const vault = await seededVault();
    const keyAcme = canonKey("domain", "acme.io");
    const rels = typedRelationshipsFor(vault, keyAcme);
    expect(rels).toHaveLength(1); // the ghost relationship is dropped (its endpoint isn't in the store)
    expect(rels[0].relType).toBe("hosted_on");
    expect(rels[0].direction).toBe("out");
    expect(rels[0].otherLabel).toBe("1.2.3.4");
    expect(rels[0].otherRef.type).toBe("ip");
  });

  it("reports the reverse direction from the other endpoint's view", async () => {
    const vault = await seededVault();
    const keyIp = canonKey("ip", "1.2.3.4");
    const rels = typedRelationshipsFor(vault, keyIp);
    expect(rels).toHaveLength(1);
    expect(rels[0].direction).toBe("in");
    expect(rels[0].otherLabel).toBe("acme.io");
  });
});

describe("sf-entity-detail — appears-in + corrections", () => {
  it("lists the runs an entity appeared in with the gate evidentiary weight", async () => {
    const vault = await seededVault();
    const store = entityDbFor(vault);
    const acme = getEntity(store, "domain", "acme.io")!;
    const apps = entityAppearancesFor(vault, acme.ref);
    expect(apps).toHaveLength(1);
    expect(apps[0].objective).toBe("Investigate acme.io");
    expect(apps[0].promoted).toBe(true);
    expect(apps[0].grade).toBe("A");
    expect(apps[0].sourceCount).toBe(2);
  });

  it("returns ONLY the active corrections that touch one entity", async () => {
    const vault = await seededVault();
    const keyAcme = canonKey("domain", "acme.io");
    const keyIp = canonKey("ip", "1.2.3.4");
    await applyCorrection(vault, "domain", "acme.io", "role", "channel");
    const onAcme = entityCorrectionsFor(vault, keyAcme);
    expect(onAcme).toHaveLength(1);
    expect(onAcme[0].predicate).toBe("role");
    expect(onAcme[0].value).toBe("channel");
    expect(onAcme[0].active).toBe(true);
    // a different entity's slice does not see acme's correction
    expect(entityCorrectionsFor(vault, keyIp)).toHaveLength(0);
  });
});

describe("sf-entity-detail — editable dossier override (the ONE persisted write)", () => {
  it("round-trips a saved override; a blank text reverts to null (AI dossier shows again)", async () => {
    const vault = await seededVault();
    const store = entityDbFor(vault);
    const acme = getEntity(store, "domain", "acme.io")!;
    expect(getEntityDossierOverride(vault, acme.ref)).toBeNull();
    await setEntityDossierOverride(vault, acme.ref, "Analyst note: confirmed C2 staging.");
    const saved = getEntityDossierOverride(vault, acme.ref)!;
    expect(saved.text).toBe("Analyst note: confirmed C2 staging.");
    expect(saved.author).toBeTruthy();
    await setEntityDossierOverride(vault, acme.ref, ""); // revert = blank write (the wired path)
    expect(getEntityDossierOverride(vault, acme.ref)).toBeNull();
  });

  it("redacts the live key out of a saved override text (never persist-then-redact)", async () => {
    const vault = await seededVault();
    const store = entityDbFor(vault);
    const acme = getEntity(store, "domain", "acme.io")!;
    await setEntityDossierOverride(vault, acme.ref, `key is ${LEAK_KEY} do not store`);
    const saved = getEntityDossierOverride(vault, acme.ref)!;
    expect(saved.text).not.toContain(LEAK_KEY);
    expect(saved.text).toContain("[REDACTED]");
  });
});

describe("sf-entity-detail — redaction belt", () => {
  it("the live key never appears in ANY of the detail-fold projections", async () => {
    const vault = await seededVault();
    const store = entityDbFor(vault);
    const acme = getEntity(store, "domain", "acme.io")!;
    const keyAcme = canonKey("domain", "acme.io");
    const blob = JSON.stringify([
      entityScoreBreakdownFor(vault, acme.ref, acme.role, acme.promoted),
      typedRelationshipsFor(vault, keyAcme),
      entityCorrectionsFor(vault, keyAcme),
      entityAppearancesFor(vault, acme.ref),
    ]);
    expect(blob).not.toContain(LEAK_KEY);
  });

  // codex impl-review belt: typedRelationshipsFor redacts the free-text evidence on READ even when a
  // record bypasses the putAnalysis write-redaction (a legacy/forged relationship). Seed the analysis
  // record DIRECTLY (not through putAnalysis) so the evidence keeps the live key, then assert it is
  // redacted out at read time.
  it("redacts a forged relationship's evidence on read (write-redaction bypassed)", async () => {
    const vault = await seededVault();
    const keyAcme = canonKey("domain", "acme.io");
    const keyIp = canonKey("ip", "1.2.3.4");
    const forged = emptyAnalysis("default");
    forged.relationships = [
      { srcKey: keyAcme, dstKey: keyIp, relType: "hosted_on", confidence: "high", evidence: `secret in evidence ${LEAK_KEY}` },
    ];
    await vault.put("analysis:default", forged); // bypass putAnalysis → evidence is NOT redacted on write
    const rels = typedRelationshipsFor(vault, keyAcme);
    expect(rels).toHaveLength(1);
    expect(rels[0].evidence).not.toContain(LEAK_KEY); // the read belt caught it
    expect(rels[0].evidence).toContain("[REDACTED]");
  });

  // codex impl-review belt: getEntityDossierOverride rejects a secret-tainted ref (redact-first, before
  // canonKey lowercases the marker) — returns null without throwing or forming a raw key from the secret.
  it("getEntityDossierOverride returns null for a secret-tainted ref (no raw-key lookup)", async () => {
    const vault = await seededVault();
    expect(getEntityDossierOverride(vault, { type: "domain", value: `host-${LEAK_KEY}.example` })).toBeNull();
  });
});
