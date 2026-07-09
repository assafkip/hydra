import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, exportFilesFor, exportModelFor } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";
import { buildStixBundle, buildMispEvent, buildEntitiesCsv, buildRelationshipsCsv, buildClustersCsv, type ExportModel } from "../../src/export/intel.js";

// sf-exports: the serializers (intel.ts) are a verbatim port of intel_exports.py; exportModelFor (session)
// builds the KEY-REDACTED model. The two parts are tested separately: pure format faithfulness over a
// hand-built model, then the model-assembly + redaction belt over a seeded vault.

const MODEL: ExportModel = {
  investigationName: "test-case",
  entities: [
    { id: 1, name: "1.2.3.4", type: "ip", role: "ioc", threatScore: 50, degree: 2, reportCount: 1, clusters: ["Infra"] },
    { id: 2, name: "evil.com", type: "domain", role: "operator", threatScore: 40, degree: 1, reportCount: 1, clusters: ["Infra"] },
    { id: 3, name: "John Smith", type: "person", role: "channel", threatScore: 30, degree: 1, reportCount: 1, clusters: ["Ring"] },
    { id: 4, name: "lead.example", type: "domain", role: "", threatScore: 0, degree: 0, reportCount: 0, clusters: [] }, // no explicit role
    { id: 5, name: "5.6.7.8", type: "ip", role: "infra", threatScore: 5, degree: 0, reportCount: 0, clusters: [] }, // infra → MISP-excluded
  ],
  relationships: [
    { srcId: 3, dstId: 2, srcName: "John Smith", dstName: "evil.com", relType: "deployed", confidence: "high", evidence: "deployed it" },
  ],
  clusters: [
    { name: "Infra", kind: "infrastructure_block", description: "the infra", members: ["1.2.3.4", "evil.com"] },
    { name: "Ring", kind: "ring", description: "the ring, with a comma", members: ["John Smith"] },
  ],
};

describe("intel serializers — STIX 2.1", () => {
  it("emits an identity SDO + one object per mapped entity + a relationship SRO", () => {
    const bundle = JSON.parse(buildStixBundle(MODEL));
    expect(bundle.type).toBe("bundle");
    const byType = (t: string) => bundle.objects.filter((o: { type: string }) => o.type === t);
    expect(byType("identity").some((o: { name: string; identity_class: string }) => o.identity_class === "organization")).toBe(true);
    expect(byType("ipv4-addr")[0].value).toBe("1.2.3.4");
    expect(byType("domain-name").some((o: { value: string }) => o.value === "evil.com")).toBe(true);
    const person = byType("identity").find((o: { identity_class: string }) => o.identity_class === "individual");
    expect(person.name).toBe("John Smith");
    expect(person.roles).toEqual(["channel"]); // explicit role flows into the SDO
    const rel = byType("relationship")[0];
    expect(rel.relationship_type).toBe("deployed");
    expect(rel.source_ref).toMatch(/^identity--/); // John Smith (person → identity)
    expect(rel.target_ref).toMatch(/^domain-name--/); // evil.com
    expect(rel.x_kipi_confidence).toBe("high");
  });
});

describe("intel serializers — MISP", () => {
  it("includes ONLY entities whose EXPLICIT role is operator/channel/ioc AND have a MISP type", () => {
    const event = JSON.parse(buildMispEvent(MODEL)).Event;
    const values = event.Attribute.map((a: { value: string }) => a.value).sort();
    // 1.2.3.4 (ioc/ip-src) + evil.com (operator/domain). John Smith (channel) has NO misp type (person);
    // lead.example (no role) + 5.6.7.8 (infra) are excluded.
    expect(values).toEqual(["1.2.3.4", "evil.com"]);
    const ip = event.Attribute.find((a: { value: string }) => a.value === "1.2.3.4");
    expect(ip.type).toBe("ip-src");
    expect(ip.to_ids).toBe(true); // ioc → to_ids
    expect(ip.category).toBe("Network activity");
    expect(event.published).toBe(false);
  });
});

describe("intel serializers — CSV", () => {
  it("entities.csv has the exact columns; a no-explicit-role entity has a blank role", () => {
    const csv = buildEntitiesCsv(MODEL);
    const lines = csv.trim().split("\r\n");
    expect(lines[0]).toBe("id,name,type,role,threat_score,degree,report_count,clusters");
    expect(lines).toHaveLength(6); // header + 5 entities
    const leadRow = lines.find((l) => l.startsWith("4,lead.example"))!;
    expect(leadRow).toBe("4,lead.example,domain,,0,0,0,"); // blank role + blank clusters
  });

  it("relationships.csv emits src,rel_type,dst,confidence,evidence", () => {
    const lines = buildRelationshipsCsv(MODEL).trim().split("\r\n");
    expect(lines[0]).toBe("src,rel_type,dst,confidence,evidence");
    expect(lines[1]).toBe("John Smith,deployed,evil.com,high,deployed it");
  });

  it("clusters.csv RFC-4180-quotes a description containing a comma", () => {
    const csv = buildClustersCsv(MODEL);
    expect(csv).toContain('Ring,ring,"the ring, with a comma",John Smith'); // the comma cell is quoted
  });

  it("neutralizes CSV formula injection — a value starting with = / + / - / @ gets a single-quote prefix", () => {
    const malicious: ExportModel = {
      investigationName: "x",
      entities: [{ id: 1, name: "=cmd|'/c calc'!A0", type: "domain", role: "operator", threatScore: 0, degree: 0, reportCount: 0, clusters: [] }],
      relationships: [{ srcId: 1, dstId: 1, srcName: "@evil.com", dstName: "+attack", relType: "links", confidence: "low", evidence: "-1+1" }],
      clusters: [],
    };
    const ent = buildEntitiesCsv(malicious);
    expect(ent).toContain("'=cmd"); // the formula cell is defanged
    const rels = buildRelationshipsCsv(malicious);
    expect(rels).toContain("'@evil.com");
    expect(rels).toContain("'+attack");
    expect(rels).toContain("'-1+1");
  });
});

// ---- exportModelFor: the redacted model assembly over a seeded vault ----

const LEAK_KEY = "sk-ant-EXPORT-secret-1212";

async function seededVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, LEAK_KEY);
  await vault.put("run:investigate acme.io", {
    objective: "investigate acme.io",
    steps: [],
    promoted: [
      { entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "1.2.3.4", entity_type: "ip", grade: "B", source_count: 1, infra_source_count: 1 },
      { entity: "junk", entity_type: "domain", grade: "D", source_count: 1, infra_source_count: 0 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  const keyAcme = canonKey("domain", "acme.io");
  const keyIp = canonKey("ip", "1.2.3.4");
  const keyJunk = canonKey("domain", "junk");
  const a = emptyAnalysis("default");
  // role decision (founder 2026-06-24): a malicious DOMAIN is `ioc`, never `operator` (operator = people).
  a.roles = { [keyAcme]: "ioc", [keyIp]: "ioc", [keyJunk]: "noise" }; // explicit roles
  a.clusters = [{ name: "Ring", kind: "ring", description: "the operator ring", memberKeys: [keyAcme, keyIp] }];
  a.relationships = [{ srcKey: keyAcme, dstKey: keyIp, relType: "hosted_on", confidence: "high", evidence: "A record" }];
  a.entityScores = { [keyAcme]: { threatScore: 57, degree: 1, reportCount: 1 } };
  await vault.put("analysis:default", a); // direct put → keeps the values raw (so the read belt is exercised below)
  return vault;
}

describe("exportModelFor — model assembly + redaction belt", () => {
  it("uses the EXPLICIT role, drops noise, includes the cluster description, MISP-filters by role", async () => {
    const vault = await seededVault();
    const model = exportModelFor(vault);
    const names = model.entities.map((e) => e.name).sort();
    expect(names).toContain("acme.io");
    expect(names).toContain("1.2.3.4");
    expect(names).not.toContain("junk"); // role:noise dropped
    expect(model.entities.find((e) => e.name === "acme.io")!.role).toBe("ioc");
    expect(model.clusters.find((c) => c.name === "Ring")!.description).toBe("the operator ring"); // from analysisFor
    const misp = JSON.parse(buildMispEvent(model)).Event;
    const mispValues = misp.Attribute.map((x: { value: string }) => x.value).sort();
    expect(mispValues).toEqual(["1.2.3.4", "acme.io"]); // both ioc, noise dropped
  });

  it("redacts the live key out of EVERY export file (belt on the raw analysis record)", async () => {
    const vault = await seededVault();
    // forge a tainted analysis record (bypassing putAnalysis) with the key in a description + evidence.
    const keyAcme = canonKey("domain", "acme.io");
    const keyIp = canonKey("ip", "1.2.3.4");
    const a = emptyAnalysis("default");
    a.roles = { [keyAcme]: "operator", [keyIp]: "ioc" };
    a.clusters = [{ name: `Ring ${LEAK_KEY}`, kind: "ring", description: `secret ${LEAK_KEY}`, memberKeys: [keyAcme, keyIp] }];
    a.relationships = [{ srcKey: keyAcme, dstKey: keyIp, relType: "hosted_on", confidence: "high", evidence: `evidence ${LEAK_KEY}` }];
    await vault.put("analysis:default", a);
    const files = exportFilesFor(vault);
    const blob = [files.stix, files.misp, files.entitiesCsv, files.relationshipsCsv, files.clustersCsv].join("\n");
    expect(blob).not.toContain(LEAK_KEY);
    expect(blob).toContain("[REDACTED]");
  });
});
