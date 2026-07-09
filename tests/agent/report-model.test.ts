import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, reportModelFor } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";

// sf-report-builder: reportModelFor builds the KEY-REDACTED branded-report model (client_report.gather port)
// from the existing redacted accessors — brief:case, focusItemsFor, dossier:<key>, IOC-typed entities,
// listIngestedDocs. The page renders it into the print-ready deliverable.

const LEAK_KEY = "sk-ant-REPORT-secret-3434";

async function seededVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, LEAK_KEY);
  // an ingested doc (sourceKind file_ingest → a "source report" + a scope count).
  await vault.put("run:file: intel.csv #aa11bb", {
    objective: "file: intel.csv #aa11bb",
    steps: [],
    promoted: [
      { entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "1.2.3.4", entity_type: "ip", grade: "B", source_count: 1, infra_source_count: 1 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
    sourceKind: "file_ingest",
    ingestedAt: "2026-06-19T10:00:00.000Z",
    title: "intel.csv",
    sourceType: "csv",
  });
  const keyAcme = canonKey("domain", "acme.io");
  const keyIp = canonKey("ip", "1.2.3.4");
  const a = emptyAnalysis("default");
  // role decision (founder 2026-06-24): a malicious DOMAIN is `ioc`, never `operator` (operator = people).
  a.roles = { [keyAcme]: "ioc", [keyIp]: "ioc" };
  a.entityScores = { [keyAcme]: { threatScore: 57, degree: 1, reportCount: 1 }, [keyIp]: { threatScore: 40, degree: 1, reportCount: 1 } };
  await vault.put("analysis:default", a);
  await vault.put("brief:case", { objective: "case", brief: "## Summary\nThe acme network fronts a drainer.", builtOn: 1 });
  await vault.put(`dossier:${keyAcme}`, { type: "domain", value: "acme.io", dossier: "## Dossier\nacme.io is the operator front." });
  return vault;
}

describe("reportModelFor — the branded-report model", () => {
  it("assembles brief / actors / dossiers / IOCs / sources, cross-case empty in single-vault", async () => {
    const vault = await seededVault();
    const m = reportModelFor(vault);
    expect(m.execSummary).toContain("The acme network fronts a drainer."); // brief:case
    expect(m.stats.reports).toBe(1); // one ingested doc
    expect(m.stats.entities).toBeGreaterThanOrEqual(2);

    const actorNames = m.topActors.map((x) => x.name).sort();
    expect(actorNames).toContain("acme.io");
    expect(actorNames).toContain("1.2.3.4");
    expect(m.topActors.find((x) => x.name === "acme.io")!.role).toBe("ioc");
    expect(m.topActors.find((x) => x.name === "acme.io")!.why).toBeTruthy(); // the _build_why sentence

    const dossier = m.dossiers.find((x) => x.name === "acme.io")!;
    expect(dossier).toBeTruthy();
    expect(dossier.source).toBe("ai"); // from the dossier:<key> record
    expect(dossier.body).toContain("acme.io is the operator front.");

    const iocNames = m.iocs.map((x) => x.name).sort();
    expect(iocNames).toContain("acme.io"); // domain ∈ IOC types
    expect(iocNames).toContain("1.2.3.4"); // ip ∈ IOC types
    expect(m.iocs.find((x) => x.name === "1.2.3.4")!.reports).toBeGreaterThanOrEqual(1);

    expect(m.sources[0].title).toBe("intel.csv");
    expect(m.crossCase).toEqual([]); // single-vault → no cross-case overlaps (until sf-cases)
  });

  it("the analyst dossier override WINS over the AI dossier (source=analyst)", async () => {
    const vault = await seededVault();
    const { setEntityDossierOverride } = await import("../../src/agent/session.js");
    await setEntityDossierOverride(vault, { type: "domain", value: "acme.io" }, "Analyst: confirmed C2 operator.");
    const m = reportModelFor(vault);
    const dossier = m.dossiers.find((x) => x.name === "acme.io")!;
    expect(dossier.source).toBe("analyst");
    expect(dossier.body).toContain("confirmed C2 operator");
  });

  it("redacts the live key out of the brief + a forged dossier + a forged source title (no-leak belt)", async () => {
    const vault = await seededVault();
    await vault.put("brief:case", { objective: "case", brief: `## Summary\nkey is ${LEAK_KEY}`, builtOn: 1 });
    await vault.put(`dossier:${canonKey("domain", "acme.io")}`, { type: "domain", value: "acme.io", dossier: `## Dossier\nleak ${LEAK_KEY}` });
    // codex impl-review: a forged file-ingest record whose title carries the key must be belted on read.
    await vault.put("run:file: clean #zz99", { objective: "file: clean #zz99", steps: [], promoted: [], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", sourceKind: "file_ingest", ingestedAt: "2026-06-19T11:00:00.000Z", title: `report ${LEAK_KEY}`, sourceType: "pdf" });
    const m = reportModelFor(vault);
    const blob = JSON.stringify(m);
    expect(blob).not.toContain(LEAK_KEY);
    expect(m.execSummary).toContain("[REDACTED]");
    expect(m.sources.some((s) => s.title.includes("[REDACTED]"))).toBe(true);
  });
});
