import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { listIngestedDocs, reportDetailFor, FILE_SOURCE_KIND } from "../../src/agent/session.js";

// sf-reports: listIngestedDocs projects the persisted report metadata (title/ingestedAt/sourceType) +
// sorts newest-first; reportDetailFor projects the per-report entities. Pure read projections over the
// vault — no write-path, no key.

async function fresh(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

const promotedDomain = (entity: string) => ({ entity, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 });

async function fileReport(v: Vault, objective: string, title: string, ingestedAt: string, promoted: unknown[]): Promise<void> {
  await v.put(`run:${objective}`, {
    objective, steps: [], promoted, leads: [], usage: { input: 0, output: 0 }, stopReason: "ingested",
    sourceKind: FILE_SOURCE_KIND, title, ingestedAt, sourceType: FILE_SOURCE_KIND,
  });
}

describe("sf-reports — listIngestedDocs projection + sort", () => {
  it("projects title/ingestedAt/sourceType and sorts newest-first; excludes non-file runs", async () => {
    const v = await fresh();
    await fileReport(v, "file: alpha #1", "alpha.pdf", "2026-06-01T00:00:00.000Z", [promotedDomain("a.com")]);
    await fileReport(v, "file: beta #2", "beta.pdf", "2026-06-03T00:00:00.000Z", [promotedDomain("b.com")]);
    // a non-file (agent) run — must be EXCLUDED from the reports table.
    await v.put("run:Investigate x", { objective: "Investigate x", steps: [], promoted: [promotedDomain("c.com")], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", sourceType: "investigation" });

    const docs = listIngestedDocs(v);
    expect(docs.length).toBe(2); // the agent run is not a report
    expect(docs[0].title).toBe("beta.pdf"); // newest-first by ingestedAt
    expect(docs[0].ingestedAt).toBe("2026-06-03T00:00:00.000Z");
    expect(docs[0].sourceType).toBe(FILE_SOURCE_KIND);
    expect(docs[1].title).toBe("alpha.pdf");
    expect(docs.every((d) => d.count >= 1)).toBe(true);
  });
});

describe("sf-report-detail — reportDetailFor projection", () => {
  it("returns the report's gate-faithful entities (with role/grade) and an empty overrides list when none", async () => {
    const v = await fresh();
    await fileReport(v, "file: beta #2", "beta.pdf", "2026-06-03T00:00:00.000Z", [promotedDomain("b.com")]);
    const rd = reportDetailFor(v, "file: beta #2");
    expect(rd.entities.length).toBeGreaterThan(0);
    const b = rd.entities.find((e) => e.value === "b.com");
    expect(b, "the promoted domain is in the detail").toBeTruthy();
    expect(b!.type).toBe("domain");
    expect(b!.promoted).toBe(true);
    expect(Array.isArray(rd.overrides)).toBe(true);
    expect(rd.overrides.length).toBe(0); // no analyst corrections seeded
  });
});
