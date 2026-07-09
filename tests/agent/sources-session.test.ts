import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, sourcesFor } from "../../src/agent/session.js";

// sf-sources: sourcesFor is a READ projection over the RETAINED ingested docs (run:file: records) + their
// gate-extracted entities (runEntities). The page image + raw OCR blob are discarded at ingest, so the
// projection is doc-metadata + entities only — key-redacted, tainted docs/entities dropped.

const LEAK_KEY = "sk-ant-SOURCES-secret-3434";

async function vaultWithKey(key = LEAK_KEY): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

// a file-ingest run = sourceKind "file" + title/ingestedAt/sourceType + promoted/leads entities.
function fileRun(objective: string, title: string, at: string, sourceType: string, promoted: { entity: string; entity_type: string }[]) {
  return {
    objective,
    sourceKind: "file_ingest", // FILE_SOURCE_KIND
    title,
    ingestedAt: at,
    sourceType,
    steps: [],
    promoted: promoted.map((p) => ({ ...p, grade: "B", source_count: 1, infra_source_count: 1 })),
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  };
}

describe("sf-sources — sourcesFor projection", () => {
  it("projects each retained doc with its date, type, entity count + entity chips", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:file: acme.pdf #a1", fileRun("file: acme.pdf #a1", "acme.pdf", "2026-06-19T10:00:00.000Z", "pdf", [
      { entity: "acme.io", entity_type: "domain" },
      { entity: "1.2.3.4", entity_type: "ip" },
    ]));
    await vault.put("run:file: notes.txt #b2", fileRun("file: notes.txt #b2", "notes.txt", "2026-06-18T09:00:00.000Z", "text", [
      { entity: "evil.com", entity_type: "domain" },
    ]));
    const sources = sourcesFor(vault);
    expect(sources).toHaveLength(2);
    // newest-first (listIngestedDocs sort)
    expect(sources[0].title).toBe("acme.pdf");
    expect(sources[0].ingestDate).toBe("2026-06-19");
    expect(sources[0].sourceType).toBe("pdf");
    expect(sources[0].entityCount).toBe(2);
    expect(sources[0].entities.map((e) => e.label).sort()).toEqual(["1.2.3.4", "acme.io"]);
    expect(sources[1].title).toBe("notes.txt");
    expect(sources[1].entities[0].label).toBe("evil.com");
  });

  it("ignores non-file runs (a normal agent investigation is not a source doc)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:investigate x", { objective: "investigate x", steps: [], promoted: [{ entity: "x.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" });
    expect(sourcesFor(vault)).toHaveLength(0); // no sourceKind "file"
  });

  it("returns [] when no docs are ingested", async () => {
    const vault = await vaultWithKey();
    expect(sourcesFor(vault)).toEqual([]);
  });

  it("does NOT crash on a malformed file-ingest record (a numeric entity_type) — degrades to no chips", async () => {
    const vault = await vaultWithKey();
    // a forged file doc whose finding has a NON-string entity_type — runEntities' admission gate could throw.
    await vault.put("run:file: bad.pdf #x9", {
      objective: "file: bad.pdf #x9", sourceKind: "file_ingest", title: "bad.pdf", ingestedAt: "2026-06-19T10:00:00.000Z", sourceType: "pdf",
      steps: [], promoted: [{ entity: "Alice", entity_type: 1, source_count: 1, infra_source_count: 1 }], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    expect(() => sourcesFor(vault)).not.toThrow();
    const sources = sourcesFor(vault);
    expect(sources).toHaveLength(1);
    expect(sources[0].title).toBe("bad.pdf"); // the doc still lists; its entities just degrade
  });

  it("redacts the live key out of the projection (a tainted doc title / entity)", async () => {
    const vault = await vaultWithKey();
    // a doc whose title carries the key + an entity value carrying the key.
    await vault.put(`run:file: leak-${LEAK_KEY}.pdf #c3`, fileRun(`file: leak-${LEAK_KEY}.pdf #c3`, `leak-${LEAK_KEY}.pdf`, "2026-06-19T10:00:00.000Z", "pdf", [
      { entity: `${LEAK_KEY}.evil.com`, entity_type: "domain" },
    ]));
    const blob = JSON.stringify(sourcesFor(vault));
    expect(blob).not.toContain(LEAK_KEY);
  });
});
