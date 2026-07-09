import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { ingestText, listIngestedDocs, entityDbFor, setApiKey } from "../../src/agent/session.js";
import { allEntities } from "../../src/entity/db.js";

// ig-ingest: extract → gated findings → a sanitized run: record via the EXISTING vault.put. The doc's
// entities land in the entity DB; junk is dropped; the key (echoed in the doc text) is never written.

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

const DOC = "Contact admin@evil.xyz, host 93.184.216.34, pay 0x" + "a".repeat(40) + ". Report date 2026-04-19. ref 000000000.";

describe("ingestText", () => {
  it("extracts the document's entities into the entity DB; junk is dropped", async () => {
    const vault = await freshVault();
    const { count, objective } = await ingestText(vault, "report.txt", DOC);
    expect(count).toBeGreaterThanOrEqual(3); // email + ip + wallet
    expect(objective).toContain("file: report.txt");
    const values = allEntities(entityDbFor(vault, null)).map((e) => e.label);
    expect(values).toContain("admin@evil.xyz");
    expect(values).toContain("93.184.216.34");
    expect(values).toContain("0x" + "a".repeat(40));
    expect(values).not.toContain("2026-04-19"); // date dropped by the gate
    expect(values).not.toContain("000000000");
  });

  it("ig-record: structured CSV entities (a handle column) land via ingestText; a secret cell is dropped", async () => {
    const vault = await freshVault();
    const KEY = "sk-ant-CSV-secret-7777";
    await setApiKey(vault, KEY);
    // the flat text has only the free-text column; the username column has no regex signature, so the
    // handle arrives ONLY via the structured list. A cell that holds the live key must never become an entity.
    const flatText = "username,phone,note,leaked\nali_r99,+1 (402) 928-3844,lead operator," + KEY;
    const structured = [
      { type: "handle", value: "ali_r99" },
      { type: "phone", value: "+1 (402) 928-3844" }, // a FORMATTED phone survives the value-only hard floor
      { type: "handle", value: KEY }, // a secret pasted into a cell — must be dropped
    ];
    await ingestText(vault, "actors.csv", flatText, structured);
    const values = allEntities(entityDbFor(vault, null)).map((e) => e.label);
    expect(values).toContain("ali_r99"); // structured column-typed entity landed
    expect(values).toContain("+1 (402) 928-3844"); // formatted phone from a 'phone' column lands
    expect(values).not.toContain(KEY); // secret cell dropped, never an entity
  });

  it("routes through vault.put exactly once (single writer untouched)", async () => {
    const vault = await freshVault();
    const putSpy = vi.spyOn(vault, "put");
    await ingestText(vault, "a.txt", "see evil.top");
    expect(putSpy).toHaveBeenCalledTimes(1);
    expect(putSpy.mock.calls[0][0]).toMatch(/^run:file: a\.txt #/);
  });

  it("a key-echoing document never writes the raw key into the record (D3)", async () => {
    const vault = await freshVault();
    const KEY = "sk-ant-INGEST-secret-8888";
    await setApiKey(vault, KEY);
    const { objective } = await ingestText(vault, `doc-${KEY}.txt`, `leak ${KEY} and evil.xyz`);
    expect(objective).not.toContain(KEY);
    const rec = vault.get(`run:${objective}`);
    expect(JSON.stringify(rec)).not.toContain(KEY);
  });

  it("listIngestedDocs returns the file: runs filtered by sourceKind (D4), not a user 'file:' objective", async () => {
    const vault = await freshVault();
    await ingestText(vault, "doc.txt", "evil.xyz");
    // a user-investigated objective that starts with 'file:' must NOT be treated as an ingested doc
    await vault.put("run:file: not-an-upload", { objective: "file: not-an-upload", steps: [], promoted: [], leads: [], usage: {}, stopReason: "end_turn" });
    const docs = listIngestedDocs(vault);
    expect(docs).toHaveLength(1);
    expect(docs[0].objective).toContain("doc.txt");
  });
});
