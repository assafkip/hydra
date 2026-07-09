import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey, getApiKey, setAnalyst, getAnalyst,
  scopedVault, activeCaseId, setActiveCase, listCases, createCase, deleteCase, migrateLegacyData,
  entityDbFor, liveReportCount,
} from "../../src/agent/session.js";
import { getEntity } from "../../src/entity/db.js";

// sf-cases: the per-case ISOLATION invariant — the heart of multi-case. scopedVault is the SINGLE chokepoint:
// data keys scope per case, secret:/setting: are GLOBAL (per-user). The default case uses the existing
// un-prefixed keys (zero migration) and NEVER sees another case's data; a named case sees ONLY its own.

const LEAK_KEY = "sk-ant-CASES-secret-3434";

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

function seedRun(view: Vault, objective: string, entity: string, type: string): Promise<void> {
  return view.put(`run:${objective}`, {
    objective, steps: [],
    promoted: [{ entity, entity_type: type, grade: "A", source_count: 2, infra_source_count: 2 }],
    leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
  });
}

describe("sf-cases — scopedVault per-case isolation (no cross-case bleed)", () => {
  it("default and named cases never see each other's data; secret:/setting: are shared", async () => {
    const raw = await freshVault();
    await setApiKey(raw, LEAK_KEY); // a GLOBAL secret: key

    const def = scopedVault(raw, "default");
    const caseB = scopedVault(raw, "case-b");

    await seedRun(def, "investigate acme.io", "acme.io", "domain");
    await seedRun(caseB, "investigate evil.com", "evil.com", "domain");

    // each case's entity DB sees ONLY its own entity
    const defEnts = entityDbFor(def);
    const bEnts = entityDbFor(caseB);
    expect(getEntity(defEnts, "domain", "acme.io")).toBeTruthy();
    expect(getEntity(defEnts, "domain", "evil.com")).toBeNull(); // B's data does NOT bleed into default
    expect(getEntity(bEnts, "domain", "evil.com")).toBeTruthy();
    expect(getEntity(bEnts, "domain", "acme.io")).toBeNull(); // default's data does NOT bleed into B

    // the API key (secret:) is GLOBAL — both views read it
    expect(getApiKey(def)).toBe(LEAK_KEY);
    expect(getApiKey(caseB)).toBe(LEAK_KEY);
    // and the analyst name (setting:) is shared
    await setAnalyst(def, "Alice");
    expect(getAnalyst(caseB)).toBe("Alice");
  });

  it("a named case scopes EVERY data prefix incl. pivot: (the catch-all), and default hides case:* keys", async () => {
    const raw = await freshVault();
    const caseB = scopedVault(raw, "case-b");
    const def = scopedVault(raw, "default");
    // a pivot: record (a DATA prefix the catch-all auto-scopes) written in case B
    await caseB.put("pivot:evil.com", [{ provider: "dns", tier: "T1", entities: [] }]);
    // the RAW vault stores it under the case prefix
    expect(raw.keys()).toContain("case:case-b:pivot:evil.com");
    // the default case's keys() HIDES it (never sees case:* data)
    expect(def.keys().some((k) => k.includes("pivot:evil.com"))).toBe(false);
    // case B sees it back at the BASE key (stripped)
    expect(caseB.keys()).toContain("pivot:evil.com");
    expect(caseB.get("pivot:evil.com")).toBeTruthy();
  });

  it("migrateLegacyData adopts pre-cases un-prefixed data into ONE case (idempotent)", async () => {
    const raw = await freshVault();
    await setApiKey(raw, LEAK_KEY); // a GLOBAL secret: — migration must not touch it
    // pre-existing data written UN-PREFIXED (the world before this change). No case owns it.
    await seedRun(raw, "legacy run", "legacy.example", "domain");
    expect(listCases(raw)).toEqual([]); // no case yet
    expect(activeCaseId(raw)).toBe(""); // nothing active

    await migrateLegacyData(raw);

    // exactly ONE case now owns the data, and it's active
    const cases = listCases(raw);
    expect(cases).toHaveLength(1);
    const id = cases[0].id;
    expect(activeCaseId(raw)).toBe(id);
    // the legacy entity is readable THROUGH that case's scoped view (re-keyed under case:<id>:)
    expect(getEntity(entityDbFor(scopedVault(raw, id)), "domain", "legacy.example")).toBeTruthy();
    // NO un-prefixed data key remains
    expect(raw.keys().some((k) => k.startsWith("run:"))).toBe(false);
    // the GLOBAL key survived
    expect(getApiKey(raw)).toBe(LEAK_KEY);

    // idempotent: a second run does NOTHING (no duplicate case)
    await migrateLegacyData(raw);
    expect(listCases(raw)).toHaveLength(1);
  });
});

describe("sf-cases — case management", () => {
  it("createCase mints an OPAQUE id (never name-derived) + a redacted name; listCases + activeCase track it", async () => {
    const raw = await freshVault();
    await setApiKey(raw, LEAK_KEY);
    expect(activeCaseId(raw)).toBe(""); // a fresh vault has NO active case (no implicit default)
    expect(listCases(raw)).toEqual([]); // and NO cases (no "Default case" row)

    // a case name containing the live key — the id must NOT embed it, the stored name must redact it
    const id = await createCase(raw, `Acme ${LEAK_KEY} breach`);
    expect(id).not.toContain(LEAK_KEY); // opaque uuid, never the name
    expect(id.startsWith("c-")).toBe(true);
    const cases = listCases(raw);
    expect(cases).toHaveLength(1);
    const created = cases.find((c) => c.id === id)!;
    expect(created.name).not.toContain(LEAK_KEY); // the key is redacted out of the stored name
    expect(created.name).toContain("[REDACTED]");

    // switching the active case
    await setActiveCase(raw, id);
    expect(activeCaseId(raw)).toBe(id);
    expect(listCases(raw).find((c) => c.active)!.id).toBe(id);
    // an unknown id is rejected
    await expect(setActiveCase(raw, "no-such-case")).rejects.toThrow();
  });

  it("no case data or key leaks into the cases index", async () => {
    const raw = await freshVault();
    await setApiKey(raw, LEAK_KEY);
    await createCase(raw, `secret ${LEAK_KEY}`);
    expect(JSON.stringify(listCases(raw))).not.toContain(LEAK_KEY);
  });
});

describe("sf-cases — deleteCase (drop a case + ALL its data, siblings untouched)", () => {
  it("removes EVERY data key for the case + its index row; sibling case and default are untouched", async () => {
    const raw = await freshVault();
    await setApiKey(raw, LEAK_KEY); // a GLOBAL secret: — must survive a case delete

    const idB = await createCase(raw, "case B");
    const idC = await createCase(raw, "case C");
    await seedRun(scopedVault(raw, idB), "investigate b.example", "b.example", "domain");
    await seedRun(scopedVault(raw, idC), "investigate c.example", "c.example", "domain");
    await seedRun(scopedVault(raw, "default"), "investigate d.example", "d.example", "domain");

    // every case:<idB>: key exists before the delete
    expect(raw.keys().some((k) => k.startsWith(`case:${idB}:`))).toBe(true);

    await deleteCase(raw, idB);

    // (1) the index row is gone; B is no longer a known case
    expect(listCases(raw).some((c) => c.id === idB)).toBe(false);
    // (2) NOT ONE case:<idB>: key remains in the raw vault
    expect(raw.keys().some((k) => k.startsWith(`case:${idB}:`))).toBe(false);
    // (3) sibling case C is fully intact
    expect(listCases(raw).some((c) => c.id === idC)).toBe(true);
    expect(getEntity(entityDbFor(scopedVault(raw, idC)), "domain", "c.example")).toBeTruthy();
    expect(liveReportCount(scopedVault(raw, idC))).toBe(1);
    // (4) the default case (un-prefixed) is intact
    expect(getEntity(entityDbFor(scopedVault(raw, "default")), "domain", "d.example")).toBeTruthy();
    // (5) the GLOBAL key survived
    expect(getApiKey(raw)).toBe(LEAK_KEY);
  });

  it("can delete the LAST case → zero cases, active cleared (no implicit default remains)", async () => {
    const raw = await freshVault();
    const id = await createCase(raw, "only case");
    await setActiveCase(raw, id);
    // deleting the active case is refused — the caller clears active first (app.ts switches to "")
    await expect(deleteCase(raw, id)).rejects.toThrow();
    await setActiveCase(raw, ""); // clear active (the empty state)
    await deleteCase(raw, id);
    expect(listCases(raw)).toEqual([]); // ZERO cases — no "Default case" backstop
    expect(activeCaseId(raw)).toBe("");
  });

  it("refuses to delete the ACTIVE case (caller switches away first)", async () => {
    const raw = await freshVault();
    const id = await createCase(raw, "active one");
    await setActiveCase(raw, id);
    await expect(deleteCase(raw, id)).rejects.toThrow();
    expect(listCases(raw).some((c) => c.id === id)).toBe(true); // still there — nothing was dropped
  });

  it("refuses an unknown case id", async () => {
    const raw = await freshVault();
    await expect(deleteCase(raw, "c-not-a-real-case")).rejects.toThrow();
  });

  it("deleteByPrefix throws on an empty prefix (would wipe the whole vault)", async () => {
    const raw = await freshVault();
    await expect(raw.deleteByPrefix("")).rejects.toThrow();
  });
});
