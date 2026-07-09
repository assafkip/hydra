import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, activityFor, ENRICH_SOURCE_KIND } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import { emptyAnalysis } from "../../src/entity/analysis.js";

// sf-activity: activityFor is a READ projection over the SEVEN timestamped retained record types — no
// server activity table (the browser keeps no event log). It reverse-chron-orders by `at`, key-redacts
// every value, and excludes tainted records. An action with no timestamped record is a SIGNED divergence
// (the manifest note), never a silent strip.

const LEAK_KEY = "sk-ant-" + "ACTIVITY-secret-9090";

// distinct ascending timestamps so reverse-chron order (DESC) is unambiguous.
const T = {
  upload: "2026-06-19T10:00:00.000Z",
  correction: "2026-06-19T11:00:00.000Z",
  notes: "2026-06-19T12:00:00.000Z",
  dossier: "2026-06-19T13:00:00.000Z",
  process: "2026-06-19T14:00:00.000Z",
  enrich: "2026-06-19T15:00:00.000Z",
  group: "2026-06-19T16:00:00.000Z",
};

async function vaultWithKey(key = LEAK_KEY): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

async function seededVault(): Promise<Vault> {
  const vault = await vaultWithKey();
  const keyAcme = canonKey("domain", "acme.io");

  // a base run so the entity DB has acme.io (corrections/dossier resolve their label through it). No
  // ingestedAt → NOT an upload.
  await vault.put("run:investigate acme.io", {
    objective: "investigate acme.io",
    steps: [],
    promoted: [{ entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });

  // 1) upload — a file-ingest run carries ingestedAt + title (a normal agent run does not).
  await vault.put("run:file: acme.csv #ab12cd", {
    objective: "file: acme.csv #ab12cd",
    steps: [],
    promoted: [],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
    ingestedAt: T.upload,
    title: "acme.csv",
    sourceType: "csv",
  });
  // 2) correction (author + at) — raw record (listCorrections drops `at`).
  await vault.put(`correction:role:${keyAcme}`, { value: "channel", predicate: "role", author: "alice", at: T.correction, deleted: false });
  // 3) report notes (at, no author).
  await vault.put("report:investigate acme.io:notes", { text: "watch this one", at: T.notes });
  // 4) dossier override (author + at).
  await vault.put(`entity:${keyAcme}:dossier_override`, { text: "confirmed staging host", author: "bob", at: T.dossier });
  // 5) process (analysis.updatedAt) — seeded directly so the timestamp is controlled (putAnalysis stamps its own).
  await vault.put("analysis:default", { ...emptyAnalysis("default"), updatedAt: T.process });
  // 6) enrichment run — a run: record with sourceKind=enrich + provider/target/at (listEnrichRuns reads it).
  await vault.put("run:enrich: dns example.com", { objective: "enrich: dns example.com", sourceKind: ENRICH_SOURCE_KIND, provider: "dns", target: "example.com", at: T.enrich, promoted: [], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" });
  // 7) group briefs — the groupbrief:index pointer carries `at`.
  await vault.put("groupbrief:index", { groups: ["group-1", "group-2"], standalone: false, at: T.group });
  return vault;
}

describe("sf-activity — activityFor projects every timestamped source", () => {
  it("covers all seven sources with the right action verbs + entity/report/detail", async () => {
    const vault = await seededVault();
    const items = activityFor(vault);
    const byAction = (needle: string) => items.find((i) => i.action.includes(needle));

    expect(byAction("uploaded acme.csv")).toBeTruthy();
    expect(byAction("uploaded acme.csv")!.detail).toBe("csv");
    const corr = byAction("asserted role → channel")!;
    expect(corr).toBeTruthy();
    expect(corr.analyst).toBe("alice");
    expect(corr.entityLabel).toBe("acme.io");
    const notes = byAction("edited notes")!;
    expect(notes.analyst).toBeNull(); // report notes carry no author
    expect(notes.report).toBe("investigate acme.io");
    const dossier = byAction("edited the dossier")!;
    expect(dossier.analyst).toBe("bob");
    expect(dossier.entityLabel).toBe("acme.io");
    expect(byAction("processed the case")).toBeTruthy();
    const enrich = byAction("ran dns enrichment")!;
    expect(enrich.detail).toBe("example.com");
    const group = byAction("grouped related reports")!;
    expect(group.detail).toBe("2 group(s)");
  });

  it("orders the feed reverse-chron (at DESC)", async () => {
    const vault = await seededVault();
    const items = activityFor(vault);
    const ats = items.map((i) => i.at);
    const sorted = [...ats].sort().reverse();
    expect(ats).toEqual(sorted);
    expect(items[0].at).toBe(T.group); // the latest action is first
    expect(items[items.length - 1].at).toBe(T.upload); // the earliest is last
  });

  it("a deleted correction reads as a revert, not an assert", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:investigate acme.io", {
      objective: "investigate acme.io", steps: [],
      promoted: [{ entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    await vault.put(`correction:role:${canonKey("domain", "acme.io")}`, { value: "", predicate: "role", author: "alice", at: T.correction, deleted: true });
    const items = activityFor(vault);
    expect(items.find((i) => i.action === "reverted role")).toBeTruthy();
    expect(items.find((i) => i.action.startsWith("asserted"))).toBeUndefined();
  });

  it("returns [] for a vault with no timestamped actions", async () => {
    const vault = await vaultWithKey();
    expect(activityFor(vault)).toEqual([]);
  });
});

describe("sf-activity — redaction belt", () => {
  it("redacts the live key out of a correction author/value and a dossier author", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:investigate acme.io", {
      objective: "investigate acme.io", steps: [],
      promoted: [{ entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    const keyAcme = canonKey("domain", "acme.io");
    await vault.put(`correction:role:${keyAcme}`, { value: "channel", predicate: "role", author: `agent ${LEAK_KEY}`, at: T.correction, deleted: false });
    await vault.put(`entity:${keyAcme}:dossier_override`, { text: `note ${LEAK_KEY}`, author: `bob ${LEAK_KEY}`, at: T.dossier });
    const blob = JSON.stringify(activityFor(vault));
    expect(blob).not.toContain(LEAK_KEY);
    expect(blob).toContain("[REDACTED]");
  });

  it("excludes a report-notes record whose objective is secret-tainted", async () => {
    const vault = await vaultWithKey();
    await vault.put(`report:leaky ${LEAK_KEY}:notes`, { text: "should never surface", at: T.notes });
    const blob = JSON.stringify(activityFor(vault));
    expect(blob).not.toContain(LEAK_KEY);
    // the tainted notes record is dropped entirely (its objective carried the key)
    expect(activityFor(vault).find((i) => i.action === "edited notes")).toBeUndefined();
  });

  // codex impl-review belts:
  it("redacts a forged correction value + drops a correction whose canonKey is secret-tainted", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:investigate acme.io", {
      objective: "investigate acme.io", steps: [],
      promoted: [{ entity: "acme.io", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    // a FORGED correction whose value is not an allowlisted role (carries the key) — the value must redact.
    await vault.put(`correction:role:${canonKey("domain", "acme.io")}`, { value: `evil ${LEAK_KEY}`, predicate: "role", author: "x", at: T.correction, deleted: false });
    // a correction whose canonKey ENTITY value carries the key — the whole row must drop (not just redact).
    await vault.put(`correction:role:${canonKey("domain", `bad-${LEAK_KEY}.example`)}`, { value: "channel", predicate: "role", author: "y", at: T.dossier, deleted: false });
    const items = activityFor(vault);
    expect(JSON.stringify(items)).not.toContain(LEAK_KEY);
    // the tainted-canonKey correction is dropped; the forged-value one survives with a redacted value.
    expect(items.find((i) => i.action.includes("[REDACTED]"))).toBeTruthy();
  });

  it("redacts a forged enrich run's provider/target on read", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:enrich: dns leak.example", { objective: "enrich: dns leak.example", sourceKind: ENRICH_SOURCE_KIND, provider: "dns", target: `host ${LEAK_KEY}`, at: T.enrich, promoted: [], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" });
    const blob = JSON.stringify(activityFor(vault));
    expect(blob).not.toContain(LEAK_KEY);
  });

  it("does NOT double-count an enrich run as an upload even if it carries ingestedAt", async () => {
    const vault = await vaultWithKey();
    // a forged enrich record with BOTH at + ingestedAt — it must count ONCE (as an enrich run), never as an upload.
    await vault.put("run:enrich: dns example.com", { objective: "enrich: dns example.com", sourceKind: ENRICH_SOURCE_KIND, provider: "dns", target: "example.com", at: T.enrich, ingestedAt: T.upload, title: "sneaky.csv", promoted: [], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" });
    const items = activityFor(vault);
    expect(items.filter((i) => i.action.includes("enrichment"))).toHaveLength(1);
    expect(items.find((i) => i.action.includes("uploaded"))).toBeUndefined();
  });
});
