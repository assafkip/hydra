import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { SessionError, setApiKey, alertsFor, setReportNotes, getReportNotes } from "../../src/agent/session.js";

// rb-session: alertsFor (the gate-faithful priority projection) + the per-report notes store.

async function fresh(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}
const finding = (entity: string, grade: string, infra: number) => ({
  entity,
  entity_type: "domain",
  grade,
  source_count: grade === "A" ? 2 : grade === "B" ? 2 : 1,
  infra_source_count: infra,
});
const lead = (entity: string) => ({ finding: { entity, entity_type: "domain" }, verdict: { promote: false, grade: "C", reason: "held" } });
async function run(v: Vault, objective: string, promoted: unknown[], leads: unknown[] = []): Promise<void> {
  await v.put(`run:${objective}`, { objective, steps: [], promoted, leads, usage: { input: 0, output: 0 }, stopReason: "end_turn" });
}

describe("rb-session — alerts + report notes", () => {
  it("alertsFor surfaces grade-A and PROMOTED cross-run entities; not a single-run grade-C nor a cross-run LEAD (D3)", async () => {
    const v = await fresh();
    await run(v, "r1", [finding("a.com", "A", 2), finding("b.com", "B", 1), finding("c.com", "C", 0)], [lead("d.com")]);
    await run(v, "r2", [finding("b.com", "B", 1)], [lead("d.com")]); // b promoted in 2 runs; d lead in 2 runs
    const labels = alertsFor(v).map((a) => a.label);
    expect(labels).toContain("a.com"); // grade A
    expect(labels).toContain("b.com"); // promoted cross-run
    expect(labels).not.toContain("c.com"); // single-run grade C
    expect(labels).not.toContain("d.com"); // non-promoted cross-run lead is NOT an alert (D3)
    expect(alertsFor(v)[0].label).toBe("a.com"); // grade A ranks first
  });

  it("report notes round-trip through the single writer", async () => {
    const v = await fresh();
    await run(v, "file: doc #abcd1234", [finding("x.com", "A", 2)]);
    expect(getReportNotes(v, "file: doc #abcd1234")).toBe("");
    await setReportNotes(v, "file: doc #abcd1234", "follow up on x.com");
    expect(getReportNotes(v, "file: doc #abcd1234")).toBe("follow up on x.com");
  });

  it("a note embedding a configured secret is stored redacted; a secret-tainted objective is rejected (D2/D4)", async () => {
    const v = await fresh();
    const KEY = "sk-ant-NOTE-secret-3131";
    await setApiKey(v, KEY);
    await setReportNotes(v, "file: doc #zz", `the key is ${KEY} keep it secret`);
    const back = getReportNotes(v, "file: doc #zz");
    expect(back).not.toContain(KEY);
    expect(back).toContain("[REDACTED]");
    // a secret-tainted objective (the key is in the objective) is rejected (D2)
    await expect(setReportNotes(v, `file: ${KEY}`, "x")).rejects.toBeInstanceOf(SessionError);
    expect(getReportNotes(v, `file: ${KEY}`)).toBe("");
  });

  it("a note is length-capped (D7)", async () => {
    const v = await fresh();
    await setReportNotes(v, "file: doc #cap", "a".repeat(99999));
    expect(getReportNotes(v, "file: doc #cap").length).toBeLessThanOrEqual(4000);
  });
});
