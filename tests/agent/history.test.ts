import { describe, it, expect } from "vitest";
import { Vault, VaultError } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, listRuns, listBriefs, getBrief, ANTHROPIC_KEY } from "../../src/agent/session.js";

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}
const run = (promoted: number, leads: number) => ({
  objective: "x",
  steps: [],
  promoted: Array.from({ length: promoted }, (_, i) => ({ entity: `e${i}`, entity_type: "domain" })),
  leads: Array.from({ length: leads }, (_, i) => ({ finding: { entity: `l${i}`, entity_type: "person" }, verdict: { promote: false, grade: "D", reason: "x" } })),
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
});

describe("Vault.keys()", () => {
  it("returns key names when unlocked, throws when locked", async () => {
    const v = await freshVault();
    await v.put("run:a", {});
    expect(v.keys()).toContain("run:a");
    v.lock();
    expect(() => v.keys()).toThrow(VaultError);
  });
});

describe("listRuns / listBriefs", () => {
  it("summarizes saved runs (counts) and briefs", async () => {
    const v = await freshVault();
    await v.put("run:alpha.com", run(2, 1));
    await v.put("run:beta.com", run(0, 3));
    await v.put("brief:alpha.com", { objective: "alpha.com", brief: "# brief" });
    const runs = listRuns(v);
    expect(runs.map((r) => r.objective).sort()).toEqual(["alpha.com", "beta.com"]);
    const alpha = runs.find((r) => r.objective === "alpha.com")!;
    expect(alpha).toMatchObject({ promoted: 2, leads: 1, stopReason: "end_turn" });
    expect(listBriefs(v)).toEqual(["alpha.com"]);
  });
});

describe("SECRET leakage is closed", () => {
  it("never lists the secret namespace, even via run:secret: / brief:secret: keys", async () => {
    const v = await freshVault();
    await setApiKey(v, "sk-ant-LIST"); // stored at secret:anthropic_key
    await v.put(`run:${ANTHROPIC_KEY}`, run(1, 0)); // adversarial: objective IS the secret key name
    await v.put(`brief:${ANTHROPIC_KEY}`, { objective: ANTHROPIC_KEY, brief: "x" });
    await v.put("run:legit.com", run(1, 0));

    expect(listRuns(v).map((r) => r.objective)).toEqual(["legit.com"]); // secret-prefixed dropped
    expect(listBriefs(v)).toEqual([]); // the only brief was secret-prefixed
    expect(getBrief(v, ANTHROPIC_KEY)).toBeNull();
    expect(getBrief(v, "secret:anything")).toBeNull();
  });

  it("drops a run whose objective CONTAINS the live key, and redacts the key from a brief BODY", async () => {
    const v = await freshVault();
    await setApiKey(v, "sk-ant-REDACT-7");
    await v.put("run:probe sk-ant-REDACT-7", run(1, 0)); // key in the objective
    await v.put("run:clean.com", run(1, 0));
    await v.put("brief:clean.com", { objective: "clean.com", brief: "the report echoes sk-ant-REDACT-7 here" });

    expect(listRuns(v).map((r) => r.objective)).toEqual(["clean.com"]); // tainted-objective run dropped
    const brief = getBrief(v, "clean.com")!;
    expect(brief).not.toContain("sk-ant-REDACT-7"); // key redacted from the body
    expect(brief).toContain("[REDACTED]");
  });
});

describe("getBrief type guard", () => {
  it("returns null for a missing or malformed brief record", async () => {
    const v = await freshVault();
    await v.put("brief:bad", { notbrief: 1 });
    await v.put("brief:str", "just a string, not an object");
    expect(getBrief(v, "bad")).toBeNull();
    expect(getBrief(v, "str")).toBeNull();
    expect(getBrief(v, "never")).toBeNull();
  });
});
