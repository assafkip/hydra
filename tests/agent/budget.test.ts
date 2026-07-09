import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { getCaseBudget, setCaseBudget, DEFAULT_CASE_BUDGET } from "../../src/agent/session.js";

// D3 (prd-kipi-web-4points-investigator-parity / finding-6): the cost guard is an explicit UP-FRONT
// per-case output-token budget (persisted), threaded into the deep run path where loop.ts already enforces
// finish("budget") at a turn boundary — a clean stop, NEVER a mid-run kill. Default is a generous runaway
// ceiling, not a tight leash (memory: cost-model-budget-the-scope, never kill mid-investigation).

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

describe("D3 finding-6: per-case up-front output-token budget", () => {
  it("defaults to DEFAULT_CASE_BUDGET (a positive ceiling) when unset", async () => {
    const vault = await freshVault();
    expect(DEFAULT_CASE_BUDGET).toBeGreaterThan(0);
    expect(getCaseBudget(vault)).toBe(DEFAULT_CASE_BUDGET);
  });

  it("round-trips a set budget, and it persists across a re-unlock (up-front, durable)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setCaseBudget(vault, 50_000);
    expect(getCaseBudget(vault)).toBe(50_000);
    const reopened = await Vault.unlock(storage, "pw"); // a fresh unlock reads the persisted budget
    expect(getCaseBudget(reopened)).toBe(50_000);
  });

  it("rejects a non-positive / non-finite budget (no silent zero-leash)", async () => {
    const vault = await freshVault();
    await expect(setCaseBudget(vault, 0)).rejects.toThrow();
    await expect(setCaseBudget(vault, -5)).rejects.toThrow();
    await expect(setCaseBudget(vault, Number.NaN)).rejects.toThrow();
    await expect(setCaseBudget(vault, Number.POSITIVE_INFINITY)).rejects.toThrow();
  });
});
