import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { ingestText, recordScope, composeCaseTask, caseRoster, caseCoOccurLeads } from "../../src/agent/session.js";

// D3 (prd-kipi-web-4points-investigator-parity / finding-5): the recorded scope is no longer decorative —
// it COMPOSES into the whole-case agent task as the objective, alongside the roster seeds (not a
// replacement). The coOccur doc-proximity pairs (preserved by D2) surface as suggested-relationships-to-
// verify so the agent is AWARE of the document's hints without rendering them as edges.

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

const DOC = "fifa-rewards.com and fifaworldcup-claim.net both resolve to 104.21.5.9. Contact support@fifa-rewards.com.";

describe("D3 finding-5: scope composes into the case task; coOccur becomes leads", () => {
  it("the case task names the recorded scope as the objective AND keeps the roster seeds (composition)", async () => {
    const vault = await freshVault();
    await ingestText(vault, "fifa.txt", DOC);
    recordScope(vault, { question: "trace the money from the FIFA reward domains" });

    const roster = caseRoster(vault);
    const task = composeCaseTask(vault, roster);

    expect(task).toContain("trace the money from the FIFA reward domains"); // the recorded scope IS the objective
    expect(task.toLowerCase()).toContain("fifa-rewards.com"); // a roster seed is still named (composition, not replacement)
    expect(roster.length).toBeGreaterThan(0);
  });

  it("coOccur pairs surface as suggested-relationships-to-verify (a hint, not a confirmed edge)", async () => {
    const vault = await freshVault();
    await ingestText(vault, "fifa.txt", DOC);

    const leads = caseCoOccurLeads(vault);
    expect(leads.length).toBeGreaterThan(0); // the doc proximity pairs are preserved as leads

    const task = composeCaseTask(vault, caseRoster(vault));
    expect(task.toLowerCase()).toMatch(/verify|hint|place these|together/); // the task says VERIFY, not assume
    expect(task).toContain(leads[0].split(" ↔ ")[0]); // at least one lead endpoint is named in the task

    // codex: every lead is count-capped AND endpoint-length-capped (no prompt-bloat from a junk-long token).
    expect(leads.length).toBeLessThanOrEqual(20);
    for (const lead of leads) {
      for (const endpoint of lead.split(" ↔ ")) expect(endpoint.length).toBeLessThanOrEqual(100);
    }
  });

  it("a case with no scope still builds a valid task (scope is additive, not required)", async () => {
    const vault = await freshVault();
    await ingestText(vault, "fifa.txt", DOC);
    const task = composeCaseTask(vault, caseRoster(vault));
    expect(task).toContain("Investigate this WHOLE case");
    expect(task).not.toContain("Analyst scope");
  });
});
