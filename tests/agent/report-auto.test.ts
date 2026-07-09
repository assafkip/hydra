import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  liveCaseSummary,
  reportModelFor,
  getReportSummaryEdit,
  saveReportSummaryEdit,
  clearReportSummaryEdit,
} from "../../src/agent/session.js";

// clu-auto-report: the case report AUTO-EXISTS (no Generate button) and reflects current state. The
// exec summary always resolves: analyst edit > the LLM brief > a deterministic live summary; on an empty
// case it is useful guidance, never an error. Edits persist; re-render reverts to the current state.

const KEY = "sk-ant-REPORT-secret-77";

async function vaultWithKey(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  return vault;
}

const RUN = {
  objective: "Investigate acme.io",
  steps: [],
  promoted: [
    { entity: "1.2.3.4", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
    { entity: "acme.io", entity_type: "domain", grade: "B", source_count: 1, infra_source_count: 1 },
  ],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("liveCaseSummary — deterministic auto-report (clu-auto-report)", () => {
  it("an empty case returns USEFUL GUIDANCE (non-empty), not an error", async () => {
    const vault = await vaultWithKey();
    const s = liveCaseSummary(vault);
    expect(s.length).toBeGreaterThan(0);
    expect(s.toLowerCase()).toMatch(/no (evidence|findings)|attach|investigate/);
  });

  it("a case with findings returns non-empty content NAMING the case's entities", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    const s = liveCaseSummary(vault);
    expect(s.length).toBeGreaterThan(0);
    expect(s).toContain("1.2.3.4");
    expect(s).toContain("acme.io");
  });

  it("never leaks the API key (redacted projections only)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    expect(liveCaseSummary(vault)).not.toContain(KEY);
  });
});

describe("reportModelFor.execSummary precedence: edit > brief > live (clu-auto-report)", () => {
  it("with NO brief and NO edit, execSummary is the live summary (auto-exists with entities)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    const m = reportModelFor(vault);
    expect(m.execSummary.length).toBeGreaterThan(0);
    expect(m.execSummary).toContain("1.2.3.4"); // the live summary, no Generate needed
  });

  it("an analyst edit overrides everything (analyst is top authority)", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    await saveReportSummaryEdit(vault, "ANALYST OWNED SUMMARY");
    expect(reportModelFor(vault).execSummary).toBe("ANALYST OWNED SUMMARY");
  });
});

describe("report summary edit — persist + re-render (clu-auto-report)", () => {
  it("save round-trips and a configured key is rejected/redacted (never persisted raw)", async () => {
    const vault = await vaultWithKey();
    await saveReportSummaryEdit(vault, "my edited summary");
    expect(getReportSummaryEdit(vault)).toBe("my edited summary");
    await saveReportSummaryEdit(vault, `leak ${KEY} here`);
    expect(getReportSummaryEdit(vault) ?? "").not.toContain(KEY);
  });

  it("re-render (clear) reverts to the derived current-state summary", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    await saveReportSummaryEdit(vault, "stale manual text");
    await clearReportSummaryEdit(vault);
    expect(getReportSummaryEdit(vault)).toBeNull();
    expect(reportModelFor(vault).execSummary).toContain("1.2.3.4"); // back to the live summary
  });
});
