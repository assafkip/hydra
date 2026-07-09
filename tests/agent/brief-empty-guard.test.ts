import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, synthesizeCaseBrief, getBrief, CASE_BRIEF_KEY } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// clu-error-output: a failed/empty brief must NOT be persisted as a finished deliverable
// (the "brief-failure-persisted-as-success" bug). synthesizeCaseBrief throws and leaves no brief:case.

async function vaultWithKey(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, "sk-ant-BRIEF-guard-01");
  return vault;
}

// the model returns an EMPTY brief (failure / blank completion)
const emptyBriefWire = (): FetchLike =>
  (async () => ({ ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: "   " }], stop_reason: "end_turn", usage: {} }) })) as unknown as FetchLike;
// a SUCCESSFUL brief
const goodBriefWire = (text: string): FetchLike =>
  (async () => ({ ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) })) as unknown as FetchLike;
// a FAILURE that returns a NON-EMPTY string with ok:false (max_tokens → "Brief truncated…")
const truncatedBriefWire = (): FetchLike =>
  (async () => ({ ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: "partial" }], stop_reason: "max_tokens", usage: {} }) })) as unknown as FetchLike;

const RUN = {
  objective: "Investigate acme.io",
  steps: [],
  promoted: [{ entity: "1.2.3.4", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("synthesizeCaseBrief — empty brief is not persisted (clu-error-output)", () => {
  it("throws on an empty LLM response and persists NO brief:case", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN); // findings exist → reaches the LLM path
    await expect(synthesizeCaseBrief(vault, { fetchImpl: emptyBriefWire() })).rejects.toThrow(/empty|failed/i);
    expect(getBrief(vault, CASE_BRIEF_KEY)).toBeNull(); // nothing persisted as a "finished" deliverable
  });

  it("a non-empty FAILURE string (ok:false, e.g. max_tokens) does NOT overwrite a prior good brief", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.io", RUN);
    // 1) a good brief is synthesized + persisted
    const good = await synthesizeCaseBrief(vault, { fetchImpl: goodBriefWire("# Brief\n\nReal findings on 1.2.3.4.") });
    expect(getBrief(vault, CASE_BRIEF_KEY)).toContain("Real findings");
    // 2) a later run fails with a NON-EMPTY ok:false string — must throw and leave the prior brief intact
    await expect(synthesizeCaseBrief(vault, { fetchImpl: truncatedBriefWire() })).rejects.toThrow(/failed|empty/i);
    expect(getBrief(vault, CASE_BRIEF_KEY)).toBe(good); // NOT overwritten with "Brief truncated…"
  });
});
