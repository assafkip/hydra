import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, generateBrief, applyCorrection, revertCorrection, SessionError } from "../../src/agent/session.js";
import { canonKey } from "../../src/entity/db.js";
import type { FetchLike } from "../../src/osint/types.js";

async function vaultWithKey(key = "sk-ant-brief"): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

function briefFetch(text: string): { impl: FetchLike; calls: { body: string }[] } {
  const calls: { body: string }[] = [];
  const impl = (async (_url: string, init: RequestInit) => {
    calls.push({ body: String(init.body) });
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) };
  }) as unknown as FetchLike;
  return { impl, calls };
}

const PROMOTED_RUN = {
  objective: "Investigate live.example.com",
  steps: [{ kind: "tool", tool: "dns_lookup", isError: false }],
  promoted: [{ entity: "live.example.com", entity_type: "domain", grade: "A", infra_source_count: 2, source_count: 2 }],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("generateBrief errors + empty-run short-circuit", () => {
  it("no key -> clean SessionError", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await expect(generateBrief(vault, "x")).rejects.toBeInstanceOf(SessionError);
  });

  it("missing run -> clean SessionError (investigate first)", async () => {
    const vault = await vaultWithKey();
    await expect(generateBrief(vault, "never ran")).rejects.toThrow(/no run to brief/i);
  });

  it("a run with zero findings AND zero leads -> deterministic no-evidence brief, NO model call", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:empty", { objective: "empty", steps: [], promoted: [], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" });
    const { impl, calls } = briefFetch("should not be called");
    const brief = await generateBrief(vault, "empty", { fetchImpl: impl });
    expect(brief.toLowerCase()).toContain("no evidence");
    expect(calls.length).toBe(0); // no model spend on an empty run
    expect((vault.get("brief:empty") as { brief: string }).brief).toBe(brief);
  });
});

describe("generateBrief happy path + persistence", () => {
  it("synthesizes from a saved run and persists brief:<objective>", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate live.example.com", PROMOTED_RUN);
    const { impl } = briefFetch("# Investigation brief\n## Executive summary\nlive.example.com is operating.");
    const brief = await generateBrief(vault, "Investigate live.example.com", { fetchImpl: impl });
    expect(brief).toContain("Investigation brief");
    const saved = vault.get("brief:Investigate live.example.com") as { brief: string };
    expect(saved.brief).toBe(brief);
  });
});

describe("ca-session D9 — a TYPE correction propagates into the brief (analyst authority reaches the deliverable)", () => {
  // The brief digest serializes every finding as `entity [entity_type] grade ...` (synthesize.buildDigest).
  // An analyst TYPE correction must re-label the finding's entity_type in the digest the model actually sees,
  // proving the override reaches the BRIEF — not just the entity DB / graph. This is the codex finding the
  // corrections PRD blocked the `faithful` flip on. Negative self-test: the ORIGINAL type must be ABSENT for
  // that entity, so the assertion can only pass when the correction genuinely propagated (not a no-op match).
  const TYPED_RUN = {
    objective: "Investigate acme.example",
    steps: [{ kind: "tool", tool: "dns_lookup", isError: false }],
    promoted: [{ entity: "acme.example", entity_type: "domain", grade: "A", infra_source_count: 2, source_count: 2 }],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  };

  it("the corrected type (domain->org) reaches the model request body; the original type does not", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.example", TYPED_RUN);
    await applyCorrection(vault, "domain", "acme.example", "type", "org");
    const { impl, calls } = briefFetch("# Investigation brief\nacme.example.");
    await generateBrief(vault, "Investigate acme.example", { fetchImpl: impl });
    expect(calls[0].body).toContain("acme.example [org]"); // corrected type reached synthesis
    expect(calls[0].body).not.toContain("acme.example [domain]"); // negative: the original type is gone
  });

  it("reverting the type correction restores the original type in the brief request", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate acme.example", TYPED_RUN);
    await applyCorrection(vault, "domain", "acme.example", "type", "org");
    await revertCorrection(vault, canonKey("domain", "acme.example"), "type");
    const { impl, calls } = briefFetch("# Investigation brief\nacme.example.");
    await generateBrief(vault, "Investigate acme.example", { fetchImpl: impl });
    expect(calls[0].body).toContain("acme.example [domain]"); // revert propagates to the brief
    expect(calls[0].body).not.toContain("acme.example [org]");
  });
});

describe("KEY HYGIENE: redact the key from the model INPUT and OUTPUT", () => {
  it("the key seeded into the run + the model response appears in no digest/brief/record", async () => {
    const KEY = "sk-ant-REDACT-ME-9";
    const vault = await vaultWithKey(KEY);
    // seed the key into the objective, a step, and a finding field
    await vault.put(`run:probe ${KEY}`, {
      objective: `probe ${KEY}`,
      steps: [{ kind: "tool", tool: "dns_lookup", result: `leaked ${KEY}`, isError: false }],
      promoted: [{ entity: "live.example.com", entity_type: "domain", grade: "A", infra_source_count: 2, source_count: 2, note: KEY }],
      leads: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    });
    const { impl, calls } = briefFetch(`The brief accidentally echoes ${KEY} here.`);
    const brief = await generateBrief(vault, `probe ${KEY}`, { fetchImpl: impl });

    // the request body sent to the model (the digest) carries no key
    expect(calls[0].body).not.toContain(KEY);
    // the returned brief redacts the key the model echoed
    expect(brief).not.toContain(KEY);
    // the persisted record carries no key
    expect(JSON.stringify(vault.get(`brief:probe ${KEY}`))).not.toContain(KEY);
  });
});
