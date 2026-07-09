import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  entityDbFor,
  runEntities,
  getBrief,
  graphModelForRun,
  runInvestigation,
} from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// swh-redact (audit S1/S3, codex D1/D3/D4/D6): the Anthropic-key redaction must be CASE-INSENSITIVE,
// like the provider-key path (redactForms /gi). The named scar: downstream paths lowercase values
// (entity/db.ts canonRef, the OSINT adapters' .toLowerCase()), so a key echoed by a malicious provider
// inside a value (evil-<KEY>.com) reaches a record LOWERCASED. An exact-case match misses it.
// These tests drive PUBLIC surfaces only (no exported internals — codex D6) and the (a)/(D1) cases
// FAIL on the pre-fix exact-case `redact` (verified before applying the fix).

const MIXED = "sk-ant-" + "AbCdEfGhIjKlMnOpQr012345"; // the stored key (mixed case)
const LOWER = MIXED.toLowerCase(); // the form a lowercasing downstream path produces

async function vaultWithKey(key = MIXED): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, key);
  return vault;
}

// A run whose objective is CLEAN (so objectivesUnder keeps it) but whose promoted entity embeds the
// key LOWERCASED — exactly the adapter-lowercased-echo scar.
const TAINTED_RUN = {
  objective: "Investigate good.example",
  steps: [{ kind: "reason", text: `noted ${LOWER} while resolving` }],
  promoted: [
    { entity: `evil-${LOWER}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
  ],
  leads: [],
  usage: { input: 0, output: 0 },
  stopReason: "end_turn",
};

describe("swh-redact — read projections scrub a LOWERCASED key (case-insensitive)", () => {
  it("entityDbFor: a lowercased key in a promoted entity is scrubbed from the store", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate good.example", TAINTED_RUN);
    const store = entityDbFor(vault);
    // NEGATIVE SELF-TEST: fails on the pre-fix exact-case redact (the lowercased key survives).
    expect(JSON.stringify(store)).not.toContain(LOWER);
    expect(JSON.stringify(store)).not.toContain(MIXED);
  });

  it("runEntities: a lowercased key in a run's entities is scrubbed", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate good.example", TAINTED_RUN);
    const ents = runEntities(vault, "Investigate good.example");
    expect(JSON.stringify(ents)).not.toContain(LOWER);
  });

  it("graphModelForRun: a lowercased key in the result is scrubbed from the model", async () => {
    const vault = await vaultWithKey();
    const result = {
      objective: "Investigate good.example",
      steps: [],
      promoted: [
        { entity: `evil-${LOWER}.com`, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      ],
      leads: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    } as unknown as Parameters<typeof graphModelForRun>[2];
    const model = graphModelForRun(vault, "Investigate good.example", result);
    expect(JSON.stringify(model)).not.toContain(LOWER);
  });

  it("getBrief: a lowercased key in a saved brief body is scrubbed", async () => {
    const vault = await vaultWithKey();
    await vault.put("brief:Investigate good.example", {
      objective: "Investigate good.example",
      brief: `# Brief\nObserved evil-${LOWER}.com on the wire.`,
    });
    const brief = getBrief(vault, "Investigate good.example");
    expect(brief).toBeTruthy();
    expect(brief!).not.toContain(LOWER);
    expect(brief!).toContain("[REDACTED]");
  });
});

describe("swh-redact — write path (D1): the persisted run record carries no key form", () => {
  function scriptedAnthropic(): FetchLike {
    const turns = [
      {
        content: [
          {
            type: "text",
            text:
              `Saw evil-${LOWER}.com.\n` +
              '```json\n{"findings":[' +
              `{"entity":"evil-${LOWER}.com","entity_type":"domain","confidence":"high"}` +
              "]}\n```",
          },
        ],
        stop_reason: "end_turn",
        usage: { output_tokens: 10 },
      },
    ];
    return (async () => ({ ok: true, status: 200, json: async () => turns.shift() })) as unknown as FetchLike;
  }

  it("runInvestigation persists a scrubbed record (no lowercased key in the stored value)", async () => {
    const vault = await vaultWithKey();
    await runInvestigation({
      vault,
      objective: "Investigate good.example",
      fetchImpl: scriptedAnthropic(),
      maxTurns: 2,
    });
    const stored = vault.get("run:Investigate good.example");
    expect(JSON.stringify(stored)).not.toContain(LOWER);
    expect(JSON.stringify(stored)).not.toContain(MIXED);
  });
});

describe("swh-redact — no over-scrub, no-key no-op", () => {
  it("does not over-scrub benign text that does not contain the key", async () => {
    const vault = await vaultWithKey();
    await vault.put("run:Investigate good.example", {
      ...TAINTED_RUN,
      promoted: [
        { entity: "benign.example.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
      ],
      steps: [{ kind: "reason", text: "ordinary text with no secret" }],
    });
    const store = entityDbFor(vault);
    expect(JSON.stringify(store)).toContain("benign.example.com");
    expect(JSON.stringify(store)).not.toContain("[REDACTED]");
  });

  it("a locked/keyless vault redacts nothing and does not crash", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw"); // no key set
    await vault.put("brief:Investigate good.example", {
      objective: "Investigate good.example",
      brief: "# Brief\nplain content",
    });
    const brief = getBrief(vault, "Investigate good.example");
    expect(brief).toContain("plain content");
    expect(brief).not.toContain("[REDACTED]");
  });
});
