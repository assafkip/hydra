import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import {
  setApiKey,
  setProviderKey,
  graphModelForRun,
  runEntities,
  entityDbFor,
  getBrief,
} from "../../src/agent/session.js";
import type { InvestigateResult } from "../../src/agent/loop.js";

// m3-redact-hardening (codex blockers D1/D2): once a provider key can flow through the agent loop,
// EVERY session projection must redact PROVIDER secrets, not just the Anthropic key. Before this
// chunk these paths used redactDeep(x, ANTHROPIC_KEY) only, so a provider key echoed by a malicious
// provider into an entity value / note / reason / step would leak to the graph, entity DB, runs page,
// and a saved brief. This test embeds a Shodan key in raw, URL-encoded, and lowercased forms and
// proves every read projection scrubs it. It is the negative self-test: it FAILS on Anthropic-only
// redaction (the key survives) and passes once the projections converge on allSecretForms.

const ANTHROPIC = "sk-ant-" + "AAAAA-anthropic-key-1234";
const PKEY = "shodan/Key+Abc123456"; // a provider key with chars that change under encodeURIComponent
const PKEY_ENC = encodeURIComponent(PKEY); // "shodan%2FKey%2BAbc123456"
const PKEY_LOW = PKEY.toLowerCase(); // "shodan/key+abc123456" — the case-insensitive path
const OBJ = "Investigate example.com"; // a CLEAN objective (a tainted one is dropped entirely)

async function vaultWithKeys(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const v = await Vault.unlock(storage, "pw");
  await setApiKey(v, ANTHROPIC);
  await setProviderKey(v, "shodan", PKEY);
  return v;
}

/** A run: record whose surviving fields embed the provider key in three forms. */
async function seedRun(v: Vault): Promise<void> {
  await v.put(`run:${OBJ}`, {
    objective: OBJ,
    steps: [
      { kind: "tool", tool: "enrich_shodan", input: { target: "8.8.8.8" }, result: `{"note":"${PKEY_ENC}"}` },
    ],
    // an opaque-typed entity whose VALUE is the raw key survives admission + promotion (source_count 2)
    promoted: [{ entity: PKEY, entity_type: "affiliate_id", source_count: 2, infra_source_count: 0 }],
    leads: [
      {
        finding: { entity: "Jane Roe", entity_type: "person" },
        verdict: { promote: false, grade: "C", reason: `held — leaked ${PKEY_LOW}` },
      },
    ],
    relationships: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
}

function noKey(json: string): void {
  expect(json).not.toContain(PKEY);
  expect(json).not.toContain(PKEY_ENC);
  expect(json).not.toContain(PKEY_LOW);
}

describe("m3-redact-hardening — provider keys are first-class secrets on every projection", () => {
  it("runEntities scrubs an embedded provider key", async () => {
    const v = await vaultWithKeys();
    await seedRun(v);
    const json = JSON.stringify(runEntities(v, OBJ));
    noKey(json);
    expect(json).toContain("[REDACTED]");
  });

  it("entityDbFor scrubs an embedded provider key", async () => {
    const v = await vaultWithKeys();
    await seedRun(v);
    const json = JSON.stringify(entityDbFor(v));
    noKey(json);
  });

  it("graphModelForRun scrubs a provider key from the result it is handed", async () => {
    const v = await vaultWithKeys();
    const result: InvestigateResult = {
      steps: [],
      promoted: [{ entity: "1.2.3.4", entity_type: "ip", source_count: 2, infra_source_count: 2 }],
      leads: [
        {
          finding: { entity: "evil.com", entity_type: "domain" },
          verdict: { promote: false, grade: "C", reason: `held ${PKEY} / ${PKEY_ENC}` },
        },
      ],
      relationships: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
      worked: true,
    };
    const json = JSON.stringify(graphModelForRun(v, `dig ${PKEY}`, result));
    noKey(json);
    expect(json).toContain("[REDACTED]");
  });

  it("getBrief scrubs a provider key from a saved brief body", async () => {
    const v = await vaultWithKeys();
    await v.put(`brief:${OBJ}`, { objective: OBJ, brief: `# Brief\n\nObserved key ${PKEY} (enc ${PKEY_ENC}).` });
    const brief = getBrief(v, OBJ);
    expect(brief).not.toBeNull();
    noKey(brief as string);
    expect(brief as string).toContain("[REDACTED]");
  });

  it("the Anthropic key is still redacted (no regression)", async () => {
    const v = await vaultWithKeys();
    await v.put(`run:${OBJ}`, {
      objective: OBJ,
      steps: [],
      promoted: [{ entity: `leak ${ANTHROPIC}`, entity_type: "affiliate_id", source_count: 2, infra_source_count: 0 }],
      leads: [],
      relationships: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    });
    expect(JSON.stringify(runEntities(v, OBJ))).not.toContain(ANTHROPIC);
  });
});
