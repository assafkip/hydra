import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, graphModelForRun } from "../../src/agent/session.js";
import type { InvestigateResult } from "../../src/agent/loop.js";

// PRD-7 p7-graph-render (codex finding-2): the graph is built from the raw objective +
// result and __kipi.graphModel() exposes it, so the live key must be redacted in the
// SESSION layer BEFORE the pure model is built. The pure model.ts stays vault-unaware.

const KEY = "sk-ant-" + "SUPERSECRET-0xdeadbeef";

async function vaultWithKey(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const v = await Vault.unlock(storage, "pw");
  await setApiKey(v, KEY);
  return v;
}

function empty(): InvestigateResult {
  return { steps: [], promoted: [], leads: [], relationships: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", worked: true };
}

describe("graphModelForRun — key/secret redaction before model construction", () => {
  it("redacts the live key from the objective, entity labels, and lead reasons", async () => {
    const vault = await vaultWithKey();
    const result: InvestigateResult = {
      steps: [],
      promoted: [{ entity: `1.2.3.4 ${KEY}`, entity_type: "ip", source_count: 2, infra_source_count: 2 }],
      leads: [
        {
          finding: { entity: "Jane Roe", entity_type: "person" },
          verdict: { promote: false, grade: "C", reason: `held — leaked ${KEY}` },
        },
      ],
      relationships: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
      worked: true,
    };

    const model = graphModelForRun(vault, `Investigate ${KEY}`, result);
    const json = JSON.stringify(model);
    expect(json).not.toContain(KEY); // the key never reaches the model (or the __kipi hook)
    expect(json).toContain("[REDACTED]");
    expect(model.nodes).toHaveLength(3); // structure preserved: objective + ip + person
  });

  it("a locked vault has no key to redact and does not throw (keyless model)", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const locked = await Vault.unlock(storage, "pw");
    locked.lock();
    const model = graphModelForRun(locked, "obj", empty());
    expect(model.nodes).toHaveLength(1);
    expect(model.edges).toHaveLength(0);
  });
});
