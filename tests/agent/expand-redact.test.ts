import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, expandFromNode } from "../../src/agent/session.js";
import { buildGraphModel } from "../../src/graph/model.js";
import type { Finding } from "../../src/agent/gate.js";
import type { InvestigateResult } from "../../src/agent/loop.js";
import type { FetchLike } from "../../src/osint/types.js";

// PRD-8 p8-interactions (codex-1 + codex-2): a one-hop expand must (a) redact the live key
// before the merge so it never reaches the merged model / __kipi.graphModel(), and (b) NOT
// persist a run:<entity> vault record the key could be read back from via __kipi.getCase.

const KEY = "sk-ant-EXPANDSECRET-9z9z9z";

async function vaultWithKey(): Promise<{ vault: Vault; storage: ReturnType<typeof memoryStorage> }> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  return { vault, storage };
}

// one-turn scripted Anthropic wire: end_turn with a finding whose entity echoes the key
function scriptedAnthropic(): FetchLike {
  const text =
    "done\n```json\n{\"findings\":[" +
    `{"entity":"leaked-${KEY}","entity_type":"person","confidence":"low"}` +
    "]}\n```";
  const queue = [{ content: [{ type: "text", text }], stop_reason: "end_turn", usage: { output_tokens: 5 } }];
  return (async () => ({
    ok: true,
    status: 200,
    json: async () => queue.shift() ?? { content: [], stop_reason: "end_turn", usage: {} },
  })) as unknown as FetchLike;
}

function base() {
  const promoted: Finding[] = [{ entity: "seed.com", entity_type: "domain", source_count: 1, infra_source_count: 1 }];
  const result: InvestigateResult = { steps: [], promoted, leads: [], relationships: [], usage: { input: 0, output: 0 }, stopReason: "end_turn", worked: true };
  const model = buildGraphModel("seed", result);
  return { model, fromId: model.nodes.find((n) => n.entityType === "domain")!.id };
}

describe("expandFromNode", () => {
  it("redacts the live key from the merged model and persists NO run record", async () => {
    const { vault } = await vaultWithKey();
    const { model, fromId } = base();
    const beforeNodes = model.nodes.length;

    const merged = await expandFromNode(vault, "seed.com", model, fromId, {
      fetchImpl: scriptedAnthropic(),
      toolOpts: { retries: 0 },
    });

    const json = JSON.stringify(merged);
    expect(json).not.toContain(KEY); // never in the merged model / graphModel hook
    expect(json).toContain("[REDACTED]"); // the key-bearing entity was redacted, node kept
    expect(merged.nodes.length).toBeGreaterThan(beforeNodes); // the graph grew
    expect(model.nodes).toHaveLength(beforeNodes); // base untouched

    // codex-1: no run:<entity> record exists, so the key cannot be read back
    expect(vault.get("run:seed.com")).toBeUndefined();
  });

  it("a missing parent id yields the base unchanged", async () => {
    const { vault } = await vaultWithKey();
    const { model } = base();
    const merged = await expandFromNode(vault, "seed.com", model, "no-such-node", {
      fetchImpl: scriptedAnthropic(),
      toolOpts: { retries: 0 },
    });
    expect(merged.nodes).toHaveLength(model.nodes.length);
  });
});
