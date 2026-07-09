import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import type { FetchLike } from "../../src/osint/types.js";
import { setApiKey, consolidateEntities, typeEntities } from "../../src/agent/session.js";

// ct-session: the read-projection session hooks over entityDbFor + a bounded Haiku classify pass. The
// model output is validated against the PRESENTED opaque ids; the prompt is key-redacted IN and the
// suggestions redacted OUT; an empty/single case never calls the model. New symbols (negative self-test).

const ANTHROPIC = "sk-ant-CONSOL-secret-4242";

/** A classify wire that records each request body and returns a fixed Messages-API text payload. */
function classifyWire(text: string, log: { bodies: string[] }): FetchLike {
  return (async (_url: string, init: RequestInit) => {
    log.bodies.push(String(init.body));
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) } as Response;
  }) as unknown as FetchLike;
}

async function seeded(promoted: { entity: string; entity_type: string }[]): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const v = await Vault.unlock(storage, "pw");
  await setApiKey(v, ANTHROPIC);
  await v.put("run:dig", {
    objective: "dig",
    steps: [],
    promoted: promoted.map((p) => ({ ...p, source_count: 2, infra_source_count: 2, grade: "A" })),
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  return v;
}

const TWO = [
  { entity: "alpha.example.com", entity_type: "domain" },
  { entity: "alpha-cdn.example.com", entity_type: "domain" },
];

describe("ct-session — consolidateEntities + typeEntities", () => {
  it("consolidate returns a validated equivalence group from a scripted classify wire", async () => {
    const v = await seeded(TWO);
    const log = { bodies: [] as string[] };
    const wire = classifyWire(JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "alias" }] }), log);
    const out = await consolidateEntities(v, { fetchImpl: wire });
    expect(out).toHaveLength(1);
    expect(out[0].members.map((m) => m.id).sort()).toEqual(["e0", "e1"]);
    expect(out[0].role).toBe("channel");
    expect(log.bodies).toHaveLength(1); // one model call
  });

  it("typing returns a validated changed-type suggestion", async () => {
    const v = await seeded(TWO);
    const log = { bodies: [] as string[] };
    const wire = classifyWire(JSON.stringify({ types: [{ id: "e0", type: "url", confidence: "high", reason: "it is a url" }] }), log);
    const out = await typeEntities(v, { fetchImpl: wire });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: "e0", fromType: "domain", toType: "url" });
  });

  it("a group referencing a NON-PRESENTED id is dropped", async () => {
    const v = await seeded(TWO);
    const log = { bodies: [] as string[] };
    const wire = classifyWire(JSON.stringify({ groups: [{ ids: ["e0", "e9"], role: "channel", confidence: "high", reason: "x" }] }), log);
    expect(await consolidateEntities(v, { fetchImpl: wire })).toEqual([]);
  });

  it("the Anthropic key reaches neither the prompt sent to the wire nor the suggestions (D8)", async () => {
    // a third entity whose value embeds the key; entityDbFor + the prompt/output redaction must scrub it
    const v = await seeded([...TWO, { entity: `x-${ANTHROPIC}.com`, entity_type: "domain" }]);
    const log = { bodies: [] as string[] };
    const wire = classifyWire(
      JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: `tie to x-${ANTHROPIC}.com` }] }),
      log,
    );
    const out = await consolidateEntities(v, { fetchImpl: wire });
    expect(log.bodies[0]).not.toContain(ANTHROPIC); // prompt redacted IN
    expect(log.bodies[0]).toContain("[REDACTED]"); // the key-bearing label was actually scrubbed
    expect(JSON.stringify(out)).not.toContain(ANTHROPIC); // suggestions redacted OUT
  });

  it("kweb-classify-batch: classifies EVERY entity by batching past MAX_CONSOLIDATE_ENTITIES (no silent drop)", async () => {
    // 90 entities = 2 batches of 80 + 10. OLD behavior sliced to the first 80 and made ONE call — the
    // overflow stayed unclassified ("squares"). NEW behavior makes ceil(90/80)=2 calls, classifying all.
    const many = Array.from({ length: 90 }, (_, i) => ({ entity: `d${String(i).padStart(3, "0")}.example.com`, entity_type: "domain" }));
    const v = await seeded(many);
    const log = { bodies: [] as string[] };
    const wire = classifyWire(JSON.stringify({ groups: [{ ids: ["e0"], role: "infra", confidence: "high", reason: "x" }] }), log);
    await consolidateEntities(v, { fetchImpl: wire });
    expect(log.bodies).toHaveLength(2); // ceil(90 / MAX_CONSOLIDATE_ENTITIES) — every entity reached the model
  });

  it("kweb-classify-batch: a truncated (max_tokens) batch FAILS HONESTLY, never silently drops roles", async () => {
    const v = await seeded(TWO);
    // a batch that returns stop_reason max_tokens with a half-written JSON — extractJsonObject would
    // null-parse it and drop every role silently; the guard must throw instead.
    const truncatingWire = (async () => ({
      ok: true, status: 200,
      json: async () => ({ content: [{ type: "text", text: '{"groups":[{"ids":["e0"]' }], stop_reason: "max_tokens", usage: {} }),
    })) as unknown as FetchLike;
    await expect(consolidateEntities(v, { fetchImpl: truncatingWire })).rejects.toThrow(/truncated/i);
    await expect(typeEntities(v, { fetchImpl: truncatingWire })).rejects.toThrow(/truncated/i);
  });

  it("an empty vault returns [] with ZERO model calls", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const v = await Vault.unlock(storage, "pw");
    await setApiKey(v, ANTHROPIC);
    const log = { bodies: [] as string[] };
    const wire = classifyWire("{}", log);
    expect(await consolidateEntities(v, { fetchImpl: wire })).toEqual([]);
    expect(await typeEntities(v, { fetchImpl: wire })).toEqual([]);
    expect(log.bodies).toHaveLength(0);
  });
});
