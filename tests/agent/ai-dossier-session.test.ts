import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, aiDossierFor, semanticRelationsFor } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// adr-session: the AI passes are READ-ONLY, key-redacted in+out (codex D4: the key is absent
// from the WHOLE serialized request body, present only in the x-api-key header), and an
// unknown/zero-connection entity makes NO model call. The strong-attribution gate holds THROUGH
// the accessor (a low-confidence same_operator is dropped).

const KEY = "sk-ant-LEAKTEST-abc123";

async function vaultWithRun(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  // Two promoted, co-occurring infra entities -> a co_occurs connection between them.
  await vault.put("run:Investigate evil.com", {
    objective: "Investigate evil.com",
    steps: [],
    promoted: [
      { entity: "1.1.1.1", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 },
      { entity: "host.example", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  return vault;
}

/** A dossier wire that CAPTURES the request body and ECHOES the key in its output (to prove
 *  redact-in via the body + redact-out via the returned dossier). */
function dossierWire(capture: { body?: string; header?: string }): FetchLike {
  return (async (_url: string, init: RequestInit) => {
    capture.body = init.body as string;
    capture.header = (init.headers as Record<string, string>)["x-api-key"];
    // hostile echo of the key in the model output:
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: `## Summary\nLeak attempt ${KEY}\n## Threat assessment\nx\n## Key connections\ny\n## Open questions\nz` }], usage: {} }) };
  }) as unknown as FetchLike;
}

/** A relations wire that reads the first cid out of the prompt body and labels it. */
function relationsWire(relType: string, confidence: string): FetchLike {
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(init.body as string);
    const userMsg = body.messages[0].content as string;
    const m = userMsg.match(/"cid":\s*("(?:[^"\\]|\\.)*")/);
    const cid = m ? JSON.parse(m[1]) : "NONE";
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: JSON.stringify({ relations: [{ cid, rel_type: relType, confidence }] }) }], usage: {} }) };
  }) as unknown as FetchLike;
}

describe("aiDossierFor", () => {
  it("an unknown / objective entity returns null with NO fetch call", async () => {
    const vault = await vaultWithRun();
    const fetchImpl = vi.fn() as unknown as FetchLike;
    expect(await aiDossierFor(vault, "domain", "nope.example", { fetchImpl })).toBeNull();
    expect(await aiDossierFor(vault, "objective", "Investigate evil.com", { fetchImpl })).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("grounds a dossier; the key is absent from the WHOLE request body (header only) and from the output", async () => {
    const vault = await vaultWithRun();
    const cap: { body?: string; header?: string } = {};
    const dossier = await aiDossierFor(vault, "ip", "1.1.1.1", { fetchImpl: dossierWire(cap) });
    expect(dossier).toBeTruthy();
    expect(dossier).toContain("## Summary");
    // D4: the key is present ONLY in the x-api-key header, never in the serialized body
    expect(cap.header).toBe(KEY);
    expect(cap.body).not.toContain(KEY);
    // redact-out: the model echoed the key, but the returned dossier has it stripped
    expect(dossier).not.toContain(KEY);
    expect(dossier).toContain("[REDACTED]");
  });

  it("is READ-ONLY: it issues no vault write", async () => {
    const vault = await vaultWithRun();
    const putSpy = vi.spyOn(vault, "put");
    await aiDossierFor(vault, "ip", "1.1.1.1", { fetchImpl: dossierWire({}) });
    expect(putSpy).not.toHaveBeenCalled();
  });
});

describe("semanticRelationsFor", () => {
  it("an entity with no relatable connection returns [] with NO call", async () => {
    const vault = await vaultWithRun();
    const fetchImpl = vi.fn() as unknown as FetchLike;
    expect(await semanticRelationsFor(vault, "domain", "nope.example", { fetchImpl })).toEqual([]);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("keeps a high non-attribution label", async () => {
    const vault = await vaultWithRun();
    const rels = await semanticRelationsFor(vault, "ip", "1.1.1.1", { fetchImpl: relationsWire("hosts", "high") });
    expect(rels).toHaveLength(1);
    expect(rels[0].relType).toBe("hosts");
  });

  it("a LOW-confidence same_operator is gate-dropped THROUGH the accessor", async () => {
    const vault = await vaultWithRun();
    const rels = await semanticRelationsFor(vault, "ip", "1.1.1.1", { fetchImpl: relationsWire("same_operator", "low") });
    expect(rels).toHaveLength(0);
  });

  it("is READ-ONLY: it issues no vault write", async () => {
    const vault = await vaultWithRun();
    const putSpy = vi.spyOn(vault, "put");
    await semanticRelationsFor(vault, "ip", "1.1.1.1", { fetchImpl: relationsWire("hosts", "high") });
    expect(putSpy).not.toHaveBeenCalled();
  });
});
