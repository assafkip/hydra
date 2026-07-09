import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, setProviderKey, runDetail } from "../../src/agent/session.js";

// r1-detail: runDetail is a READ projection over one run: record — all-secret-redacted steps (D1),
// gate-faithful + redacted findings, entity-match attribution (D3/D4/D5), objective taint guard (D2).

const KEY = "sk-ant-AbCdEf012345";
const PROVIDER = "shodanKEY01234567ABCDEF";

async function vaultWithSecrets(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  await setProviderKey(vault, "shodan", PROVIDER);
  return vault;
}

function toolStep(tool: string, input: unknown, entities: { type: string; value: string; note?: string }[], opts?: { isError?: boolean; raw?: string }) {
  const result = opts?.raw ?? JSON.stringify(opts?.isError ? { error: "boom" } : { provider: tool, tier: "T1", entities });
  return { kind: "tool", tool, input, result, isError: !!opts?.isError };
}

describe("runDetail", () => {
  it("returns null for a secret-namespace or key-bearing objective (D2)", async () => {
    const vault = await vaultWithSecrets();
    await vault.put("run:clean.io", { objective: "clean.io", steps: [], promoted: [], leads: [], usage: {}, stopReason: "end_turn" });
    expect(runDetail(vault, "secret:anthropic_key")).toBeNull();
    expect(runDetail(vault, `probe ${KEY}`)).toBeNull(); // contains the Anthropic key
    expect(runDetail(vault, `probe ${PROVIDER.toLowerCase()}`)).toBeNull(); // contains a provider secret (lowercased)
    expect(runDetail(vault, "does-not-exist.io")).toBeNull();
  });

  it("scrubs ALL secret forms from steps (raw + lowercased + url-encoded provider secret) (D1)", async () => {
    const vault = await vaultWithSecrets();
    await vault.put("run:leak.io", {
      objective: "leak.io",
      steps: [
        { kind: "tool", tool: "dns_lookup", input: { domain: "leak.io", note: PROVIDER }, result: `{"entities":[{"type":"ip","value":"1.2.3.4"}],"echo":"${PROVIDER.toLowerCase()}"}`, isError: false },
        { kind: "reasoning", text: `the provider echoed ${encodeURIComponent(PROVIDER)} in headers` },
      ],
      promoted: [],
      leads: [],
      usage: {},
      stopReason: "end_turn",
    });
    const json = JSON.stringify(runDetail(vault, "leak.io"));
    expect(json).not.toContain(PROVIDER);
    expect(json.toLowerCase()).not.toContain(PROVIDER.toLowerCase());
    expect(json).not.toContain(encodeURIComponent(PROVIDER));
    expect(json).not.toContain(KEY);
  });

  it("attributes a promoted finding to the successful tool step that emitted it (D3/D4/D5)", async () => {
    const vault = await vaultWithSecrets();
    await vault.put("run:hit.io", {
      objective: "hit.io",
      steps: [
        { kind: "reasoning", text: "resolving" },
        toolStep("dns_lookup", { domain: "hit.io" }, [{ type: "ip", value: "93.184.216.34", note: "A of hit.io" }]),
      ],
      promoted: [{ entity: "93.184.216.34", entity_type: "ip", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [{ finding: { entity: "ghost.io", entity_type: "domain", source_count: 1, infra_source_count: 0 }, verdict: { promote: false, grade: "C", reason: "x" } }],
      usage: {},
      stopReason: "end_turn",
    });
    const d = runDetail(vault, "hit.io")!;
    expect(d).toBeTruthy();
    const ip = d.findings.find((f) => f.value === "93.184.216.34")!;
    expect(ip.stepRef).toBe(2); // the dns_lookup tool step (1-based)
    expect(ip.stepTool).toBe("dns_lookup");
    expect(ip.promoted).toBe(true);
    // ghost.io appears in NO emitted entity (it is only the note of the dns step is hit.io, not ghost) -> no ref
    const ghost = d.findings.find((f) => f.value === "ghost.io")!;
    expect(ghost.stepRef).toBeUndefined();
    // the trail surfaced (2 steps), and the bottom line reflects 1 promoted
    expect(d.steps).toHaveLength(2);
    expect(d.promoted).toBe(1);
    expect(d.bottomLine).toContain("1 promoted");
  });

  it("is gate-faithful: a forged-promoted finding (no corroboration) is a lead, not promoted", async () => {
    const vault = await vaultWithSecrets();
    await vault.put("run:forged.io", {
      objective: "forged.io",
      steps: [],
      promoted: [{ entity: "9.9.9.9", entity_type: "ip", grade: "A", source_count: 0, infra_source_count: 0 }],
      leads: [],
      usage: {},
      stopReason: "end_turn",
    });
    const d = runDetail(vault, "forged.io")!;
    const n = d.findings.find((f) => f.value === "9.9.9.9")!;
    expect(n.promoted).toBe(false); // re-gated down to a lead
    expect(d.promoted).toBe(0);
  });
});
