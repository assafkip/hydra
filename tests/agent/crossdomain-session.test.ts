import { describe, it, expect, vi } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, crossDomainEntities } from "../../src/agent/session.js";

// td-session: crossDomainEntities surfaces entities bridging >= 2 distinct SPECIFIC types. It is
// read-only and key-redacted (the inputs come through runEntities/entityDbFor); a key echoed into a
// gated ENTITY VALUE never appears raw (D8).

const KEY = "sk-ant-XDOM-secret-3131";

const A = (entity: string, type: string) => ({ entity, entity_type: type, grade: "A", source_count: 2, infra_source_count: 2 });
function run(objective: string, promoted: ReturnType<typeof A>[]) {
  return { objective, steps: [], promoted, leads: [], usage: {}, stopReason: "end_turn" };
}

async function vaultWith(runs: Record<string, ReturnType<typeof run>>): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, KEY);
  for (const [k, v] of Object.entries(runs)) await vault.put(k, v);
  return vault;
}

describe("crossDomainEntities", () => {
  it("two runs of DIFFERENT specific types sharing an entity surface it with BOTH types", async () => {
    // crypto-fraud run (wallet + 'rugpull drainer') + intrusion-apt run (ip+hash + 'malware c2'),
    // sharing the domain bridge.example.
    const vault = await vaultWith({
      "run:rugpull drainer wallet probe": run("rugpull drainer wallet probe", [A("0xabc", "wallet"), A("bridge.example", "domain")]),
      "run:malware c2 backdoor probe": run("malware c2 backdoor probe", [A("1.1.1.1", "ip"), A("deadbeef", "hash_sha256"), A("bridge.example", "domain")]),
    });
    const xd = crossDomainEntities(vault);
    const bridge = xd.find((e) => e.label === "bridge.example");
    expect(bridge).toBeTruthy();
    expect(bridge!.types).toContain("crypto-fraud");
    expect(bridge!.types).toContain("intrusion-apt");
  });

  it("an entity in two SAME-type runs is NOT cross-domain (that is cross-case)", async () => {
    const vault = await vaultWith({
      "run:rugpull wallet one": run("rugpull wallet one", [A("0xa", "wallet"), A("same.example", "domain")]),
      "run:drainer wallet two": run("drainer wallet two", [A("0xb", "wallet"), A("same.example", "domain")]),
    });
    expect(crossDomainEntities(vault).find((e) => e.label === "same.example")).toBeUndefined();
  });

  it("a general↔specific shared entity is NOT cross-domain (D1)", async () => {
    const vault = await vaultWith({
      "run:rugpull wallet probe": run("rugpull wallet probe", [A("0xa", "wallet"), A("g.example", "domain")]),
      "run:look into this": run("look into this", [A("g.example", "domain")]), // thin -> general
    });
    expect(crossDomainEntities(vault).find((e) => e.label === "g.example")).toBeUndefined();
  });

  it("a key echoed in a gated ENTITY VALUE never appears raw (D8); read-only", async () => {
    const vault = await vaultWith({
      "run:rugpull drainer wallet probe": run("rugpull drainer wallet probe", [A("0xabc", "wallet"), A(`leaked-${KEY}.example`, "domain")]),
      "run:malware c2 backdoor probe": run("malware c2 backdoor probe", [A("1.1.1.1", "ip"), A("h", "hash_md5"), A(`leaked-${KEY}.example`, "domain")]),
    });
    const putSpy = vi.spyOn(vault, "put");
    const json = JSON.stringify(crossDomainEntities(vault));
    expect(json).not.toContain(KEY);
    expect(json.toLowerCase()).toContain("[redacted]"); // the key-bearing bridge entity, redacted
    expect(putSpy).not.toHaveBeenCalled(); // read-only
  });
});
