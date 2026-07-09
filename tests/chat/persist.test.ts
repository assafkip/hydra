// clu-chat-persist (issue chat-vault-persist): the conversation must survive refresh/nav/tab-switch.
// These tests pin the three guarantees the bug fix depends on:
//   (1) round-trip — save then load returns the same ordered messages (incl. agent sources);
//   (2) encryption-at-rest — the chat plaintext is NOT recoverable from the raw stored blob (finding-3);
//   (3) the 100-message cap drops the oldest and leaves a VISIBLE trim marker, never silent (finding-2).
// Each guarantee carries a NEGATIVE self-test so a no-op implementation cannot pass (fable-discipline).

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault";
import { memoryStorage } from "../../src/vault/store";
import {
  scopedVault,
  loadChatHistory,
  saveChatHistory,
  capChatHistory,
  type ChatMessage,
} from "../../src/agent/session";

const CASE = "case-test";

async function freshScopedVault() {
  const storage = memoryStorage();
  const { vault } = await Vault.create(storage, "hunter2");
  return { storage, vault: scopedVault(vault, CASE) };
}

describe("chat persistence", () => {
  it("round-trips an ordered conversation (text + agent sources)", async () => {
    const { vault } = await freshScopedVault();
    const convo: ChatMessage[] = [
      { role: "you", text: "who runs trumpfundus.com?" },
      { role: "agent", text: "The registrant is X.", sources: [{ run: "r1", entity: "trumpfundus.com", entity_type: "domain", status: "promoted" }] },
      { role: "you", text: "and the wallet?" },
    ];
    await saveChatHistory(vault, convo);

    const loaded = loadChatHistory(vault);
    expect(loaded).toEqual(convo); // same order, same text, sources preserved

    // NEGATIVE: an empty/never-saved case returns [], not the prior case's data.
    const other = await freshScopedVault();
    expect(loadChatHistory(other.vault)).toEqual([]);
  });

  it("persists across a real lock/unlock round-trip (a new Vault instance)", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "hunter2");
    await saveChatHistory(scopedVault(vault, CASE), [{ role: "you", text: "remember me after reload" }]);

    // A new Vault reading the SAME storage = the refresh/tab-switch case.
    const reopened = await Vault.unlock(storage, "hunter2");
    const loaded = loadChatHistory(scopedVault(reopened, CASE));
    expect(loaded).toEqual([{ role: "you", text: "remember me after reload" }]);
  });

  it("encrypts at rest — the chat plaintext is absent from the raw stored blob", async () => {
    const { storage, vault } = await freshScopedVault();
    const CANARY = "PLAINTEXT_CANARY_8f3a2b"; // not a secret form, so only sealing (not redaction) can hide it
    await saveChatHistory(vault, [{ role: "you", text: CANARY }]);

    const raw = await storage.read("vault.json");
    expect(raw).not.toBeNull();
    const onDisk = new TextDecoder().decode(raw!);
    expect(onDisk).not.toContain(CANARY); // sealed by vault.put → no plaintext on disk

    // NEGATIVE self-test: the canary IS recoverable through the unlocked vault (proves we stored it at all,
    // so the absence above is real encryption, not an empty write).
    expect(loadChatHistory(vault)[0].text).toBe(CANARY);
  });

  it("caps to the last 100 messages and leaves a visible trim marker (no silent truncation)", async () => {
    const big: ChatMessage[] = Array.from({ length: 150 }, (_, i) => ({ role: "you", text: `m${i}` }));
    const capped = capChatHistory(big);

    expect(capped).toHaveLength(101); // 1 marker + 100 real
    expect(capped[0].role).toBe("aside");
    expect(capped[0].text).toMatch(/50 earlier messages trimmed/); // VISIBLE, names the count
    expect(capped[1].text).toBe("m50"); // oldest 50 dropped
    expect(capped[capped.length - 1].text).toBe("m149"); // newest kept

    // NEGATIVE: a no-op cap would keep all 150 with no marker.
    expect(capped.length).toBeLessThan(big.length);
    expect(capped.some((m) => m.role === "aside")).toBe(true);
  });

  it("never stacks trim markers across successive caps", async () => {
    const once = capChatHistory(Array.from({ length: 150 }, (_, i) => ({ role: "you", text: `m${i}` })));
    // Append 60 more and cap again — the prior marker must be stripped, not doubled.
    const more: ChatMessage[] = [...once, ...Array.from({ length: 60 }, (_, i) => ({ role: "you" as const, text: `n${i}` }))];
    const twice = capChatHistory(more);
    expect(twice.filter((m) => m.role === "aside").length).toBe(1);
  });

  it("does not add a marker when under the cap", async () => {
    const small: ChatMessage[] = [{ role: "you", text: "hi" }, { role: "agent", text: "hello" }];
    expect(capChatHistory(small)).toEqual(small); // unchanged, no marker
  });
});
