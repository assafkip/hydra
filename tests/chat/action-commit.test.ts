import { describe, expect, it } from "vitest";
import { commitChatAction } from "../../src/chat/action-commit";
import type { ProposedActionCard } from "../../src/chat/action-card";
import type { ChatActionPolicy } from "../../src/chat/action-policy";

const ACTION: ProposedActionCard = {
  id: "act-1",
  kind: "promote_finding",
  title: "Promote finding",
  body: "Promote alpha.example after review.",
};

function policy(kind: ChatActionPolicy["kind"], commit: ChatActionPolicy["commit"]): ChatActionPolicy {
  return { kind, commit, reason: "test", userText: "test" };
}

describe("chat action commit chokepoint", () => {
  it("allows explicit proposed actions to reach the writer", async () => {
    const calls: string[] = [];
    const result = await commitChatAction(
      { policy: policy("propose", "approval_required"), action: ACTION },
      async (a) => {
        calls.push(a.id);
        return { ok: true, actionId: a.id };
      },
    );

    expect(result).toEqual({ ok: true, actionId: "act-1" });
    expect(calls).toEqual(["act-1"]);
  });

  it("blocks answer/investigate/blocked policy states before the writer", async () => {
    for (const p of [
      policy("answer", "none"),
      policy("investigate", "run"),
      policy("blocked", "none"),
      policy("needs_capability", "none"),
    ]) {
      const calls: string[] = [];
      const result = await commitChatAction({ policy: p, action: ACTION }, async (a) => {
        calls.push(a.id);
        return { ok: true, actionId: a.id };
      });

      expect(result.ok).toBe(false);
      expect(calls).toEqual([]);
    }
  });
});
