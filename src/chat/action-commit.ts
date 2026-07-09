import type { ChatActionPolicy } from "./action-policy.js";
import type { ProposedActionCard } from "./action-card.js";

export type ChatCommitResult =
  | { ok: true; actionId: string }
  | { ok: false; reason: string };

export interface ChatCommitRequest {
  policy: ChatActionPolicy;
  action: ProposedActionCard;
}

export type ChatCommitWriter = (action: ProposedActionCard) => ChatCommitResult | Promise<ChatCommitResult>;

export async function commitChatAction(req: ChatCommitRequest, writer: ChatCommitWriter): Promise<ChatCommitResult> {
  if (req.policy.kind !== "propose" || req.policy.commit !== "approval_required") {
    return { ok: false, reason: "Only explicit proposed actions can reach the chat commit chokepoint." };
  }
  return writer(req.action);
}
