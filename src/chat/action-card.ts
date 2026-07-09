export type ProposedActionKind = "promote_finding" | "add_relationship" | "delete_finding" | "remove_graph_node";

export interface ProposedActionCard {
  id: string;
  kind: ProposedActionKind;
  title: string;
  body: string;
  target?: string;
  approveLabel?: string;
  cancelLabel?: string;
}

export interface ProposedActionHandlers {
  onApprove?: (action: ProposedActionCard) => void;
  onCancel?: (action: ProposedActionCard) => void;
}

type DocLike = Pick<Document, "createElement">;

export function renderProposedActionCard(
  action: ProposedActionCard,
  handlers: ProposedActionHandlers = {},
  doc: DocLike = document,
): HTMLElement {
  const card = doc.createElement("section");
  card.className = "proposed-action-card";
  card.dataset.actionId = action.id;
  card.dataset.actionKind = action.kind;

  const title = doc.createElement("h3");
  title.textContent = action.title;
  card.appendChild(title);

  const body = doc.createElement("p");
  body.textContent = action.body;
  card.appendChild(body);

  const controls = doc.createElement("div");
  controls.className = "proposed-action-controls";

  const approve = doc.createElement("button");
  approve.type = "button";
  approve.textContent = action.approveLabel ?? "Approve";
  approve.addEventListener("click", () => handlers.onApprove?.(action));

  const cancel = doc.createElement("button");
  cancel.type = "button";
  cancel.className = "ghost";
  cancel.textContent = action.cancelLabel ?? "Cancel";
  cancel.addEventListener("click", () => handlers.onCancel?.(action));

  controls.appendChild(approve);
  controls.appendChild(cancel);
  card.appendChild(controls);
  return card;
}
