import { describe, expect, it } from "vitest";
import { renderProposedActionCard, type ProposedActionCard } from "../../src/chat/action-card";

class FakeElement {
  className = "";
  dataset: Record<string, string> = {};
  textContent: string | null = "";
  type = "";
  children: FakeElement[] = [];
  listeners: Record<string, (() => void)[]> = {};

  set innerHTML(_value: string) {
    throw new Error("innerHTML is forbidden for proposed action cards");
  }

  appendChild(child: FakeElement): FakeElement {
    this.children.push(child);
    return child;
  }

  addEventListener(name: string, fn: () => void): void {
    this.listeners[name] = [...this.listeners[name] ?? [], fn];
  }

  click(): void {
    for (const fn of this.listeners.click ?? []) fn();
  }
}

class FakeDocument {
  createElement(_tag: string): FakeElement {
    return new FakeElement();
  }
}

const ACTION: ProposedActionCard = {
  id: "act-1",
  kind: "add_relationship",
  title: "Propose relationship",
  body: "alpha.example may resolve to 1.2.3.4. Verify before commit.",
};

describe("proposed action cards", () => {
  it("renders typed action data with textContent, not HTML", () => {
    const card = renderProposedActionCard(
      { ...ACTION, title: "<img src=x onerror=alert(1)>", body: "<b>not html</b>" },
      {},
      new FakeDocument() as unknown as Document,
    ) as unknown as FakeElement;

    expect(card.className).toBe("proposed-action-card");
    expect(card.dataset).toEqual({ actionId: "act-1", actionKind: "add_relationship" });
    expect(card.children[0].textContent).toBe("<img src=x onerror=alert(1)>");
    expect(card.children[1].textContent).toBe("<b>not html</b>");
  });

  it("exposes explicit approve and cancel actions", () => {
    const approved: string[] = [];
    const cancelled: string[] = [];
    const card = renderProposedActionCard(
      ACTION,
      {
        onApprove: (a) => approved.push(a.id),
        onCancel: (a) => cancelled.push(a.id),
      },
      new FakeDocument() as unknown as Document,
    ) as unknown as FakeElement;
    const controls = card.children[2];
    const approve = controls.children[0];
    const cancel = controls.children[1];

    expect(approve.textContent).toBe("Approve");
    expect(cancel.textContent).toBe("Cancel");
    approve.click();
    cancel.click();
    expect(approved).toEqual(["act-1"]);
    expect(cancelled).toEqual(["act-1"]);
  });
});
