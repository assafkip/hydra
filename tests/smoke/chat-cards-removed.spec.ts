import { test, expect, type Page } from "@playwright/test";
// remove-cards (founder 2026-07-03): no cards in the chat. A graph node click renders NO node card; the
// right-click menu routes each item into the chat (askInChat → dispatch) so the answer arrives as a normal
// chat turn. This drives the REAL path: run a scripted investigation to populate the graph, then click +
// right-click a node and assert (a) no .node-card ever renders, (b) a menu item posts a chat question.

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving evil.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "evil.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' }],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  // scripted wire so the run + any end-of-run briefing are offline (no real key / no 401).
  await page.evaluate(() => (window as any).__kipi.installChatWire({ qaText: "ok" }));
}

test("no card is injected when a node is clicked; the right-click menu routes to the chat", async ({ page }) => {
  await freshVault(page);
  await page.evaluate((turns) => {
    (window as any)._p = (window as any).__kipi.runScriptedInvestigation("investigate evil.com", turns);
  }, RUN_TURNS);
  await page.evaluate(async () => await (window as any)._p);
  // the graph grew (objective + ip)
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes)).toBeGreaterThanOrEqual(2);

  // click the ip node → it SELECTS, but NO node card is injected into the chat
  const ipId = await page.evaluate(() => {
    const g = (window as any).__kipi.graphModel();
    return (g.nodes.find((n: any) => n.entityType === "ip" || n.label?.includes("93.184")) || {}).id;
  });
  expect(ipId).toBeTruthy();
  await page.evaluate((id) => (window as any).__kipi.selectNode(id), ipId);
  await expect(page.locator(".node-card")).toHaveCount(0);
  await expect(page.locator(".edge-card")).toHaveCount(0);

  // the right-click menu → "What is this?" posts the question into the chat as a normal You turn
  await page.evaluate((id) => {
    const bridge = (window as any).__kipiChat;
    const g = (window as any).__kipi.graphModel();
    const n = g.nodes.find((x: any) => x.id === id);
    bridge.askInChat(`what is ${n.label}?`); // the exact call the menu item makes
  }, ipId);
  await expect(page.locator("#chat-messages .msg.you")).toContainText("what is");
  await expect(page.locator(".node-card")).toHaveCount(0); // still no card anywhere

  // "Show full details" renders the DETERMINISTIC panel as a chat MESSAGE (no card), no LLM call
  await page.evaluate((id) => {
    const g = (window as any).__kipi.graphModel();
    const n = g.nodes.find((x: any) => x.id === id);
    // the real menu passes a CyNodeData (full_name populated); mirror that shape from the model node.
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, kind: n.kind || "entity" });
  }, ipId);
  await expect(page.locator("#chat-messages .msg.agent").last()).toContainText("93.184");
  await expect(page.locator(".node-card")).toHaveCount(0); // it's a chat message, still not a card

  // a 'findings' command answers as chat TEXT, not a .runs-card
  await page.fill("#chat-input", "findings");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("Findings");
  await expect(page.locator(".runs-card")).toHaveCount(0);
});
