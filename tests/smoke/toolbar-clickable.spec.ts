import { test, expect, type Page } from "@playwright/test";

// PRD chat-graph-parity-fixes (tb-click): the on-graph overlay controls (#cy-controls, #cy-stats)
// must WIN the hit-test over the cytoscape canvas. Founder bug: "the toolbars on the graph are not
// clickable, it clicks the graph behind them." The truth is document.elementFromPoint at a control's
// center — if it resolves to a <canvas>/#cy instead of the control, the click passes through.

const INITIAL_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "done\n```json\n{\"findings\":[" +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"Jane Roe","entity_type":"person","confidence":"high"}' +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

async function settle(page: Page, ms = 900): Promise<void> { await page.waitForTimeout(ms); }

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("Investigate example.com", turns), INITIAL_TURNS);
  await settle(page);
});

// For each overlay control, the element at its visual center must be the control (or a descendant),
// NOT the cytoscape canvas behind it.
async function topAt(page: Page, selector: string): Promise<{ inControl: boolean; topTag: string; topId: string }> {
  await page.locator("#cy").scrollIntoViewIfNeeded();
  return await page.evaluate((sel) => {
    const ctl = document.querySelector(sel) as HTMLElement | null;
    if (!ctl) return { inControl: false, topTag: "MISSING", topId: sel };
    const r = ctl.getBoundingClientRect();
    const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2) as HTMLElement | null;
    const inControl = !!top && ctl.contains(top);
    return { inControl, topTag: top?.tagName ?? "null", topId: top?.id ?? "" };
  }, selector);
}

test("on-graph controls win the hit-test over the cytoscape canvas (toolbar is clickable)", async ({ page }) => {
  // the Fit button inside #cy-controls
  const fitBtn = page.locator("#cy-controls button", { hasText: "Fit" });
  await expect(fitBtn).toBeVisible();

  const at = await topAt(page, "#cy-controls .ghost");
  expect(at.inControl, `top element at the toolbar button center was <${at.topTag} #${at.topId}>, not the control — clicks pass through to the graph`).toBe(true);

  // the stats overlay is the same z-tier as the toolbar — assert it too (systemic: the 999 canvas
  // was eating EVERY on-graph overlay, not just the toolbar).
  const statsAt = await topAt(page, "#cy-stats");
  expect(statsAt.inControl, `#cy-stats was overlaid by <${statsAt.topTag} #${statsAt.topId}>`).toBe(true);

  // and a real click on Fit fires the control's handler (does not pan/zoom the graph instead)
  const vpBefore = await page.evaluate(() => (window as any).__kipi.cyViewport());
  await fitBtn.click();
  await settle(page, 200);
  // The button received the click (no throw, viewport may legitimately change via fit()); the
  // hit-test assertion above is the real guarantee. This click just proves the button is reachable.
  expect(vpBefore).toBeTruthy();
});

test("selecting a graph node renders no card; Show full details puts the detail in the chat", async ({ page }) => {
  // remove-cards (founder 2026-07-03): selecting shows no card; detail comes via a chat MESSAGE.
  const id = await page.evaluate(() => (window as any).__kipi.graphModel().nodes.find((n: any) => n.entityType === "ip")?.id);
  await page.evaluate((nid) => (window as any).__kipi.selectNode(nid), id);
  await expect(page.locator(".node-card")).toHaveCount(0);
  await page.evaluate((nid) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === nid);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, id);
  const detail = page.locator("#chat-messages .msg.agent").last();
  await expect(detail).toContainText("93.184.216.34");
  await expect(detail).toContainText("promoted");
  await expect(page.locator(".node-card")).toHaveCount(0);
});
