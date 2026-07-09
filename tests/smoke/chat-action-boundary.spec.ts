import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";

const KEY = "sk-ant-BOUNDARY-secret-77";
const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
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

async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account");
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]');
  await expect(page.locator("#chat-input")).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await freshKeyedVault(page);
});

test("destructive chat asks are blocked and do not start a run", async ({ page }) => {
  await page.fill("#chat-input", "delete all findings");
  await page.click("#chat-send");

  await expect(page.locator("#chat-messages")).toContainText("cannot be committed from chat text alone");
  await expect(page.locator("#chat-busy")).toBeHidden();
  expect(await page.evaluate(() => (window as any).__kipi.runStore())).toMatchObject({ status: "idle", steps: 0 });
  expect(await page.evaluate(() => (window as any).__kipi.runEvents())).toMatchObject({ runId: null, active: false });
});

test("raw upload graph dump asks are refused with the extraction/gating path", async ({ page }) => {
  await page.fill("#chat-input", "add every uploaded entity to the graph");
  await page.click("#chat-send");

  await expect(page.locator("#chat-messages")).toContainText("extraction, typing, and gating");
  expect(await page.evaluate(() => (window as any).__kipi.runStore())).toMatchObject({ status: "idle", steps: 0 });
});

test("co-occurrence edge asks are verify-first proposals, not committed edges", async ({ page }) => {
  await page.fill("#chat-input", "create edges for every co-occurrence");
  await page.click("#chat-send");

  await expect(page.locator(".proposed-action-card")).toContainText("verify with evidence before adding an edge");
  expect(await page.evaluate(() => (window as any).__kipi.runStore())).toMatchObject({ status: "idle", steps: 0 });
});

test("approved graph-node removal goes through an explicit action card; cancel does nothing", async ({ page }) => {
  await page.evaluate((turns) => (window as any).__kipi.installChatWire({ turns }), RUN_TURNS);
  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");
  // remove-chat-findings (2026-07-08): the #findings column is gone — wait for the ip on the GRAPH.
  await expect.poll(() => page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel())), { timeout: 10_000 }).toContain("93.184.216.34");
  const before = await page.evaluate(() => (window as any).__kipi.cyCounts());
  expect(before.nodes).toBe(2);

  await page.fill("#chat-input", "remove 93.184.216.34");
  await page.click("#chat-send");
  await expect(page.locator(".proposed-action-card").last()).toContainText("Remove graph node?");
  await page.locator(".proposed-action-card").last().getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator("#chat-messages")).toContainText("Cancelled.");
  expect(await page.evaluate(() => (window as any).__kipi.cyCounts())).toEqual(before);

  await page.fill("#chat-input", "remove 93.184.216.34");
  await page.click("#chat-send");
  await page.locator(".proposed-action-card").last().getByRole("button", { name: "Remove" }).click();
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes)).toBeLessThan(before.nodes);
  await expect(page.locator("#chat-messages")).toContainText("Approved: Remove graph node?");
});
