import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// ux-polish (Goal 6 / the Dr. Maya Chen design brief): proves the additive UX affordances shipped —
// the Runs "View step trail" affordance + no leaked end_turn, the Exports downloads disabled on an empty
// case, the Account key card before the storage bar, and the Entities chip legend.

const RUN = [
  { content: [{ type: "text", text: "Resolving probe.example.com." }, { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "probe.example.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
  { content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' }], stop_reason: "end_turn", usage: { output_tokens: 20 } },
];

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
}

test("Account: the Anthropic key card renders before the storage bar (brief §Account #17)", async ({ page }) => {
  await freshVault(page);
  await gotoRoute(page, "/account");
  await expect(page.locator("#keycard")).toBeVisible();
  const keyBeforeStorage = await page.evaluate(() => {
    const key = document.getElementById("keycard");
    const storage = Array.from(document.querySelectorAll(".pg-body *")).find((e) => (e.textContent || "").includes("Save to a folder"));
    if (!key || !storage) return false;
    return Boolean(key.compareDocumentPosition(storage) & Node.DOCUMENT_POSITION_FOLLOWING);
  });
  expect(keyBeforeStorage).toBe(true);
});

test("Exports: the downloads are DISABLED on an empty case (brief §Exports #15)", async ({ page }) => {
  await freshVault(page);
  await gotoRoute(page, "/exports");
  // EVERY export download is disabled on an empty case (codex: not just the first)
  await expect(page.locator(".exp-actions button:not([disabled])")).toHaveCount(0);
  await expect(page.locator(".exp-actions button").first()).toBeDisabled();
});

test("Runs: a run card shows the 'View step trail' affordance; no raw end_turn (brief §Runs #3)", async ({ page }) => {
  await freshVault(page);
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("investigate probe.example.com", t), RUN);
  await page.evaluate((r) => { location.hash = "#" + r; }, "/runs"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".run-trail-hint").first()).toContainText("View step trail");
  await expect(page.locator(".run-card").first()).not.toContainText("end_turn");
  // the affordance actually TOGGLES the trail open/closed (codex: prove it's not a dead label)
  await page.locator(".run-trail-hint").first().click();
  await expect(page.locator(".run-trail-hint").first()).toContainText("Hide step trail");
  await page.locator(".run-trail-hint").first().click();
  await expect(page.locator(".run-trail-hint").first()).toContainText("View step trail");
});

test("Entities: the chip legend explains the scoring vocab (brief §Entities #4)", async ({ page }) => {
  await freshVault(page);
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("investigate probe.example.com", t), RUN);
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-legend")).toContainText("promoted");
});
