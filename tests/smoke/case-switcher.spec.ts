import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// case-switcher (brief §Cases #16): the top-right header chip is a DROPDOWN that switches the active case
// from ANY page (no /cases round-trip). Create a 2nd case, open the dropdown from /entities, switch back
// via it, and assert the active case (chip text) + the dropdown lifecycle. No theater.

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
}

test("the header chip dropdown lists the vault's cases and switches the active case from any page", async ({ page }) => {
  await freshVault(page);
  // a provisioned test vault starts on its starter case (no implicit "Default case" anymore)
  await expect(page.locator("#case-chip")).toHaveText("Test case");

  // create a 2nd case via /cases — it becomes active (the chip updates)
  await gotoRoute(page, "/cases");
  await page.locator(".case-name-input").fill("Case Bravo");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Case Bravo", { timeout: 10_000 });

  // navigate AWAY from /cases, then open the HEADER dropdown — switching is now a one-click verb anywhere
  await gotoRoute(page, "/entities");
  await expect(page.locator("#case-menu")).not.toBeVisible();
  await page.click("#caseChipBtn");
  await expect(page.locator("#case-menu")).toBeVisible();
  // it lists BOTH cases, with the active one marked
  await expect(page.locator(".case-menu-item")).toHaveCount(2);
  await expect(page.locator(".case-menu-item.active")).toContainText("Case Bravo");

  // switch to the starter case via the dropdown (no /cases page) → the chip + scope follow
  await page.locator(".case-menu-item", { hasText: "Test case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Test case", { timeout: 10_000 });
  // the menu closed itself after the switch
  await expect(page.locator("#case-menu")).not.toBeVisible();
  // and the active mark moved to the starter case on the now-refreshed menu
  await page.click("#caseChipBtn");
  await expect(page.locator(".case-menu-item.active")).toContainText("Test case");
});
