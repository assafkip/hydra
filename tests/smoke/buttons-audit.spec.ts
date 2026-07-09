import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";

// ch-buttons-audit (controls-honesty): the two minor PARTIALs the live button audit surfaced.
// CHECK A: header Back (#chrome-back) silently no-op'd when there was no in-app history (it read as dead).
//   It is now HIDDEN where Back is meaningless (home, the locked login gate, create-first-case) and on any
//   real in-app route it returns home via navigate("/") — always inside Hydra, never history.back() (which
//   could leave the app on a deep link). Hidden via inline style.display — the `hidden` attribute is
//   overridden by the element's Tailwind `.flex` class.
// CHECK B: OSINT "Run all applicable providers" with an empty target. The audit flagged it as a silent
//   no-op; on inspection the validation already existed — this test LOCKS that it shows the message (no
//   redundant code was added; scope discipline).

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
}

test("ch-buttons-audit A: Back is hidden on the login gate, hidden on home, and returns home off-route", async ({ page }) => {
  // locked / no-vault login gate — Back is meaningless here too (codex: was wrongly shown). Hidden.
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset()); // no vault → the create/unlock gate
  await expect(page.locator("#chrome-back")).toBeHidden();

  await page.evaluate(() => (window as any).__kipi.createVault("pw")); // unlocked, home
  // on home, Back is meaningless → hidden (so it can never read as a dead click)
  await expect(page.locator("#chrome-back")).toBeHidden();

  // on a detail route, Back is shown and returns to home (always inside Hydra)
  await gotoRoute(page, "/entities");
  await expect(page.locator("#chrome-back")).toBeVisible();
  await page.locator("#chrome-back").click();
  await expect.poll(() => page.evaluate(() => location.hash)).toMatch(/^#\/?$|^$/); // landed on home
  await expect(page.locator("#chrome-back")).toBeHidden(); // and hidden again on home
});

test("ch-buttons-audit B: OSINT 'Run all' with an empty target shows inline validation (not a silent no-op)", async ({ page }) => {
  await freshVault(page);
  await gotoRoute(page, "/enrich");

  // ensure the target field is empty, then click Run all
  const input = page.locator(".enr-ef-input");
  await input.fill("");
  await page.getByRole("button", { name: /Run all applicable/ }).click();

  // a clear inline message, not a silent no-op; and no run was kicked off
  await expect(page.locator(".enr-ef-out")).toContainText("Pick or enter an entity first");
  expect(await page.evaluate(() => (window as any).__kipi.runStore().status)).toBe("idle");
});
