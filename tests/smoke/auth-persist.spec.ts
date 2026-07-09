import { test, expect } from "@playwright/test";

// clu-auth (stay signed in on this device, founder 2026-06-20): a vault must survive a page reload
// WITHOUT re-entering the password, and an explicit Sign out must lock it. The mechanism is a
// non-extractable data CryptoKey kept in IndexedDB (src/vault/session.ts), restored by
// bootstrapSession before first paint. Pairs with issue-clu-auth-usability.

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
});

test("a vault stays unlocked across a reload; Sign out then reload locks it", async ({ page }) => {
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.goto("/#/"); // the workspace (graph home)
  await expect(page.locator("#graph")).toBeVisible(); // unlocked
  await expect(page.locator("#auth-pw")).toHaveCount(0); // no login form

  // RELOAD — must STILL be unlocked via the persisted session key (no re-login).
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  await expect(page.locator("#graph")).toBeVisible();
  await expect(page.locator("#auth-pw")).toHaveCount(0);

  // Sign out from /account → the real lock (forgets the persisted key).
  await page.goto("/#/account");
  await expect(page.locator("#lockBtn")).toBeVisible();
  await page.click("#lockBtn");

  // RELOAD after Sign out — must be LOCKED (the login form returns, no graph).
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  await expect(page.locator("#auth-pw")).toBeVisible();
  await expect(page.locator("#graph")).toHaveCount(0);
});
