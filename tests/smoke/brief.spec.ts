import { test, expect } from "@playwright/test";

// PRD-4 p4-smoke (Playwright): prove the brief RENDERS in a real browser by driving a
// SCRIPTED brief (injected fetch — no key, no network) through the same render path the
// Generate-brief button uses. The live brief is the user's (docs/agent-loop.md).

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
});

test("a scripted brief renders into #brief", async ({ page }) => {
  const briefText = "# Investigation brief\n## Executive summary\nlive.example.com is operating now.";
  const res = await page.evaluate(
    (t) => (window as any).__kipi.runScriptedBrief("Investigate live.example.com", t),
    briefText,
  );
  expect(res.brief).toContain("Investigation brief");
  await expect(page.locator("#brief")).toContainText("Executive summary");
  await expect(page.locator("#brief")).toContainText("live.example.com is operating now");
});
