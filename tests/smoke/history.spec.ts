import { test, expect } from "@playwright/test";
import { gotoRoute } from "./_nav";
import { readFileSync } from "node:fs";

// PRD-6 p6-smoke: prove the History surface + brief download in a real browser, and
// prove (adversarially) that the reserved secret namespace / the live key never leak
// into History, the rendered brief, or the .md download.

const KEY = "sk-ant-HISTKEY-1";
const BRIEF = "# Investigation brief\n## Executive summary\nlive.example.com is operating now.";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
});

test("History lists past runs + briefs and reopens a brief", async ({ page }) => {
  await page.evaluate((b) => (window as any).__kipi.runScriptedBrief("Investigate live.example.com", b), BRIEF);
  // History moved to /account (ac-ui)
  await gotoRoute(page, "/account");
  await expect(page.locator("#history")).toContainText("Investigate live.example.com");
  await expect(page.locator("#history")).toContainText("promoted");
  // reopen the brief from history — viewBrief routes home and shows it in the dock (#brief)
  await page.locator(".histbrief button", { hasText: "Investigate live.example.com" }).click();
  await expect(page.locator("#brief")).toContainText("Executive summary");
});

test("secret namespace + key never leak into History, the brief, or the download", async ({ page }) => {
  // adversarial seeds: a run whose objective IS the secret key name, and a brief whose BODY holds the key
  await page.evaluate(
    ([key]) => {
      const k = (window as any).__kipi;
      return Promise.all([
        k.putCase("run:secret:anthropic_key", { objective: "secret:anthropic_key", promoted: [], leads: [], stopReason: "end_turn" }),
        k.putCase("brief:bodytest", { objective: "bodytest", brief: `the report leaks ${key} here` }),
      ]);
    },
    [KEY],
  );
  // a normal scripted brief triggers a History refresh that runs the (filtering) helpers
  await page.evaluate((b) => (window as any).__kipi.runScriptedBrief("Investigate live.example.com", b), BRIEF);

  // History moved to /account (ac-ui) — read it there
  await gotoRoute(page, "/account");
  const history = (await page.locator("#history").textContent()) ?? "";
  expect(history).not.toContain("secret:anthropic_key"); // secret-prefixed run dropped
  expect(history).not.toContain(KEY);

  // the data hooks the UI uses are secret-safe
  const runs = await page.evaluate(() => (window as any).__kipi.listRuns().map((r: any) => r.objective));
  expect(runs).not.toContain("secret:anthropic_key");
  const bodyBrief = await page.evaluate(() => (window as any).__kipi.getBrief("bodytest").brief);
  expect(bodyBrief).not.toContain(KEY);
  expect(bodyBrief).toContain("[REDACTED]");

  // reopen the live brief from History (viewBrief routes home + shows it in the dock), then download it
  await page.locator(".histbrief button", { hasText: "Investigate live.example.com" }).click();
  await expect(page.locator("#brief")).toContainText("Executive summary");
  // the .md download carries the redacted brief, never the key
  const [download] = await Promise.all([page.waitForEvent("download"), page.click("#dlBriefBtn")]);
  expect(download.suggestedFilename()).toBe("brief.md");
  const path = await download.path();
  const contents = readFileSync(path, "utf8");
  expect(contents).not.toContain(KEY);
  expect(contents).toContain("Executive summary");
});
