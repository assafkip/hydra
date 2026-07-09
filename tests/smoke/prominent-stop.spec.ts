import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";

// ch-prominent-stop (controls-honesty): the in-dock #stopBtn (small, grey, bottom of the chat bar) read as
// undiscoverable for a long/spendy run, and the top "Investigating…" banner had no Stop. The "Investigator
// running…" chip — a prominent pulsing pill with a Stop that reuses activeAbort.abort() — is now shown on
// EVERY route while a run is live (was suppressed on home/detail). These tests drive the REAL run path and
// assert the chip is reachable on home AND that clicking its Stop actually HALTS the run (the promise
// resolves stopReason "aborted" + run-store status aborted) — not just that the UI hides.

const TURNS_HANG = [
  {
    content: [
      { type: "text", text: "Resolving evil.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "evil.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  { __waitForStop: true },
];

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
}

async function startHangingRun(page: Page) {
  await page.evaluate((turns) => {
    (window as any)._runP = (window as any).__kipi.runScriptedInvestigation("investigate evil.com", turns);
  }, TURNS_HANG);
  await page.waitForFunction(() => (window as any).__kipi.runStore().status === "running");
}

test("ch-prominent-stop: the run chip is reachable on HOME during a run and its Stop halts the run", async ({ page }) => {
  await freshVault(page);
  await startHangingRun(page);

  // the prominent chip is visible on home (previously suppressed here) with a Stop
  const chip = page.locator("#run-chip");
  await expect(chip).toBeVisible();
  const stop = page.locator("#run-chip-stop");
  await expect(stop).toBeVisible();

  await stop.click();

  // the run ACTUALLY halts: the in-flight promise resolves stopReason "aborted" AND the store goes aborted
  const stopReason = await page.evaluate(async () => (await (window as any)._runP).stopReason);
  expect(stopReason).toBe("aborted");
  const events = await page.evaluate(() => (window as any).__kipi.runEvents());
  expect(events.terminal).toBe("run_aborted");
  expect(events.counts.run_aborted).toBe(1);
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.runStore().status)).toBe("aborted");
  await expect(chip).toContainText("Run stopped");
  await expect(page.locator("#run-chip-stop")).toBeHidden();
});

test("ch-prominent-stop: the chip is reachable off-home too (OSINT) and halts the run", async ({ page }) => {
  await freshVault(page);
  await startHangingRun(page);

  await gotoRoute(page, "/enrich"); // run survives nav (rsn) — chip must stay reachable
  await expect(page.locator("#run-chip")).toBeVisible();
  await page.locator("#run-chip-stop").click();

  const stopReason = await page.evaluate(async () => (await (window as any)._runP).stopReason);
  expect(stopReason).toBe("aborted");
  const events = await page.evaluate(() => (window as any).__kipi.runEvents());
  expect(events.terminal).toBe("run_aborted");
  expect(events.counts.run_aborted).toBe(1);
});
