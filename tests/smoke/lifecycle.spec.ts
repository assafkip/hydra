import { test, expect } from "@playwright/test";
import { gotoRoute } from "./_nav";

// ux-rail (nav overhaul 1c): the persistent lifecycle rail (Intake→Investigate→Deliver→Portfolio).
// Proves in a real browser: it renders the 4 stages with the right labels; stages flip to done as the
// case gains reports + runs; the stage owning the active route is marked current; a chip navigates to
// its route. Offline (scripted run, no network), no key leak in the rail, no off-allowlist egress.

const KEY = "sk-ant-LIFECYCLE-secret-9";

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving acme-pay.example." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "acme-pay.example" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "Done.\n```json\n{\"findings\":[" +
          "{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}," +
          "{\"entity\":\"login.acme-pay.example\",\"entity_type\":\"domain\",\"confidence\":\"high\"}" +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

test.use({ viewport: { width: 1440, height: 900 } });

test("lifecycle rail: 4 stages, done-state tracks data, current stage tracks route, chips navigate", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.waitForSelector("#auth-host", { timeout: 10_000 });
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(p: string): Promise<unknown> } }).__kipi.createVault("pw"));

  // (1) fresh vault: the rail shows the 4 stages in order, none done yet.
  const rail = page.locator("#lifecycle-rail");
  await expect(rail).toBeVisible();
  await expect(rail.locator(".lc-stage")).toHaveCount(4);
  await expect(rail.locator(".lc-label")).toHaveText(["Intake", "Investigate", "Deliver", "Portfolio"]);
  await expect(rail.locator(".lc-stage.lc-done")).toHaveCount(0);

  // (2) save the key, ingest a report (intake), run a scripted investigation (investigate).
  await gotoRoute(page, "/account");
  await page.waitForSelector("#apikey", { timeout: 15_000 });
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await page.evaluate(
    () => (window as unknown as { __kipi: { ingestText(n: string, t: string): Promise<unknown> } }).__kipi
      .ingestText("ev.txt", "acme-pay.example resolves to 93.184.216.34; both seen in the case."),
  );
  // the scripted run streams into the home graph/trail DOM (#cy/#trail) — it only exists on "/".
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });

  // after an INGEST ONLY (no agent run yet): Intake is done, Investigate is NOT — they read different
  // projections (ingest reports vs agent runs), not the same conflated run: count. Check on /reports.
  await gotoRoute(page, "/reports");
  await expect(rail.locator('.lc-stage[data-stage="intake"]')).toHaveClass(/lc-done/);
  await expect(rail.locator('.lc-stage[data-stage="investigate"]')).not.toHaveClass(/lc-done/);
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await page.evaluate(
    ([turns]) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi
      .runScriptedInvestigation("investigate acme-pay.example", turns),
    [RUN_TURNS] as const,
  );

  // (3) on /runs the rail (re-rendered) shows Investigate done + current, and Intake done (a report exists).
  await gotoRoute(page, "/runs");
  const investigate = rail.locator('.lc-stage[data-stage="investigate"]');
  await expect(investigate).toHaveClass(/lc-done/);
  await expect(investigate).toHaveClass(/lc-current/);
  await expect(rail.locator('.lc-stage[data-stage="intake"]')).toHaveClass(/lc-done/);

  // (4) current tracks the route: /reports -> Intake current, Investigate no longer current.
  await gotoRoute(page, "/reports");
  await expect(rail.locator('.lc-stage[data-stage="intake"]')).toHaveClass(/lc-current/);
  await expect(investigate).not.toHaveClass(/lc-current/);

  // (5) a chip navigates to its stage route.
  await rail.locator('.lc-stage[data-stage="deliver"]').click();
  await expect(page).toHaveURL(/#\/deliverables$/);

  // (6) no key leak in the rail chrome.
  expect(await rail.textContent()).not.toContain(KEY);
});
