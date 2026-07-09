import { test, expect } from "@playwright/test";

// ux-starthere (brief §1/X-5): the empty-home "Start here" hero. Proves: a fresh case shows the hero
// (heading + 3 numbered step buttons) over the empty graph; step 1 navigates to /reports; step 2 RUNS
// Process (does NOT navigate — sp-1514a4c5 pins the sp-52b54ad2 mis-wire); step 3 focuses the
// Investigator input (the front door); once a run exists the hero is hidden and the graph shows.
// Offline (scripted run), no network.

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving probe.example." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "probe.example" } },
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
          "{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}" +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 14 },
  },
];

test.use({ viewport: { width: 1440, height: 900 } });

test("home Start-here: hero on an empty case, chips route + focus the Investigator, fades once data exists", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.waitForSelector("#auth-host", { timeout: 10_000 });
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(p: string): Promise<unknown> } }).__kipi.createVault("pw"));

  // (1) fresh case: the Start-here hero is visible with 3 steps over the empty graph.
  const hero = page.locator("#cy-empty.start-here");
  await expect(hero).toBeVisible();
  await expect(hero.locator(".sh-title")).toHaveText("Start here");
  await expect(hero.locator(".sh-step")).toHaveCount(3);
  await expect(hero.locator(".sh-step-label")).toHaveText(["Add evidence", "Process the case", "Investigate"]);

  // (2) step 3 focuses the Investigator input (the front door).
  await hero.locator('.sh-step[data-sh="investigate"]').click();
  await expect(page.locator("#chat-input")).toBeFocused();

  // (3) sp-1514a4c5: step 2 "Process the case" RUNS Process — it must NOT navigate to /reports (the
  // sp-52b54ad2 mis-wire that shipped because no test pinned the click target). runProcessJob({auto}) posts
  // a "Analyzing the case…" notice into the chat (notifyUser → pushAside, since the dock is mounted) and
  // never changes route.
  await hero.locator('.sh-step[data-sh="process"]').click();
  await expect(page.locator("#chat-messages")).toContainText("Analyzing the case"); // Process started, not a route change
  await expect(page).not.toHaveURL(/#\/reports$/); // did NOT navigate like step 1
  await expect(hero).toBeVisible(); // still home

  // (4) step 1 navigates to Reports & intake.
  await page.click('a[data-route="/"]'); // back home (the hero is here)
  await expect(hero).toBeVisible();
  await hero.locator('.sh-step[data-sh="reports"]').click();
  await expect(page).toHaveURL(/#\/reports$/);

  // (5) once a run exists, the hero is hidden and the graph renders.
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await page.evaluate(
    ([turns]) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi
      .runScriptedInvestigation("investigate probe.example", turns),
    [RUN_TURNS] as const,
  );
  // re-enter home so hydrateCaseGraph runs against the persisted run.
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await expect(page.locator("#cy-empty")).toBeHidden();
});
