import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// kk-search smoke (the live proof): the ⌘K modal searches the client entity DB, renders a textContent
// result list (an XSS-payload value is literal, never markup), and a result click navigates to /entities
// and focuses (expands) that entity's row. No network for the search; no key leak.

const APIKEY = "sk-ant-KK-smoke-5050";
const XSS = "evil<img src=x onerror=alert(1)>.com"; // an entity value with markup — must render literal

const SEED_TURNS = [
  {
    content: [
      {
        type: "text",
        text: `Done.\n\`\`\`json\n{"findings":[{"entity":"example.com","entity_type":"domain"},{"entity":"${XSS}","entity_type":"domain"}]}\n\`\`\``,
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 10 },
  },
];

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}

test("⌘K search: entity-DB results render literal, click focuses the /entities row; no network, no key leak", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  // seed two entities (one with an XSS-payload value)
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("seed search", turns), SEED_TURNS);

  // open the search modal + type a fragment
  await page.click("#searchBtn");
  await page.fill("#cmdk-input", "e"); // matches both example.com + evil<...>.com
  await expect(page.locator("#cmdk-results .cmdk-result")).not.toHaveCount(0);

  // the XSS value renders as LITERAL text, never an injected element
  await expect(page.locator("#cmdk-results")).toContainText("<img src=x onerror=alert(1)>");
  expect(await page.locator("#cmdk-results img").count()).toBe(0);

  // click the example.com result -> the modal closes + /entities focuses that row (expanded)
  await page.locator("#cmdk-results .cmdk-result", { hasText: "example.com" }).first().click();
  await expect(page.locator("#cmdk-input")).not.toBeVisible(); // the modal closed on select
  await expect(page.locator(".pg-title")).toHaveText("Entities");
  await expect(page.locator(".ent-row .ent-detail:not([hidden])").first()).toBeVisible();

  // no network fired for the search; no key on the page
  expect(external).toEqual([]);
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);

  await page.screenshot({ path: "test-results/kipi-search.png", fullPage: true });
});
