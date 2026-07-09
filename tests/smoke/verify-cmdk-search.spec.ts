import { test, expect, type Page } from "@playwright/test";

// cap-cmdk-search parity verification (PRD prd-kipi-web-cmdk-search-2026-06-18).
// The global ⌘K / Ctrl-K search over the client entity DB. Proven live, end to end, with the REAL
// keyboard workflow (codex-hardened): the shortcut opens AND focuses the input, typing queries the
// SAVED entity DB (proven by searching from a non-graph page), results render, and a result click
// navigates to /entities and FOCUSES (expands) the chosen entity. RCA #2: a code read is not acceptance.

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving acme-pay.example and pivoting on its infra." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "acme-pay.example" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 12 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "Done.\n```json\n{\"findings\":[" +
          "{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}," +
          "{\"entity\":\"login.acme-pay.example\",\"entity_type\":\"domain\",\"confidence\":\"high\"}," +
          "{\"entity\":\"pay-acme.example\",\"entity_type\":\"domain\",\"confidence\":\"medium\"}" +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 28 },
  },
];

async function seedRun(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.evaluate(
    ([turns]) => (window as any).__kipi.runScriptedInvestigation("investigate acme-pay.example", turns),
    [RUN_TURNS] as const,
  );
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
}

async function resultLabels(page: Page): Promise<string[]> {
  const texts = await page.locator("#cmdk-results .cmdk-result").allInnerTexts();
  return texts.map((t) => t.split(" · ")[0]);
}

test.use({ viewport: { width: 1440, height: 900 } });

test("cmd-K opens + focuses search, queries the saved entity DB, and a result navigates + focuses", async ({ page }) => {
  await seedRun(page);

  // D5: leave the graph (a non-graph page) so a passing search can ONLY be reading the SAVED entity DB
  // (searchEntities uses entityDbFor(vault, null)), not the in-session graph model.
  await page.click('a[data-route="/enrich"]');
  await page.waitForTimeout(300);

  // (1) the modal is closed until the KEYBOARD shortcut fires it
  await expect(page.locator("#cmdk-input")).toBeHidden();
  await page.keyboard.press("Control+k");
  await expect(page.locator("#cmdk-input"), "Ctrl-K opens the modal").toBeVisible();

  // (2) D3: Ctrl-K AUTOFOCUSES the input — the real keyboard workflow. Type with the keyboard (not
  // page.fill, which would bypass focus) and assert the input is the activeElement.
  await expect
    .poll(() => page.evaluate(() => document.activeElement?.id), {
      timeout: 3_000,
      message: "Ctrl-K focuses #cmdk-input so a user can type immediately",
    })
    .toBe("cmdk-input");
  await page.keyboard.type("acme");
  await page.waitForSelector("#cmdk-results .cmdk-result", { timeout: 5_000 });

  // (3) results are the SAVED entity-DB rows: 'acme' matches the two domains, NOT the ip
  const labels = await resultLabels(page);
  expect(labels.sort(), "query returns exactly the saved domains matching 'acme'")
    .toEqual(["login.acme-pay.example", "pay-acme.example"]);
  const resultText = (await page.locator("#cmdk-results").innerText()).toLowerCase();
  expect(resultText, "result rows carry the entity type from the DB").toContain("domain");

  await page.screenshot({ path: "test-results/verify-cmdk-results.png", fullPage: true });

  // a second query proves type/value search over the DB (the ip, which 'acme' did not match)
  await page.fill("#cmdk-input", "");
  await page.keyboard.type("93.184");
  await page.waitForSelector("#cmdk-results .cmdk-result", { timeout: 5_000 });
  expect((await resultLabels(page))).toEqual(["93.184.216.34"]);

  // (4) D4: a result click navigates to /entities AND focuses (EXPANDS) the chosen row — not just
  // "the label is somewhere on a page that lists every entity".
  await page.fill("#cmdk-input", "");
  await page.keyboard.type("login.acme-pay");
  await page.waitForSelector("#cmdk-results .cmdk-result", { timeout: 5_000 });
  await page.locator("#cmdk-results .cmdk-result").first().click();
  await expect.poll(() => page.evaluate(() => location.hash), { timeout: 5_000 }).toBe("#/entities");
  const chosenRow = page.locator(".ent-row", { hasText: "login.acme-pay.example" });
  await expect(chosenRow.locator(".ent-detail"), "the clicked entity row is expanded (focused), not just present")
    .toBeVisible({ timeout: 10_000 });

  await page.screenshot({ path: "test-results/verify-cmdk-focused-entity.png", fullPage: true });
});
