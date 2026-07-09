import { test, expect } from "@playwright/test";
import { gotoRoute } from "./_nav";

// ux-rowmenu (item 4): the per-row entity ⋯ actions menu on /entities. Proves: each row has a ⋯ menu
// with Open in graph / Enrich / Override role; Override role expands the row + reveals its override form;
// Enrich navigates to /enrich with the entity prefilled in the entity-first input; Open in graph
// navigates home to the graph; the menu dismisses on outside-click. Offline scripted run, no network.

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
          "{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}" +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 14 },
  },
];

test.use({ viewport: { width: 1440, height: 1000 } });

test("entity row ⋯ menu: Open in graph / Enrich / Override role + outside-click dismiss", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.waitForSelector("#auth-host", { timeout: 10_000 });
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(p: string): Promise<unknown> } }).__kipi.createVault("pw"));
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await page.evaluate(
    ([turns]) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi
      .runScriptedInvestigation("investigate acme-pay.example", turns),
    [RUN_TURNS] as const,
  );

  await gotoRoute(page, "/entities");
  // the IP finding row carries the ⋯ menu.
  const row = page.locator(".ent-row", { hasText: "93.184.216.34" }).first();
  await expect(row).toBeVisible();
  const menuBtn = row.locator(".ent-menu-btn");
  await expect(menuBtn).toBeVisible();

  // (1) the menu opens with the 3 actions.
  await menuBtn.click();
  const pop = row.locator(".ent-menu-pop");
  await expect(pop).toBeVisible();
  await expect(pop.locator(".ent-menu-item")).toHaveText(["Open in graph", "Enrich", "Override role"]);

  // (2) Override role expands the row + reveals the override form.
  await pop.getByText("Override role", { exact: true }).click();
  await expect(row.locator(".ent-assert")).toBeVisible();

  // (3) Enrich navigates to /enrich with the entity prefilled in the entity-first input.
  await row.locator(".ent-menu-btn").click();
  await row.locator(".ent-menu-pop").getByText("Enrich", { exact: true }).click();
  await expect(page).toHaveURL(/#\/enrich$/);
  await expect(page.locator(".enr-ef-input")).toHaveValue("93.184.216.34");

  // (4) Open in graph navigates home to the graph.
  await gotoRoute(page, "/entities");
  const row2 = page.locator(".ent-row", { hasText: "93.184.216.34" }).first();
  await row2.locator(".ent-menu-btn").click();
  await row2.locator(".ent-menu-pop").getByText("Open in graph", { exact: true }).click();
  await expect(page).toHaveURL(/#\/$|\/$/);
  await page.waitForSelector("#cy", { timeout: 15_000 });

  // (5) outside-click dismisses the menu.
  await gotoRoute(page, "/entities");
  const row3 = page.locator(".ent-row", { hasText: "93.184.216.34" }).first();
  await row3.locator(".ent-menu-btn").click();
  await expect(row3.locator(".ent-menu-pop")).toBeVisible();
  await page.locator(".pg-title").click(); // an outside click
  await expect(row3.locator(".ent-menu-pop")).toBeHidden();
});
