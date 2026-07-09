import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// Phase-2 UI parity capture + render smoke. Seeds a vault + key + one scripted run, then
// for each surface ASSERTS it renders real content (post-audit issue 2: the old version
// swallowed every wait with an empty catch handler and had zero expect() — a blank render
// passed green, the exact "gate measuring nothing" scar) AND screenshots it for diffing against
// the original Flask templates (investigations/webapp/templates/*). Run on demand:
//   npx playwright test tests/smoke/parity-shots.spec.ts
// Screenshots land in test-results/parity-*.png.

const KEY = "sk-ant-PARITY-secret-77";

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
      { type: "text", text: "Checking certificate transparency for sibling hosts." },
      { type: "tool_use", id: "t2", name: "crtsh_subdomains", input: { domain: "acme-pay.example" } },
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

async function shoot(page: Page, name: string) {
  await page.screenshot({ path: `test-results/parity-${name}.png`, fullPage: true });
}

test.use({ viewport: { width: 1440, height: 900 } });

test("every surface renders real content + capture for parity diffing", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());

  // 1) the auth/create-vault screen (kipi-web only; no original counterpart). reset() re-renders the
  // auth host — wait for it instead of a reload (the old reload raced createVault's re-render, so
  // #apikey never appeared and the run died at the fill — post-audit issue 2).
  await page.waitForSelector("#auth-host", { timeout: 10_000 });
  await shoot(page, "00-auth");

  // unlock + key + a seeded run so the data surfaces have content. #apikey lives on /account now (the
  // home setup strip was removed when auth moved to Supabase + /account) — navigate there to save the
  // key. (This is why the pre-gate-set smokes rotted: they filled #apikey on home — post-audit issue 2.)
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account");
  await page.waitForSelector("#apikey", { timeout: 15_000 });
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");

  // back to home (chat + graph) before the scripted run — runScriptedInvestigation writes into the
  // chat/graph DOM that only exists on "/".
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await page.evaluate(
    ([turns]) => (window as any).__kipi.runScriptedInvestigation("investigate acme-pay.example", turns),
    [RUN_TURNS] as const,
  );
  await page.waitForTimeout(800);

  // 2) home = graph + chat dock
  await page.waitForTimeout(1200); // let the graph settle / grow
  await shoot(page, "01-home-graph");

  const routes: Array<[string, string]> = [
    ["/reports", "02-reports"],
    ["/runs", "03-runs"],
    ["/enrich", "04-enrich"],
    ["/entities", "05-entities"],
    ["/clusters", "06-clusters"],
    ["/deliverables", "07-deliverables"],
    ["/inbox", "08-inbox"],
    ["/cross-case", "09-cross-case"],
    ["/cross-domain", "10-cross-domain"],
  ];
  for (const [route, name] of routes) {
    // gotoRoute (not a raw click): /entities, /clusters, /deliverables, /inbox, /cross-case,
    // /cross-domain live in collapsed sidebar sections (menu-collapse 2026-06-20) — gotoRoute
    // expands the owning section first; it's a no-op for the always-visible core-loop links.
    await gotoRoute(page, route);
    // post-audit issue 2: a REAL assertion (was a swallowed empty catch) — every standard page
    // must render its .pg-title, so a blank surface now FAILS the smoke instead of passing green.
    await expect(
      page.locator(".pg-title").first(),
      `${route} should render a .pg-title`,
    ).toBeVisible({ timeout: 10_000 });
    await page.waitForTimeout(400);
    await shoot(page, name);
  }

  // 3) entities expanded (dossier open) — assert there IS an entity, then open it
  await gotoRoute(page, "/entities");
  await expect(
    page.locator(".ent-top").first(),
    "/entities should render at least one entity from the seeded run",
  ).toBeVisible({ timeout: 10_000 });
  await page.locator(".ent-top").first().click();
  await page.waitForTimeout(500);
  await shoot(page, "11-entities-expanded");
});
