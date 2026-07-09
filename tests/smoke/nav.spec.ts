import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// Nav proof (clu-workspace-nav): the sidebar is collapsed to EXACTLY Workspace + Enrich + Account.
// Those three click-route + highlight; every OTHER route still RESOLVES via hash (the unchanged ROUTES
// set) and renders its real page — never a dead href / 404 (the built-not-wired scar). No egress.

const KEY = "sk-ant-NAV-secret-31";

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving echo.example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "echo.example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          'Done.\n```json\n{"findings":[' +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"co.example.com","entity_type":"domain","confidence":"low"}' +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
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

let external: string[] = [];
async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
}

test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await freshKeyedVault(page);
});

// auth-gate-nav (founder 2026-06-25, live on phone): a BRAND-NEW user has no case yet (createVault {cases:false}
// = the real signup landing). The keys are GLOBAL (shared across cases), but the no-case gate forced EVERY route
// back to the Cases page, so every left-nav tap bounced ("the buttons on the left I can't press them") and the
// keys were unreachable. The bug never showed in tests because __kipi.createVault seeds a "Test case" by default.
test("a new user with NO case can still reach + use the global key pages (API + OSINT)", async ({ page }) => {
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw", { cases: false })); // the real no-case landing
  await expect(page.locator(".pg-title")).toHaveText("Cases"); // lands on create-first-case (no implicit default)

  // tapping API navigates to the keys page — it must RENDER, not bounce back to Cases:
  await page.evaluate(() => { location.hash = "#/account"; });
  await expect(page.locator("#apikey")).toBeVisible();
  // and the GLOBAL Anthropic key SAVES with no case (it lives on the raw vault):
  await page.fill("#apikey", "sk-ant-nocase-7788");
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");

  // the OSINT keys page is reachable too (its provider key inputs render):
  await page.evaluate(() => { location.hash = "#/enrich"; });
  await expect(page.locator('input[placeholder="Shodan API key"]')).toBeVisible();
  expect(external).toEqual([]);
});

test("the sidebar is collapsed to Workspace + Enrich + Account; off-nav routes still resolve to real pages", async ({ page }) => {
  // clu-workspace-nav: the sidebar holds EXACTLY the three workspace links.
  await expect(page.locator("aside a[data-route]")).toHaveCount(3);
  await expect(page.locator('aside a[data-route="/"]')).toHaveText("Chat + graph");
  await expect(page.locator('aside a[data-route="/enrich"]')).toBeVisible();
  await expect(page.locator('aside a[data-route="/account"]')).toBeVisible();

  // seed one run so the off-nav data pages have content
  await page.evaluate(([turns]) => (window as any).__kipi.runScriptedInvestigation("investigate echo.example.com", turns), [RUN_TURNS] as const);

  // The three sidebar links click-route + highlight.
  await page.click('a[data-route="/enrich"]');
  await expect(page.locator(".pg-title")).toHaveText("OSINT enrichment");
  await expect(page.locator(".enr-card", { hasText: "Shodan" }).first()).toBeVisible();
  await expect(page.locator('a[data-route="/enrich"]')).toHaveClass(/nav-active/);

  await page.click('a[data-route="/"]');
  await expect(page.locator("#cy")).toBeVisible();
  await expect(page.locator('a[data-route="/"]')).toHaveClass(/nav-active/);

  // Off-nav routes STILL RESOLVE via hash (no 404) and render their real pages — gotoRoute hash-navigates
  // any route not in the sidebar.
  await gotoRoute(page, "/entities");
  await expect(page.locator(".pg-title")).toHaveText("Entities");
  await expect(page.locator(".ent-row")).toHaveCount(2);
  await expect(page.locator(".pg-body")).toContainText("93.184.216.34");

  await gotoRoute(page, "/runs");
  await expect(page.locator(".pg-title")).toHaveText("Runs & findings");
  await expect(page.locator(".run-card")).toContainText("echo.example.com");

  await gotoRoute(page, "/reports");
  await expect(page.locator(".pg-title")).toHaveText("Reports & intake");
  await expect(page.locator(".intake-paste")).toBeVisible();

  await gotoRoute(page, "/deliverables");
  await expect(page.locator(".pg-title")).toHaveText("Deliverables");

  await gotoRoute(page, "/cross-domain");
  await expect(page.locator(".pg-title")).toHaveText("Cross-type");

  // Back to the workspace: the cytoscape graph surface is mounted again.
  await page.click('a[data-route="/"]');
  await expect(page.locator("#cy")).toBeVisible();

  // no off-allowlist egress across all the navigation
  expect(external).toEqual([]);
});
