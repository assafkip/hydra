import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-reports + sf-report-detail smoke (the RENDER GATE): ingest reports, then /reports renders the
// reports TABLE (Title/Type/Investigation/Entities/Ingested, newest-first) and a row expands INLINE to
// the per-report detail (entities + notes editor). Offline, zero egress, no key leak.

const APIKEY = "sk-ant-REPORTS-smoke-3131";
const DOC_ALPHA = "Alpha report: alpha-evil.example.com and alpha-bad.example.org are connected infrastructure.";
const DOC_BETA = "Beta report: beta-drainer.example.com resolves alongside beta-front.example.org.";

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

test("reports: /reports renders the reports table newest-first + an inline per-report detail; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // key (for a meaningful no-leak assertion), then ingest two reports (alpha first, beta second → beta newest).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.evaluate((t) => (window as unknown as { __kipi: { ingestText(n: string, x: string): Promise<unknown> } }).__kipi.ingestText("alpha-report", t), DOC_ALPHA);
  await page.evaluate((t) => (window as unknown as { __kipi: { ingestText(n: string, x: string): Promise<unknown> } }).__kipi.ingestText("beta-report", t), DOC_BETA);

  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash

  // (1) the table header + both reports.
  await expect(page.locator(".rep-table-head")).toContainText("Reports · 2");
  await expect(page.locator(".rep-row-head")).toContainText("Title");
  await expect(page.locator(".rep-row-head")).toContainText("Ingested");
  await expect(page.locator(".rep-table")).toContainText("alpha-report");
  await expect(page.locator(".rep-table")).toContainText("beta-report");

  // (2) newest-first: beta (ingested second) is the FIRST data row.
  const firstDataTitle = page.locator(".rep-item .rep-row .rep-title").first();
  await expect(firstDataTitle).toContainText("beta-report");

  // (3) the source-type pill renders in the Type column.
  await expect(page.locator(".rep-row .role-pill.role-source").first()).toBeVisible();

  // (4) INLINE EXPAND: click the first report row → the detail renders (entities + notes editor).
  await page.locator(".rep-item .rep-row").first().click();
  const detail = page.locator(".rep-item").first().locator(".rep-detail");
  await expect(detail).toBeVisible();
  await expect(detail.locator(".run-section-head", { hasText: "Entities in this report" })).toBeVisible();
  await expect(detail.locator(".rep-ent").first()).toContainText("beta-drainer.example.com");
  await expect(detail.locator("textarea.rep-notes")).toBeVisible();

  await page.screenshot({ path: "test-results/kipi-reports.png", fullPage: true });

  // (5) the notes editor autosaves through the single-writer (type → saved).
  await detail.locator("textarea.rep-notes").fill("analyst note: beta is the live front");
  await expect(detail.locator(".rep-notes-status")).toContainText(/saved|saving/);

  // (6) no key in the page body; no off-allowlist egress.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
