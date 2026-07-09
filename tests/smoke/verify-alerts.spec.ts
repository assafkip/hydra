import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-alerts smoke (the live proof): with a grade-A entity + a cross-run entity in the vault, /alerts renders
// the HIGH (watchlist) + MEDIUM (cross-run) severity tiers with alert_type labels; Acknowledge hides an alert,
// Show-acknowledged reveals it, Acknowledge-all clears the open list. Offline, zero egress, no key leak.

const APIKEY = "sk-ant-ALERTS-smoke-7272";

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.hostname === "t0.gstatic.com" && u.pathname === "/faviconV2") return false;
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

test("alerts: HIGH/MEDIUM tiers render; acknowledge hides + show-acknowledged reveals; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");

  // seed two runs (run: is not a protected key): acme.io grade A → HIGH; evil.com promoted across 2 runs → MEDIUM.
  await page.evaluate(() => {
    const k = (window as unknown as { __kipi: { putCase(key: string, v: unknown): Promise<unknown> } }).__kipi;
    return Promise.all([
      k.putCase("run:r1", { objective: "r1", steps: [], promoted: [
        { entity: "acme.io", entity_type: "domain", grade: "A", source_count: 3, infra_source_count: 3 },
        { entity: "evil.com", entity_type: "domain", grade: "B", source_count: 2, infra_source_count: 1 },
      ], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" }),
      k.putCase("run:r2", { objective: "r2", steps: [], promoted: [
        { entity: "evil.com", entity_type: "domain", grade: "B", source_count: 2, infra_source_count: 1 },
      ], leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" }),
    ]);
  });

  // /alerts shows both tiers.
  await gotoRoute(page, "/alerts");
  await expect(page.locator(".pg-title")).toHaveText("Alerts");
  const high = page.locator(".alert-card.sev-high", { hasText: "acme.io" });
  const medium = page.locator(".alert-card.sev-medium", { hasText: "evil.com" });
  await expect(high).toBeVisible();
  await expect(high.locator(".alert-sev")).toHaveText("HIGH");
  await expect(high.locator(".alert-type")).toHaveText("watchlist");
  await expect(medium).toBeVisible();
  await expect(medium.locator(".alert-type")).toHaveText("cross-run");
  await page.screenshot({ path: "test-results/kipi-alerts.png", fullPage: true });

  // Acknowledge the HIGH alert → it leaves the open list (default hides acked).
  await high.getByRole("button", { name: "Acknowledge" }).click();
  await expect(page.locator(".alert-card.sev-high", { hasText: "acme.io" })).toHaveCount(0);
  await expect(page.locator(".alert-count")).toContainText("1 acknowledged");

  // Show acknowledged → it reappears with the ✓ acknowledged badge.
  await page.getByText("Show acknowledged").click();
  await expect(page.locator(".alert-card.acked", { hasText: "acme.io" })).toBeVisible();
  await expect(page.locator(".alert-acked").first()).toContainText("acknowledged");

  // Acknowledge all → no open alerts remain (toggle off → empty open list copy).
  await page.getByText("Show acknowledged").click(); // hide acked again
  await page.getByRole("button", { name: "Acknowledge all" }).click();
  await expect(page.locator(".alert-count")).toContainText("0 open");

  // no key leak, no egress.
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
