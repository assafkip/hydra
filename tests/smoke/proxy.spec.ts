import { test, expect, type Page } from "@playwright/test";
// free/pro split smoke (founder 2026-07-08): the CORS-blocked / server-side providers are NOT browser-native,
// so they moved to the paid tool. The free Hydra app shows them as a LOCKED "Pro" upsell teaser — no worker
// setup, no run. This proves the free tool only exposes the add-a-key direct providers, and the pro tier is
// a visible nudge. (The proxy CODE is retained + unit-tested in tests/osint/proxy.test.ts — it's the pro
// tool's foundation, just not reachable from the free UI.)

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

test("free/pro split: CORS-blocked providers show as a locked Pro teaser (no worker setup in the free tool); zero egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);
  await page.click('a[data-route="/enrich"]');

  // (1) the Pro-providers teaser section renders, listing the blocked providers as locked "Pro".
  await expect(page.getByText("Pro providers")).toBeVisible();
  await expect(page.locator(".enr-blocked", { hasText: "VirusTotal" })).toContainText("Pro");
  await expect(page.locator(".enr-blocked", { hasText: "Exa" })).toContainText("Pro");

  // (2) the worker setup is GONE from the free tool: no URL input, no Save, no Test connection, no proxy run.
  await expect(page.locator('input[placeholder="https://<name>.workers.dev"]')).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Save worker URL" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Test connection" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Enrich via proxy" })).toHaveCount(0);

  // (3) a static teaser makes ZERO external requests.
  expect(external, `unexpected external egress: ${external.join(", ")}`).toHaveLength(0);

  await page.screenshot({ path: "test-results/kipi-pro-teaser.png", fullPage: true });
});
