import { test, expect, type Page } from "@playwright/test";

// Capabilities catalog verification (the read-only "what Hydra can do" surface, /capabilities).
// Proves the BUILD reaches the page: a title + the grouped OSINT toolkit (39 backend adapters + the
// Apify social layer + the search tier), each row badged Free / Add key / Agent. Live, not a code read
// (verification-loops rule). Offline-safe: it is a static manifest — zero egress is asserted.

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

async function freshVault(page: Page): Promise<void> {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}

test.use({ viewport: { width: 1440, height: 1200 } });

test("capabilities page: grouped OSINT catalog with access badges, reachable from the sidebar, zero egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  await freshVault(page);

  // (1) Reachable from the Enrich page's "capability catalog" link (founder 2026-07-08: out of the 3-link
  // sidebar, reachable in-context from OSINT/Enrich).
  await page.click('a[data-route="/enrich"]');
  await page.click('a.enr-cap-link[data-route="/capabilities"]');
  await expect(page.locator(".pg-title")).toHaveText("OSINT capabilities");
  await expect(page.locator(".pg-sub")).toContainText("capabilities across the toolkit");

  // (2) The three-badge legend renders.
  await expect(page.locator(".cap-legend")).toBeVisible();

  // (2b) The free/pro promise is stated up top: free tool is BYO-key for browser-native providers; Pro rows
  // live in the paid tool (founder 2026-07-08 free/pro split).
  await expect(page.locator(".cap-byo")).toContainText("free browser tool is bring-your-own-key");
  await expect(page.locator(".cap-byo")).toContainText("Pro");

  // (2c) The token dependency is VISIBLE inline, not just a tooltip. An in-app "key" capability reads
  // "needs your <TOKEN>" (Exa — added in the app's vault). An "agent" capability's token is set where the
  // agent RUNS (backend / CLI) — hydra has no field for it — so it must NOT imply an in-app box
  // (hydra-osint-provider-inputs 2026-07-08: Apify + Bright Data were the dishonest rows).
  // free/pro split: a FREE-tool key provider (Shodan) reads "needs your <TOKEN>" (add it in the app); a PRO
  // provider (Exa, Apify, Bright Data) reads "<TOKEN> (in the pro tool)" — not an in-app field.
  await expect(page.getByText("needs your SHODAN_API_KEY").first()).toBeVisible();
  await expect(page.getByText("EXA_API_KEY (in the pro tool)").first()).toBeVisible();
  await expect(page.getByText("APIFY_TOKEN (in the pro tool)").first()).toBeVisible();
  await expect(page.getByText("BRIGHTDATA_MCP_URL (in the pro tool)").first()).toBeVisible();
  // The old phrasings that implied an in-app field for a pro/backend token are GONE.
  await expect(page.getByText("needs your APIFY_TOKEN")).toHaveCount(0);
  await expect(page.getByText("needs your EXA_API_KEY")).toHaveCount(0);

  // (3) Multiple capability GROUPS render (infra, blockchain, social, search, ...).
  const groups = page.locator(".cap-group");
  expect(await groups.count()).toBeGreaterThanOrEqual(6);

  // (4) The groups the live app previously HID are now named — the whole point of the page.
  await expect(page.locator(".cap-group-title", { hasText: "Social media scraping" })).toBeVisible();
  await expect(page.locator(".cap-group-title", { hasText: "Blockchain" })).toBeVisible();
  await expect(page.getByText("Instagram (12 actors)")).toBeVisible();
  await expect(page.getByText("crt.sh certificate transparency")).toBeVisible();

  // (5) Rows carry the access badge (Free / Add key / Agent).
  await expect(page.locator(".cap-row .pg-chip").first()).toBeVisible();
  await expect(page.locator(".cap-list").first().getByText("Free").first()).toBeVisible();

  // (6) A static manifest must make ZERO external requests.
  expect(external, `unexpected external egress: ${external.join(", ")}`).toHaveLength(0);
});
