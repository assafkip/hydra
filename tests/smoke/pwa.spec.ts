import { test, expect, type Page } from "@playwright/test";

// rel-pwa smoke (PROD build): the app is an installable PWA. The manifest is linked + parses with the
// 192/512 icons; the network-first service worker registers, activates, and controls the page; the app
// still renders the graph after SW activation; and the SW adds ZERO off-allowlist egress (it only
// touches same-origin assets). The page must NOT spuriously reload on the first SW claim.

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

async function freshVault(page: Page) {
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}

test("PWA: manifest linked + parses, SW registers + controls the page, app renders, no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);

  // (1) the manifest is linked and parses with the required icons
  const manifestHref = await page.getAttribute('link[rel="manifest"]', "href");
  expect(manifestHref).toBe("/manifest.webmanifest");
  await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute("content", "#0F766E");
  const manifest = await page.evaluate(async (href) => {
    const res = await fetch(href!);
    return res.json();
  }, manifestHref);
  expect(manifest.name).toBe("Hydra"); // product renamed kipi->Hydra 2026-06-18; manifest is the live app name
  expect(manifest.display).toBe("standalone");
  const sizes = manifest.icons.map((i: { sizes: string }) => i.sizes).sort();
  expect(sizes).toEqual(["192x192", "512x512"]);

  // (2) the service worker registers, activates, and takes control of THIS page (clients.claim)
  await page.waitForFunction(async () => {
    const reg = await navigator.serviceWorker.getRegistration();
    return !!reg && !!reg.active;
  }, null, { timeout: 15000 });
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null, null, { timeout: 15000 });

  // (3) the app still works after the SW is in control (the page did not spuriously reload away)
  await freshVault(page);
  await page.waitForFunction(() => document.querySelector("#cy") !== null);
  await expect(page.locator("#cy")).toBeVisible();

  // (4) no off-allowlist egress — the SW only ever touched same-origin assets
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-pwa.png", fullPage: true });
});
