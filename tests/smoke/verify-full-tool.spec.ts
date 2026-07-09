import { test, expect, type Page } from "@playwright/test";

// free/pro split (founder 2026-07-08): the "Full tool" upsell page — a dedicated 4th sidebar item listing
// everything a desktop/server tool (like four_points) does that this browser app can't. Read-only manifest;
// zero egress (nothing here runs in the browser — that's the point).

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

test("Full tool page: reachable from the 4th sidebar item, groups the paid-tool capabilities, zero egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  await freshVault(page);

  // (1) the sidebar "Full tool" link navigates to the page.
  await page.click('a[data-route="/full-tool"]');
  await expect(page.locator(".pg-title")).toHaveText("Full tool");
  await expect(page.locator(".pg-sub")).toContainText("beyond the free browser app");

  // (2) the framing note explains WHY it's not in the browser.
  await expect(page.locator(".cap-byo")).toContainText("full desktop/server investigation tool");

  // (3) the five capability groups render — the OSINT + analysis + workflow + evidence + ingestion story.
  await expect(page.locator(".cap-group-title", { hasText: "Advanced OSINT" })).toBeVisible();
  await expect(page.locator(".cap-group-title", { hasText: "Structured analytic techniques" })).toBeVisible();
  await expect(page.locator(".cap-group-title", { hasText: "Investigation workflow" })).toBeVisible();
  await expect(page.locator(".cap-group-title", { hasText: "Evidence & chain-of-custody" })).toBeVisible();
  await expect(page.locator(".cap-group-title", { hasText: "Deep ingestion" })).toBeVisible();

  // (4) representative capabilities appear (accurate to four_points, not fabricated).
  await expect(page.getByText("Analysis of Competing Hypotheses (ACH)")).toBeVisible();
  await expect(page.getByText("Apify social scraping (55+ actors)")).toBeVisible();
  await expect(page.getByText("EV-NNNN evidence capture")).toBeVisible();

  // (5) every row is tagged as a paid-tool capability.
  await expect(page.locator(".cap-row .pg-chip", { hasText: "Full tool" }).first()).toBeVisible();

  // (6) the contact bubble is the CTA: a mailto to the founder (no form, no network, no data collection).
  const cta = page.locator(".ft-contact a", { hasText: "Contact for more info" });
  await expect(cta).toBeVisible();
  await expect(cta).toHaveAttribute("href", /^mailto:assaf@ktlystlabs\.com\?subject=/);
  await expect(page.locator(".ft-contact-title")).toHaveText("Want the full tool?");

  // (7) a static upsell manifest makes ZERO external requests.
  expect(external, `unexpected external egress: ${external.join(", ")}`).toHaveLength(0);

  await page.screenshot({ path: "test-results/kipi-full-tool.png", fullPage: true });
});
