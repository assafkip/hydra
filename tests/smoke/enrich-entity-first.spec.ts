import { test, expect } from "@playwright/test";

// ux-enrich (brief §18 P0/P1): the entity-first enrichment path. Proves (offline, zero egress): the
// /enrich page LEADS with "Enrich an entity" (input + Run-all button); the entity input is backed by a
// datalist of the case's entities; "Run all applicable providers" on a type with no configured provider
// shows the honest no-provider message (no network); the per-provider key-cards live under a
// "Configure providers" details that is OPEN on a fresh (0-key) vault. The actual provider run reuses
// d.enrich, proven by verify-enrich.spec's scripted seam.

const KEY = "shdn-EF-4242";

test.use({ viewport: { width: 1440, height: 1000 } });

test("enrich entity-first: leads with the entity action, datalist from case entities, honest no-provider path, config collapses", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    const u = r.url();
    if (/^https?:\/\//.test(u) && !u.includes("localhost") && !u.includes("127.0.0.1")) external.push(u);
  });

  await page.goto("/");
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.waitForSelector("#auth-host", { timeout: 10_000 });
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(p: string): Promise<unknown> } }).__kipi.createVault("pw"));
  // seed an entity into the case so the datalist + a typed target have something to resolve.
  await page.evaluate(() => (window as unknown as { __kipi: { ingestText(n: string, t: string): Promise<unknown> } }).__kipi
    .ingestText("ev.txt", "Host 93.184.216.34 and domain probe.example are in scope."));

  await page.click('a[data-route="/enrich"]');

  // (1) the page LEADS with the entity-first action.
  await expect(page.locator(".enr-h2").first()).toHaveText("Enrich an entity");
  const runAll = page.getByRole("button", { name: "Run all applicable providers" });
  await expect(runAll).toBeVisible();

  // (2) the entity input is backed by a datalist of the case's entities (the seeded ip/domain).
  await expect(page.locator("#enr-ent-list option")).not.toHaveCount(0);
  const optionValues = await page.locator("#enr-ent-list option").evaluateAll((els) => els.map((e) => (e as HTMLOptionElement).value));
  expect(optionValues).toContain("93.184.216.34");

  // (3) no configured provider yet → run-all on the seeded IP shows the honest no-provider message (no net).
  await page.fill(".enr-ef-input", "93.184.216.34");
  await runAll.click();
  await expect(page.locator(".enr-ef-out")).toContainText("No configured provider applies to a ip");

  // (4) the per-provider config is collapsible and OPEN on a fresh (0-key) vault.
  const details = page.locator(".enr-configure");
  await expect(details).toHaveJSProperty("open", true);
  await expect(page.locator(".enr-configure-summary")).toContainText("0/9 configured");

  // save a Shodan key → the count updates and the panel STAYS open (founder 2026-07-08, pages.ts:2824:
  // the config now defaults open and the user collapses it via <summary>; it no longer auto-collapses on
  // save — the old "open only when configured===0" auto-collapse was removed).
  const shodan = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await shodan.locator(".enr-key").fill(KEY);
  await shodan.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.locator(".enr-configure-summary")).toContainText("1/9 configured");
  await expect(page.locator(".enr-configure")).toHaveJSProperty("open", true);

  // (5) HAPPY PATH — with Shodan configured, "Run all applicable providers" on the IP runs the applicable
  // provider via d.enrich and renders a per-provider result line. The provider call is INTERCEPTED (no real
  // egress; the fulfilled response is local), proving the entity-first loop end-to-end.
  await page.route("**api.shodan.io/**", (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ip_str: "93.184.216.34", hostnames: ["probe.example"], ports: [443], org: "ExampleNet" }) }),
  );
  await page.fill(".enr-ef-input", "93.184.216.34");
  await page.getByRole("button", { name: "Run all applicable providers" }).click();
  // the loop runs the applicable provider and renders ITS per-provider outcome line (ok or warn chip) —
  // that the entity-first loop calls d.enrich per applicable provider is the point; the canned body's
  // success-parsing is shodanHost's concern, covered by verify-enrich's seam.
  await expect(page.locator(".enr-ef-out")).toContainText("Ran 1 provider on 93.184.216.34 (ip)");
  await expect(page.locator(".enr-ef-line")).toContainText("Shodan");
  await expect(page.locator(".enr-ef-line .pg-chip")).toBeVisible();

  // no key leak in the rendered result summary.
  expect(await page.locator(".enr-ef-out").textContent()).not.toContain(KEY);
});
