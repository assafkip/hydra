import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-cases smoke (the live proof, the FINAL row): one vault, multiple cases. Seed an entity in the default
// case; create + switch to a 2nd case → its /entities is EMPTY (no bleed); seed a different entity there;
// switch back → the default entity is back and the 2nd case's is gone. The chip tracks the active case. The
// API key (a per-user secret) stays configured across the switch. Offline, zero egress, no key leak.

const APIKEY = "sk-ant-CASES-smoke-9090";

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

function seedRun(page: Page, objective: string, entity: string) {
  return page.evaluate(({ objective, entity }) =>
    (window as unknown as { __kipi: { putCase(k: string, v: unknown): Promise<unknown> } }).__kipi.putCase(`run:${objective}`, {
      objective, steps: [],
      promoted: [{ entity, entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    }), { objective, entity });
}

test("cases: a 2nd case is isolated from the default; switching changes the content; key stays; no leak/egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key (per-user secret) + seed acme.io in the STARTER case (the provisioned test vault's first case).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await seedRun(page, "investigate acme.io", "acme.io");
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-name", { hasText: "acme.io" })).toBeVisible();
  await expect(page.locator("#case-chip")).toHaveText("Test case");

  // (2) create a 2nd case via /cases — it becomes active. The chip updates.
  await gotoRoute(page, "/cases");
  await expect(page.locator(".pg-title")).toHaveText("Cases");
  await page.locator(".case-name-input").fill("Acme breach");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Acme breach", { timeout: 10_000 });

  // (3) the new case is EMPTY — the default's acme.io does NOT bleed in.
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-name", { hasText: "acme.io" })).toHaveCount(0);

  // (4) seed a DIFFERENT entity in the 2nd case (putCase lands in the active case).
  await seedRun(page, "investigate evil.com", "evil.com");
  await gotoRoute(page, "/cases"); // bounce off /entities to force a fresh render
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-name", { hasText: "evil.com" })).toBeVisible();
  await expect(page.locator(".ent-name", { hasText: "acme.io" })).toHaveCount(0);
  await page.screenshot({ path: "test-results/kipi-cases-entities-b.png", fullPage: true });

  // (5) switch BACK to the starter case — acme.io is back, evil.com is gone.
  await gotoRoute(page, "/cases");
  await expect(page.locator(".case-row", { hasText: "Test case" })).toBeVisible();
  await page.locator(".case-row", { hasText: "Test case" }).getByRole("button", { name: "Switch to" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Test case", { timeout: 10_000 });
  await page.screenshot({ path: "test-results/kipi-cases.png", fullPage: true });
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-name", { hasText: "acme.io" })).toBeVisible();
  await expect(page.locator(".ent-name", { hasText: "evil.com" })).toHaveCount(0);

  // (6) the API key (a per-user secret) survived the case switches — still configured.
  await gotoRoute(page, "/account");
  await expect(page.locator("#keychip")).toContainText("configured");

  // (7) no key leak, no off-allowlist egress.
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});

// sf-cases delete (the live proof): the Delete button removes a case + all its data. Covers the founder UX
// choice — deleting the ACTIVE case auto-switches to ANOTHER case (no implicit default), so the running view
// never points at a deleted case. The confirm() dialog is auto-accepted. The other case's data stays intact;
// no key leak, no egress.
test("cases: Delete removes the active case (auto-switch to the other case) + its data; sibling intact; no leak/egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });
  page.on("dialog", (d) => d.accept()); // the delete confirm()

  await freshVault(page);
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");

  // seed the STARTER case ("Test case"), then create + switch to "Throwaway" (it becomes active) and seed it.
  await seedRun(page, "investigate keep.io", "keep.io");
  await gotoRoute(page, "/cases");
  await page.locator(".case-name-input").fill("Throwaway");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Throwaway", { timeout: 10_000 });
  await seedRun(page, "investigate gone.com", "gone.com");

  // every case has a Delete now (no implicit default is special). Delete the ACTIVE "Throwaway".
  await gotoRoute(page, "/cases");
  await expect(page.locator(".case-count")).toHaveText("2 case(s)");
  await page.locator(".case-row", { hasText: "Throwaway" }).getByRole("button", { name: "Delete" }).click();

  // auto-switched to the sibling "Test case"; the deleted case is gone; count back to 1.
  await expect(page.locator("#case-chip")).toHaveText("Test case", { timeout: 10_000 });
  await expect(page.locator(".case-count")).toHaveText("1 case(s)");
  await expect(page.locator(".case-row", { hasText: "Throwaway" })).toHaveCount(0);
  await page.screenshot({ path: "test-results/kipi-cases-deleted.png", fullPage: true });

  // the sibling case's data is intact; the deleted case's data is gone (no orphan).
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-name", { hasText: "keep.io" })).toBeVisible();
  await expect(page.locator(".ent-name", { hasText: "gone.com" })).toHaveCount(0);

  // the API key survived; no leak, no off-allowlist egress.
  await gotoRoute(page, "/account");
  await expect(page.locator("#keychip")).toContainText("configured");
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});

// sf-cases: the REAL new-user flow — a vault with NO starter case ({ cases: false }) lands on the
// create-first-case empty state (NOT the login screen, NOT a graph). Creating the first case enters the app.
test("cases: a fresh vault (no case) shows create-first-case, and creating one enters the app", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw", { cases: false }));

  // unlocked but caseless → the Cases page (create-first-case); chip reads "No case"; zero cases.
  await expect(page.locator(".pg-title")).toHaveText("Cases");
  await expect(page.locator("#case-chip")).toHaveText("No case");
  await expect(page.locator(".case-count")).toContainText("No cases yet");

  // create the first case → it becomes active, the chip follows, and the home graph is reachable.
  await page.locator(".case-name-input").fill("First case");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("First case", { timeout: 10_000 });
  await page.click('a[data-route="/"]');
  await expect(page.locator("#graph")).toBeVisible();
});
