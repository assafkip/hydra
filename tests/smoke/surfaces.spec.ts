import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// rb-ui smoke (the live proof): /alerts lists a grade-A entity; an /inbox doc drills into its entities +
// a notes editor whose note persists across a re-render; an XSS note renders literal; the report: namespace
// is not raw-readable via __kipi; no key leak; no egress.

const APIKEY = "sk-ant-RB-smoke-1212";
const NOTE = "follow up <img src=x onerror=alert(1)>"; // a note with markup — must stay literal text

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

test("alerts list a grade-A entity; report notes persist + render literal; report: is hook-protected; no leak", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  // seed a grade-A entity (a run record) + ingest a document
  await page.evaluate(() =>
    (window as unknown as { __kipi: { putCase(k: string, v: unknown): Promise<unknown> } }).__kipi.putCase("run:seed", {
      objective: "seed",
      steps: [],
      promoted: [{ entity: "alpha.example.com", entity_type: "domain", grade: "A", source_count: 2, infra_source_count: 2 }],
      leads: [],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    }),
  );
  await page.evaluate(() => (window as unknown as { __kipi: { ingestText(n: string, t: string): Promise<unknown> } }).__kipi.ingestText("mydoc", "contact evil@example.com and 1.2.3.4"));

  // /alerts lists the grade-A entity
  await gotoRoute(page, "/alerts");
  await expect(page.locator(".pg-title")).toHaveText("Alerts");
  await expect(page.locator(".alert-card")).toContainText("alpha.example.com");
  await expect(page.locator(".alert-card")).toContainText("grade A");

  // /inbox drill-in: add a note + Save
  await gotoRoute(page, "/inbox");
  await page.locator(".inbox-row", { hasText: "mydoc" }).locator(".inbox-top").click();
  await page.locator(".report-notes-input").fill(NOTE);
  await page.getByRole("button", { name: "Save notes" }).click();
  await expect(page.locator(".report-notes-status")).toHaveText("Saved");

  // re-render (nav away + back) -> the note persisted to the vault
  await gotoRoute(page, "/alerts");
  await gotoRoute(page, "/inbox");
  await page.locator(".inbox-row", { hasText: "mydoc" }).locator(".inbox-top").click();
  await expect(page.locator(".report-notes-input")).toHaveValue(NOTE);
  expect(await page.locator(".inbox-detail img").count()).toBe(0); // the markup never became an element

  // the report: namespace is not raw-readable via the debug hook (D2)
  const refused = await page.evaluate(() => {
    try {
      (window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("report:file: mydoc:notes");
      return "NO_THROW";
    } catch {
      return "THREW";
    }
  });
  expect(refused).toBe("THREW");

  // no key on the page; no off-allowlist egress
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-surfaces.png", fullPage: true });
});
