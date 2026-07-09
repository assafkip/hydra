import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// ca-ui smoke (the live proof of analyst authority): override an entity's role via the entity-detail
// select; the override propagates to the graph (__kipi.graphModel) + the /corrections audit (with the
// analyst name); revert restores the original; an XSS name renders literal; the correction namespace is
// not raw-readable via __kipi; no key leak; no egress.

const APIKEY = "sk-ant-CA-smoke-2020";
const XSS_NAME = "<img src=x onerror=alert(1)>";

const SEED_TURNS = [
  {
    content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"example.com","entity_type":"domain"}]}\n```' }],
    stop_reason: "end_turn",
    usage: { output_tokens: 10 },
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
async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}
function roleOnGraph(page: Page): Promise<string | undefined> {
  return page.evaluate(
    () => (window as unknown as { __kipi: { graphModel(): { nodes: { label: string; role?: string }[] } | null } }).__kipi.graphModel()?.nodes.find((n) => n.label === "example.com")?.role,
  );
}

test("analyst role override propagates to the graph + /corrections audit; revert restores; no leak", async ({ page }) => {
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

  // seed a domain node on the home graph
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("dig example.com", turns), SEED_TURNS);
  // the model node carries an EXPLICIT role only once corrected (otherwise the renderer derives it), so
  // the uncorrected node.role is undefined — the correction makes it 'operator', and revert clears it.
  const originalRole = await roleOnGraph(page);

  // set the analyst name to an XSS payload via /corrections
  await gotoRoute(page, "/corrections");
  await page.fill(".corr-name-input", XSS_NAME);
  await page.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByRole("button", { name: "Saved" })).toBeVisible();

  // override the role via the entity-detail assert form on /entities (the field-select defaults to
  // "role" → pick the value, then Set). Replaces the old role-only <select> (renderAssertForm).
  await gotoRoute(page, "/entities");
  await page.locator(".ent-row", { hasText: "example.com" }).locator(".ent-top").click();
  await page.locator(".ent-assert-value").selectOption("operator");
  await page.locator(".ent-assert").getByRole("button", { name: "Set", exact: true }).click();

  // the graph reflects the corrected role (home re-projects with corrections applied)
  await page.click('a[data-route="/"]');
  await expect.poll(() => roleOnGraph(page)).toBe("operator");

  // /corrections audits it with the (literal) XSS author
  await gotoRoute(page, "/corrections");
  await expect(page.locator(".corr-card")).toContainText("operator");
  await expect(page.locator(".corr-card")).toContainText(XSS_NAME); // literal, not markup
  expect(await page.locator(".corr-card img").count()).toBe(0);

  // the correction namespace is NOT raw-readable via the debug hook (D6)
  const refused = await page.evaluate(() => {
    try {
      (window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("correction:role:[\"domain\",\"example.com\"]");
      return "NO_THROW";
    } catch {
      return "THREW";
    }
  });
  expect(refused).toBe("THREW");

  // revert -> the original role returns on the graph
  await page.locator(".corr-card").getByRole("button", { name: "Revert" }).first().click();
  await page.click('a[data-route="/"]');
  await expect.poll(() => roleOnGraph(page)).toBe(originalRole);

  // no key on the page; no off-allowlist egress
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-corrections.png", fullPage: true });
});
