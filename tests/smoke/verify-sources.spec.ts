import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-sources smoke (the live proof): with ingested docs in the vault, /inbox exposes a Docs/Sources toggle;
// the Sources gallery renders the retained docs + their gate-extracted entity chips, with working filters.
// Offline, zero egress, no key leak.

const APIKEY = "sk-ant-SOURCES-smoke-7373";

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

function fileRun(objective: string, title: string, at: string, sourceType: string, ents: { entity: string; entity_type: string }[]) {
  return {
    objective, sourceKind: "file_ingest", title, ingestedAt: at, sourceType, steps: [],
    promoted: ents.map((e) => ({ ...e, grade: "B", source_count: 1, infra_source_count: 1 })),
    leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
  };
}

test("sources: /inbox Docs/Sources toggle renders the gallery + entity chips + a working filter; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");

  // seed two ingested docs (run: is not a protected key — putCase seeds them exactly as ingest would).
  await page.evaluate(([a, b]) => {
    const k = (window as unknown as { __kipi: { putCase(k: string, v: unknown): Promise<unknown> } }).__kipi;
    return Promise.all([k.putCase("run:file: acme.pdf #a1", a), k.putCase("run:file: notes.txt #b2", b)]);
  }, [
    fileRun("file: acme.pdf #a1", "acme.pdf", "2026-06-19T10:00:00.000Z", "pdf", [{ entity: "acme.io", entity_type: "domain" }, { entity: "1.2.3.4", entity_type: "ip" }]),
    fileRun("file: notes.txt #b2", "notes.txt", "2026-06-18T09:00:00.000Z", "text", [{ entity: "evil.com", entity_type: "domain" }]),
  ] as const);

  // (1) /inbox shows the Docs/Sources toggle.
  await gotoRoute(page, "/inbox");
  await expect(page.getByRole("button", { name: "Docs", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sources", exact: true })).toBeVisible();

  // (2) toggle to Sources → the gallery renders the docs + entity chips.
  await page.getByRole("button", { name: "Sources", exact: true }).click();
  await expect(page.locator(".src-card")).toHaveCount(2);
  await expect(page.locator(".src-card", { hasText: "acme.pdf" })).toContainText("pdf");
  await expect(page.locator(".src-chip", { hasText: "acme.io" })).toBeVisible();
  await expect(page.locator(".src-chip", { hasText: "evil.com" })).toBeVisible();
  await page.screenshot({ path: "test-results/kipi-sources.png", fullPage: true });

  // (3) the entity filter narrows the gallery to docs containing the entity.
  await page.locator(".src-filter[placeholder='filter by entity…']").fill("acme.io");
  await expect(page.locator(".src-card")).toHaveCount(1);
  await expect(page.locator(".src-card")).toContainText("acme.pdf");

  // (4) the grid/table view toggle works.
  await page.locator(".src-filter[placeholder='filter by entity…']").fill("");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(page.locator(".src-table .src-row")).toHaveCount(3); // header + 2 docs

  // (5) toggle back to Docs.
  await page.getByRole("button", { name: "Docs", exact: true }).click();
  await expect(page.locator(".inbox-row").first()).toBeVisible();

  // (6) no key leak, no egress.
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
