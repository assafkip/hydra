import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-briefs smoke (the RENDER GATE): ingest reports that share entities, click "Group related reports"
// on /deliverables, and the grouped-relatedness engine + per-group summary (scripted, offline) produce
// records that the /briefs viewer renders — a verdict badge + ## Summary preview + "N reports" + a
// standalone bucket, with an INLINE-EXPAND to the full group markdown. Drives the REAL router
// (location.hash) so a faithful-but-hollow detail fails here. Zero egress, no key leak.

const APIKEY = "sk-ant-BRIEFS-smoke-5151";
const GROUP_SUMMARY = "The two reports share alpha.example.com and beta.example.com and front the same drainer operation.";

// two reports sharing 2 domains (jaccard high → strong group) + one unrelated (standalone).
const DOC_A = "Investigation notes: alpha.example.com and beta.example.com and gamma.example.com are connected infrastructure.";
const DOC_B = "Follow-up: alpha.example.com and beta.example.com also resolve alongside delta.example.com.";
const DOC_C = "Unrelated case: zeta.example.org operates on its own with no overlap.";

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

test("briefs: Group related reports clusters the reports and /briefs renders the grouped list + inline detail; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key, then ingest three file reports (the engine's report universe = file-ingest runs).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  for (const text of [DOC_A, DOC_B, DOC_C]) {
    await page.evaluate(
      (t) => (window as unknown as { __kipi: { ingestText(n: string, x: string): Promise<unknown> } }).__kipi.ingestText("report", t),
      text,
    );
  }
  // scripted per-group/standalone summary wire (offline; no key on the wire).
  await page.evaluate((g) => (window as unknown as { __kipi: { installChatWire(spec: unknown): void } }).__kipi.installChatWire({ groupBriefText: g }), GROUP_SUMMARY);

  // (2) /deliverables → click "Group related reports" → the button navigates to /briefs on success.
  await gotoRoute(page, "/deliverables");
  await page.getByRole("button", { name: /Group related reports|Regroup reports/ }).click();

  // (3) the REAL router landed on /briefs (the button did location.hash navigation).
  await expect.poll(() => page.evaluate(() => location.hash)).toBe("#/briefs");

  // (4) the grouped list rendered: a "strong" verdict badge, the ## Summary preview, and "2 reports".
  await expect(page.locator(".brief-badge-strong")).toBeVisible();
  await expect(page.locator(".brief-preview")).toContainText("front the same drainer operation");
  await expect(page.locator(".del-card", { has: page.locator(".brief-badge-strong") }).locator(".brief-reports")).toContainText("2 reports");
  // the standalone bucket (zeta.example.org didn't overlap).
  await expect(page.locator(".brief-badge-unknown")).toContainText("no overlap");

  // (5) INLINE EXPAND: click the strong group's header → the full group markdown renders in the DOM.
  const groupHead = page.locator(".del-card", { has: page.locator(".brief-badge-strong") }).locator(".brief-head");
  await groupHead.click();
  const detail = page.locator(".del-card", { has: page.locator(".brief-badge-strong") }).locator(".brief-detail");
  await expect(detail).toBeVisible();
  await expect(detail.locator("h1")).toContainText("Brief: group 1");
  await expect(detail).toContainText("Relatedness verdict");

  await page.screenshot({ path: "test-results/kipi-briefs.png", fullPage: true });

  // (6) the group records persisted at groupbrief:* + an index; key-redacted.
  const index = await page.evaluate(() =>
    (window as unknown as { __kipi: { getCase(k: string): { value: { groups?: string[]; standalone?: boolean } | null } } }).__kipi.getCase("groupbrief:index").value,
  );
  expect(index?.groups?.length, "the index lists >=1 group").toBeGreaterThan(0);
  expect(index?.standalone, "the index flags the standalone bucket").toBe(true);
  const g1 = await page.evaluate(() =>
    (window as unknown as { __kipi: { getCase(k: string): { value: { content?: string } | null } } }).__kipi.getCase("groupbrief:group-1").value,
  );
  expect(g1?.content, "the group record carries the markdown").toContain("Relatedness verdict");
  expect(JSON.stringify({ index, g1 })).not.toContain(APIKEY);

  // (7) no key in the page body; no off-allowlist egress.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
