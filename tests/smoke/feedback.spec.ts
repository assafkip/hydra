import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// rel-feedback smoke: the feedback control is a github-issue ANCHOR (target=_blank rel=noopener),
// NOT a fetch — its href is the fixed assafkip/kipi new-issue URL with no case data, the disclosure
// is visible, and github.com is NOT an egress origin (no off-allowlist request occurs).

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

test("feedback: a github-issue anchor with the disclosure; no case data; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  // seed a case so there IS vault content that must NOT appear in the feedback URL
  await freshVault(page);
  await page.evaluate(() =>
    (window as unknown as { __kipi: { putCase(k: string, v: unknown): Promise<unknown> } }).__kipi.putCase("run:secretcase", { objective: "secretcase", note: "do-not-leak-xyz" }),
  );

  // the feedback link lives on the Account page now (ac-ui moved setup/feedback off the graph home)
  await gotoRoute(page, "/account");
  const link = page.locator("#feedbackLink");
  await expect(link).toBeVisible();
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link).toHaveAttribute("rel", "noopener");
  await expect(page.locator(".feedback-note")).toContainText("never see your cases");

  const href = await link.getAttribute("href");
  expect(href).toContain("https://github.com/assafkip/kipi/issues/new");
  expect(href).not.toContain("secretcase");
  expect(href).not.toContain("do-not-leak-xyz");

  // the anchor is not a fetch: no off-allowlist egress just from rendering/inspecting it
  expect(external).toEqual([]);
});
