import { test, expect, type Page } from "@playwright/test";

// ob-smoke: the first-run onboarding overlay + the deferred-key moment.
//   (1) A freshly-created vault with zero runs shows the .onboard-card on home; "Got it" dismisses it
//       and it stays dismissed across a reload; a vault that already onboarded never shows it.
//   (2) Starting an investigation with NO Anthropic key highlights + focuses the key card; saving a key
//       clears the highlight.
// No off-allowlist egress across any of it.
//
// keyflow-gate-skip: this spec's /account navigation on a keyless run is PROGRAMMATIC (the app's
// keyless handler routes there via pendingKeyFocus), not a data-route click in the spec — so the
// static keyflow gate exempts it. It instead PROVES the routing below (toHaveURL + focus on /account).

const KEY = "sk-ant-OB-smoke-7";

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
  // { onboarded: false } opts into the genuine first-run state so the overlay actually renders.
  await page.evaluate(() =>
    (window as unknown as { __kipi: { createVault(pw: string, o: { onboarded: boolean }): Promise<unknown> } }).__kipi.createVault("pw", { onboarded: false }),
  );
}

test("onboarding overlay shows once, dismiss persists; keyless run highlights the key card", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  await freshVault(page);

  // (1) The first-run overlay is visible on a fresh vault.
  await expect(page.locator("#onboard")).toBeVisible();
  await expect(page.locator(".onboard-card")).toContainText("Nothing leaves your browser");
  await expect(page.locator(".onboard-card[role='dialog'][aria-modal='true']")).toBeVisible();
  await page.screenshot({ path: "test-results/kipi-onboarding-overlay.png", fullPage: true });

  // ob-keyprompt: run an investigation with NO key -> the key card highlights + focuses #apikey.
  // Drive the REAL chat dock (the scripted bridge injects a dummy key, so it can't exercise the keyless
  // path). "investigate <ip>" classifies as an objective -> startInvestigation -> the keyless SessionError.
  await page.locator(".onboard-dismiss").click();
  await expect(page.locator("#onboard")).toHaveCount(0);

  await page.fill("#chat-input", "investigate 8.8.8.8");
  await page.click("#chat-send");
  // kf-fix: the keyless run ROUTES to /account (the key card moved off home). Prove the routing
  // explicitly (not just incidentally) before the key-card assertions, which only resolve there.
  await expect(page).toHaveURL(/#\/account$/);
  await expect(page.locator("#keycard")).toHaveClass(/key-needed/);
  await expect(page.locator("#apikey")).toBeFocused();

  // saving a key clears the highlight (we are on /account now — the keyless run routed us here)
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await expect(page.locator("#keycard")).not.toHaveClass(/key-needed/);

  // (2) the dismissal persists on HOME across a reload. Go back to the graph home (the keyless run
  // routed us to /account), reload (drops the in-memory unlock; the vault file persists), unlock, and
  // confirm the overlay does NOT re-show (getOnboarded() is true after the earlier dismiss).
  await page.click('a[data-route="/"]');
  await expect(page.locator("#cy")).toBeVisible();
  await page.reload();
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { unlock(pw: string): Promise<unknown> } }).__kipi.unlock("pw"));
  await page.waitForFunction(() => document.querySelector("#cy") !== null);
  await expect(page.locator("#onboard")).toHaveCount(0);

  // no off-allowlist egress
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-onboarding.png", fullPage: true });
});
