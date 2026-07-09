import { test, expect, type Page } from "@playwright/test";

// ch-lifecycle-cue (controls-honesty / sp-bacfd8f0): the chat lifecycle strip prefills #chat-input and
// focuses it, but used to give zero visible feedback — so the founder read the click as a dead no-op.
// flashPrefill() now adds the deterministic .lc-prefilled class (asserted here) + scrolls the input into
// view; the class clears on the first real keystroke. The prefill-never-auto-send contract is unchanged.

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw")); // starter "Test case" → home dock open
}

test("ch-lifecycle-cue: clicking a lifecycle stage prefills #chat-input AND shows the assertable cue", async ({ page }) => {
  await freshVault(page);

  const rail = page.locator("#chat-lifecycle-rail");
  await expect(rail).toBeVisible(); // the strip is painted at the top of the chat on home (default-open dock)

  const input = page.locator("#chat-input");
  await expect(input).toHaveValue(""); // starts empty, no cue
  await expect(input).not.toHaveClass(/lc-prefilled/);

  // click the first lifecycle stage (Intake)
  await rail.locator(".lc-stage").first().click();

  // the prefill fired (non-empty) AND focused the input AND the deterministic cue class is present
  await expect(input).not.toHaveValue("");
  await expect(input).toBeFocused();
  await expect(input).toHaveClass(/lc-prefilled/);

  // it did NOT auto-send: no user bubble landed in the transcript
  await expect(page.locator(".you-bubble")).toHaveCount(0);

  // a NON-editing key (End/arrows) must NOT clear the cue — it clears only on a real edit (codex fix)
  await input.press("End");
  await expect(input).toHaveClass(/lc-prefilled/);

  // the first REAL edit (a trusted input event) clears the cue, so a later edit isn't visually stuck
  await input.press("!");
  await expect(input).not.toHaveClass(/lc-prefilled/);
});
