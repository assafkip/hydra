import { test, expect, type Page } from "@playwright/test";

// ch-gate-floor (controls-honesty / sp-2a98dc39): the tradecraft Premortem/Challenge gate used to run a
// thin model pass on a case with only a stray thin lead (no finished investigator run, no promoted
// finding), producing weak generic boilerplate the founder read as the gate lying. The floor now blocks
// the model call with a plain "hasn't been investigated yet" message UNLESS the case is substantively
// investigated (>=1 finished agent run OR >=1 promoted finding). Driven live through the real chat button.

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
}

async function clickPremortem(page: Page) {
  await page.getByRole("button", { name: /Premortem/ }).click();
}

function chatText(page: Page) {
  return page.locator("#chat-host").innerText();
}

test("ch-gate-floor: thin-leads-only case → Premortem says 'not investigated yet', NO model call", async ({ page }) => {
  await freshVault(page);

  // seed a run: record with ONLY a thin lead — no stopReason, no promoted finding (the sp-2a98dc39 case)
  await page.evaluate(() =>
    (window as any).__kipi.putCase("run:thin", {
      objective: "thin",
      promoted: [],
      leads: [{ finding: { entity: "Jane Roe", entity_type: "person" }, verdict: { promote: false, grade: "D", reason: "name only" } }],
    }),
  );

  await clickPremortem(page);
  // the honest floor message (NOT a thin model pass, NOT the key prompt — it blocks BEFORE the key check)
  await expect.poll(() => chatText(page)).toContain("hasn't been investigated yet");
  await expect.poll(() => chatText(page)).not.toContain("Add your Anthropic API key");
});

test("ch-gate-floor: a finished agent run clears the floor → Premortem proceeds (to the key prompt)", async ({ page }) => {
  await freshVault(page);

  // seed a FINISHED agent run: not an ingest report, carries a stopReason → substantively investigated
  await page.evaluate(() =>
    (window as any).__kipi.putCase("run:agent", {
      objective: "investigate evil.com",
      stopReason: "end_turn",
      promoted: [],
      leads: [{ finding: { entity: "Jane Roe", entity_type: "person" }, verdict: { promote: false, grade: "D", reason: "name only" } }],
    }),
  );

  await clickPremortem(page);
  // floor cleared → it no longer says "not investigated"; with no key it asks for the key (proves it got past the floor)
  await expect.poll(() => chatText(page)).not.toContain("hasn't been investigated yet");
  await expect.poll(() => chatText(page)).toContain("Add your Anthropic API key");
});
