import { test, expect, type Page } from "@playwright/test";

// cd-tradecraft / cd-guidance smoke (chat-graph-parity-fixes): the restored analytical surface in the
// LIVE dock. The tradecraft bar renders; "help" walks a first-time analyst through the tool (founder
// bug #3); Scope captures framing (no key, no run); Challenge runs over the case findings via the
// scripted wire and shows ✓. A no-evidence question GUIDES instead of dead-ending.

const RUN_TURNS = [
  { content: [{ type: "text", text: "Resolving example.com." }, { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
  { content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' }], stop_reason: "end_turn", usage: { output_tokens: 20 } },
];

const CHALLENGE_TEXT = "1) Name-match traps: none. 2) Circular reasoning: none. To resolve: verify the registrant of example.com.";

async function settle(page: Page, ms = 700) { await page.waitForTimeout(ms); }

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
});

test("the tradecraft bar renders all six steps; 'help' shows the walkthrough; a no-evidence question guides", async ({ page }) => {
  await expect(page.locator("#chat-input")).toBeVisible();
  // the bar renders the three gates + three helpers
  await expect(page.locator(".tc-bar .tc-step")).toHaveCount(6);
  for (const label of ["Scope", "Challenge", "Premortem", "Timeline", "Target", "Reality check"]) {
    await expect(page.locator(".tc-bar")).toContainText(label);
  }

  // bug #3: "help" walks the analyst through the tool (no key, no model call)
  await page.fill("#chat-input", "help");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("how this works");
  await expect(page.locator("#chat-messages")).toContainText("investigate <domain>");

  // bug #3: a plain question on an empty case GUIDES, it does not dead-end with "I don't know"
  await page.fill("#chat-input", "who runs the show here?");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("no findings");
  await expect(page.locator("#chat-messages")).not.toContainText("I don't know from this case");
});

test("Scope captures framing and marks the gate done (scope is the go signal)", async ({ page }) => {
  // founder 2026-06-24: submitting scope IS the go signal — saveScope now starts the whole-case run
  // (dock.ts saveScope -> runCaseMode). Seed a dummy key via a scripted run + script the scope-triggered
  // run offline, so it does NOT error-route to /account (which would unmount #chat-messages). Then assert
  // the scope aside + the gate ✓. (Was "(no key, no run)" before the conductor auto-start change.)
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("seed", turns), RUN_TURNS); // sets a dummy key
  await page.evaluate((turns) => (window as any).__kipi.installChatWire({ turns }), RUN_TURNS); // the scope run goes offline
  await settle(page);

  await page.fill("#chat-input", "scope");
  await page.click("#chat-send");
  await expect(page.locator(".tc-scope")).toBeVisible();
  await page.fill(".tc-scope-q", "Who operates the funnel?");
  await page.fill(".tc-scope-h", "A single operator behind shared infra");
  await page.click(".tc-scope-save");
  await expect(page.locator(".tc-scope")).toBeHidden();
  await expect(page.locator("#chat-messages")).toContainText("scope captured");
  // the Scope step shows a done ✓
  await expect(page.locator('.tc-bar .tc-step[data-step="scope"]')).toContainText("✓");
});

test("Challenge runs over the case findings (scripted wire) and shows ✓", async ({ page }) => {
  // seed findings (also sets a dummy key), then script the gate's model call via the chat wire
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("Investigate example.com", turns), RUN_TURNS);
  await settle(page);
  await page.evaluate((qa) => (window as any).__kipi.installChatWire({ turns: [], qaText: qa }), CHALLENGE_TEXT);

  await page.fill("#chat-input", "challenge");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("Challenge");
  await expect(page.locator("#chat-messages")).toContainText("To resolve");
  await expect(page.locator('.tc-bar .tc-step[data-step="challenge"]')).toContainText("✓");
});
