import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";

// clu-chat-persist (issue chat-vault-persist): the WARM-PATH proof for Bug 1 — chat history vanished on
// every refresh / in-app nav / tab-switch because it lived only in the mountChatDock() closure with zero
// persistence. This drives the REAL #chat path (type → send), then reloads and navigates away-and-back,
// asserting the SAME conversation is still there. A "help" turn is used because it posts both a user bubble
// (pushYou) and an agent bubble (pushAgent) through the real persist chokepoint with NO key/network needed.

const USER_TURN = "help"; // classifyInput → help mode: posts the user bubble + the TOOL_GUIDE agent bubble

async function freshVaultHome(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.click('a[data-route="/"]'); // the graph home, where the chat dock mounts
  await expect(page.locator("#chat-input")).toBeVisible();
}

async function expectConversationPresent(page: Page) {
  // the user bubble + an agent bubble both survived; the empty prompt is NOT shown (history was replayed)
  await expect(page.locator("#chat-messages")).toContainText(USER_TURN);
  await expect(page.locator("#chat-messages .msg.agent").first()).toBeVisible();
  await expect(page.locator("#chat-empty")).toBeHidden();
}

test.beforeEach(async ({ page }) => {
  await freshVaultHome(page);
});

test("chat history survives a page refresh AND an in-app nav round-trip", async ({ page }) => {
  // send a real turn through the dock
  await page.fill("#chat-input", USER_TURN);
  await page.click("#chat-send");
  await expectConversationPresent(page);

  // (a) REFRESH — the founder-reported failure: the conversation must come back, not an empty dock
  await page.reload();
  await expect(page.locator("#chat-input")).toBeVisible(); // stay-signed-in: vault auto-restores
  await expectConversationPresent(page);

  // (b) IN-APP NAV away and back — render() re-mounts the dock; it must rehydrate, not blank
  await gotoRoute(page, "/enrich");
  await expect(page.locator("#chat-input")).toBeHidden(); // left the workspace
  await gotoRoute(page, "/");
  await expect(page.locator("#chat-input")).toBeVisible();
  await expectConversationPresent(page);
});

test("a brand-new case shows the empty prompt, not a stale conversation", async ({ page }) => {
  // NEGATIVE: nothing sent yet → the empty prompt is visible and no message bubbles exist. Proves rehydrate
  // reads THIS case's (empty) history, not leftover DOM or another case's chat.
  await expect(page.locator("#chat-empty")).toBeVisible();
  await expect(page.locator("#chat-messages .msg")).toHaveCount(0);
});
