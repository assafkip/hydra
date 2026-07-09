import { test, expect } from "@playwright/test";
import { gotoRoute } from "./_nav";
// Visual capture of the cloned chat dock (scripted run — no key, no network). On-demand:
//   npx playwright test tests/smoke/chat-shot.spec.ts
// Captures the graph-dominant split-view with the Investigator chat dock after a run, for the
// side-by-side clone comparison against investigations/webapp/templates/_chat.html (docked).

const TURNS = [
  { content: [{ type: "text", text: "Resolving example.com to find its hosting." }, { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
  { content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' }], stop_reason: "end_turn", usage: { output_tokens: 20 } },
];

test("capture the chat dock", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("demo-pass"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", "sk-ant-demo");
  await page.click("#saveKeyBtn");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
  await page.evaluate((turns) => (window as any).__kipi.installChatWire({ turns }), TURNS);
  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");
  // remove-chat-findings (2026-07-08): wait for the ip on the GRAPH, not the removed #findings column.
  await expect.poll(() => page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel())), { timeout: 10_000 }).toContain("93.184.216.34");
  // ask a (no-evidence-safe) command so the thread shows a conversational turn too
  await page.fill("#chat-input", "fit");
  await page.click("#chat-send");
  await page.waitForTimeout(400);
  await page.screenshot({ path: "test-results/kipi-chat-dock.png", fullPage: true });
});
