import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// cap-chat-step-trail + cap-chat-findings-card parity verification
// (PRD prd-kipi-web-chat-caps-2026-06-18). Proven live via the REAL key-entry path:
//   - key entered on the /account card (where it actually lives — app.ts:867), NOT bypassed.
//   - cap-chat-step-trail: an objective typed into the dock STREAMS a step trail into #trail,
//     and each tool step shows the tool name + INPUT + RESULT (codex-hardened: the dock used to
//     drop input/result; now it reuses displayTrail() like the /runs trail).
//   - cap-chat-findings-card: a "runs" command folds THIS run's findings into a .runs-card.
// Streaming is proven with a DELAYED final turn: the first tool step is visible WHILE the final
// findings are still absent — a post-hoc append can't satisfy that. Scripted wire = zero egress.

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving example.com and pivoting on its infra." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 12 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "Done.\n```json\n{\"findings\":[" +
          "{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}" +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
    __delayMs: 1500, // hold the final turn so the intermediate tool step is observably earlier
  },
];

async function keyedVaultViaAccount(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  // REAL key entry — the card lives on /account (app.ts:867), not the home flow. NOT bypassed.
  await gotoRoute(page, "/account");
  await page.waitForSelector("#apikey", { timeout: 8000 });
  await page.fill("#apikey", "sk-ant-test-key");
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured", { timeout: 8000 });
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#chat-input", { timeout: 8000 });
}

let external: string[] = [];
test.use({ viewport: { width: 1440, height: 900 } });
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (r) => {
    try {
      const u = new URL(r.url());
      if (u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") external.push(r.url());
    } catch { /* ignore */ }
  });
});

test("chat dock streams a full step trail (tool+input+result) and folds findings into a runs card", async ({ page }) => {
  await keyedVaultViaAccount(page);
  await page.evaluate(([turns]) => (window as any).__kipi.installChatWire({ turns }), [RUN_TURNS] as const);

  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");

  // (a) STREAMING (cap-chat-step-trail): the tool step is in #trail WHILE the run is still busy and
  // the final findings are NOT yet rendered (turn 2 is delayed) — a post-hoc dump can't satisfy this.
  await expect(page.locator("#trail .step.tool").first()).toBeVisible({ timeout: 8000 });
  await expect(page.locator("#chat-busy")).toBeVisible();
  // remove-chat-findings (2026-07-08): the mid-stream "#findings not populated" check is gone with the column;
  // the DEPTH proof below (tool name + input + result in #trail while busy) is the streaming evidence.

  // (b) DEPTH (codex finding-1): the tool step shows the tool name + INPUT + RESULT, not just "ok".
  const toolStep = page.locator("#trail .step.tool").first();
  await expect(toolStep).toContainText("dns_lookup");
  await expect(toolStep.locator(".trail-input"), "the trail shows the tool INPUT").toContainText("example.com");
  await expect(toolStep.locator(".trail-result"), "the trail shows the tool RESULT").toContainText("93.184.216.34");

  // capture the LIVE trail (with input+result) while it is still streaming — the visual proof
  // of the codex-caught depth gap being fixed.
  await page.screenshot({ path: "test-results/verify-chat-trail.png", fullPage: true });

  // (c) COMPLETION: after the delayed final turn, the graph GROWS the promoted ip (remove-chat-findings:
  // the #findings chat column is gone — completion proves via the graph, not a chip render).
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes), { timeout: 10000 }).toBe(2);
  await expect(page.locator("#chat-busy")).toBeHidden();

  // (d) FINDINGS SUMMARY (cap-chat-findings): remove-cards (founder 2026-07-03) — a "runs" command now
  // answers as a chat MESSAGE (showRunsSummary), not a .runs-card. Assert the message CONTENT (the entity).
  await page.fill("#chat-input", "runs");
  await page.click("#chat-send");
  await expect(page.locator(".runs-card")).toHaveCount(0);
  await expect(page.locator("#chat-messages .msg.agent").last(), "the summary folds this run's findings").toContainText("example.com", { timeout: 6000 });

  await page.screenshot({ path: "test-results/verify-chat-card.png", fullPage: true });

  // (e) zero egress (the scripted wire + canned osint mean no real network)
  expect(external).toEqual([]);
});

// analyst-led direction (loosened run guard): a NATURAL-LANGUAGE directive (no explicit "investigate" verb)
// drives a real run, not Q&A. objectiveFrom("look at example.com") → "example.com", which the scripted wire
// answers. Proves the founder's "let me lead the investigation" — the chat acts on plain direction.
test("a natural-language directive (no 'investigate' verb) starts an investigation run", async ({ page }) => {
  await keyedVaultViaAccount(page);
  await page.evaluate(([turns]) => (window as any).__kipi.installChatWire({ turns }), [RUN_TURNS] as const);

  // a plain directive — the kind that used to fall through to Q&A and do nothing
  await page.fill("#chat-input", "look at example.com");
  await page.click("#chat-send");

  // it ACTS: a run starts (the step trail streams + busy), then the findings land — not a Q&A answer.
  await expect(page.locator("#trail .step.tool").first()).toBeVisible({ timeout: 8000 });
  await expect(page.locator("#chat-busy")).toBeVisible();
  // remove-chat-findings (2026-07-08): completion proves via the graph growing, not the removed #findings column.
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes), { timeout: 10000 }).toBe(2);
  await expect(page.locator("#chat-busy")).toBeHidden();
  expect(external).toEqual([]); // zero egress
});
