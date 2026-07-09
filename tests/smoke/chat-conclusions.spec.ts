import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// co-investigator Q&A smoke (founder 2026-07-03): the live proof for the two chat fixes —
// (1) a "what are the conclusions" question is routed to the SYNTHESIS voice (the connected picture,
//     bottom line + next move), not the flat per-fact frame;
// (2) a "more succinctly" follow-up carries the PRIOR ANSWER to the wire (CONVERSATION SO FAR) and
//     returns a compressed answer instead of resetting to the no-evidence refusal.
// Drives the REAL chat path (type → #chat-send → answerQuestion → AnthropicClient) with only the
// Anthropic fetch scripted (qaTexts, sequential); __kipi.qaRequests() exposes the captured request
// bodies so the assertions run against what actually reached the wire.

const KEY = "sk-ant-CONCLUSIONS-secret-42";

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      { type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

// the run-completion co-investigator briefing ALSO rides the scripted qaFetch (runBriefingFor), so it
// is the FIRST sequential answer; the conclusions Q&A and the follow-up are the second and third.
// plain-words-legs (2026-07-08): the run leg closes with the 3-part plain-words narrative.
const BRIEFING_TEXT = "Run done.\n## What I found\nThe host.\n## What I think\nLive infra.\n## Where I'd go next\nAsk for conclusions.";
const SYNTHESIS_ANSWER =
  "The case set out to identify what operates example.com. **Bottom line:** the live host " +
  "93.184.216.34 is the operating infrastructure [run: example.com]. **Next:** pivot the host's other domains.";
const COMPRESSED_ANSWER = "Compressed: 93.184.216.34 runs example.com [run: example.com].";

function isExternal(url: string): boolean {
  try { const u = new URL(url); return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1"; }
  catch { return false; }
}

async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account");
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]');
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await freshKeyedVault(page);
});

test("a conclusions question gets the synthesis voice; 'more succinctly' compresses the prior answer instead of refusing", async ({ page }) => {
  await expect(page.locator("#chat-input")).toBeVisible();
  await page.evaluate(
    ([turns, texts]) => (window as any).__kipi.installChatWire({ turns, qaTexts: texts }),
    [RUN_TURNS, [BRIEFING_TEXT, SYNTHESIS_ANSWER, COMPRESSED_ANSWER]] as const,
  );

  // a real run so the case has evidence (findings + trail) for grounding
  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");
  // remove-chat-findings + plain-words-legs (2026-07-08): the #findings chip column is gone — gate on the
  // run-completion briefing landing in the chat (its "What I found" section) instead, then confirm busy cleared.
  await expect(page.locator("#chat-messages")).toContainText("What I found", { timeout: 10_000 });
  await expect(page.locator("#chat-busy")).toBeHidden();

  // (1) the conclusions question → a CONNECTED synthesis (bottom line + linked finding), grounded
  await page.fill("#chat-input", "what are the conclusions of the investigation?");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("the operating infrastructure");
  await expect(page.locator("#chat-messages")).toContainText("93.184.216.34");
  await expect(page.locator(".sources").last()).toContainText("source"); // still cited/grounded
  const reqs1: string[] = await page.evaluate(() => (window as any).__kipi.qaRequests());
  const conclusionsReq = reqs1[reqs1.length - 1]; // the last request is the conclusions Q&A
  expect(conclusionsReq).toContain("connected picture"); // SYNTHESIS_PERSONA reached the wire
  expect(conclusionsReq).toContain("key judgments");
  expect(conclusionsReq).toContain("what are the conclusions");

  // (2) the follow-up compresses the SAME answer — the prior turn rides to the wire, no refusal
  await page.fill("#chat-input", "more succinctly");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("Compressed: 93.184.216.34");
  const reqs2: string[] = await page.evaluate(() => (window as any).__kipi.qaRequests());
  expect(reqs2.length).toBe(reqs1.length + 1); // exactly one more wire call for the follow-up
  const followupReq = reqs2[reqs2.length - 1];
  expect(followupReq).toContain("(oldest first"); // the history BLOCK is present (unique to buildQaPrompt)
  expect(followupReq).toContain("operating infrastructure"); // the PRIOR synthesis answer is what it compresses
  expect(followupReq).toContain("more succinctly");
  const chat = (await page.locator("#chat-messages").textContent()) ?? "";
  expect(chat).not.toContain("I don't know from this case"); // the old dead refusal never renders
  expect(chat).not.toContain("Nothing to answer from yet");

  // belts: no key leak, no real egress (the wire is scripted)
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(KEY);
  expect(reqs2.join(" ")).not.toContain(KEY);
  expect(external.filter((u) => u.includes("anthropic"))).toEqual([]);
});
