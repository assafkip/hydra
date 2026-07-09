import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// cd-smoke (PRD chat-dock D1): the WARM-PATH proof. The scar (warm-path-needs-a-live-smoke) is a
// chat that LOOKS wired but whose streaming run path is dead with offline tests green. So this
// proof drives the REAL user path — TYPE an objective into #chat-input, click #chat-send — through
// the REAL runInvestigation / AnthropicClient.run loop, with only the Anthropic fetch scripted via
// __kipi.installChatWire (no key needed for the wire, no network). A delayed second turn proves
// steps STREAM into #trail BEFORE the run completes; the graph GROWS on completion; a typed command
// drives the canvas; a grounded Q&A is cited and starts NO run; the in-trail Stop aborts a hanging
// run; the saved key never leaks; no unexpected egress. A fake-client test could not reproduce the
// abort-cancels-the-in-flight-await timing — that is the whole point of running the real loop.

const KEY = "sk-ant-CHATDOCK-secret-77"; // distinctive key for the no-leak sweep

// turn 1 emits a reasoning step + a tool_use (the canned dns tool surfaces the IP); turn 2 is
// DELAYED so turn 1's steps render into #trail while the run is still busy (incremental streaming).
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
    __delayMs: 1500, // hold the final turn so the intermediate steps are observably earlier
  },
];

const QA_TEXT = "The operating host is `93.184.216.34` [run: example.com]. It is a promoted finding.";

function isExternal(url: string): boolean {
  try { const u = new URL(url); return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1"; }
  catch { return false; }
}

async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY); // the REAL key-save path (the input is cleared after save)
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); }); // D2: before goto
  await freshKeyedVault(page);
});

test("an objective typed into the chat streams steps + grows the graph; a command drives the canvas; Q&A is grounded; no leak/egress", async ({ page }) => {
  // the chat dock is mounted + visible (dock defaults open)
  await expect(page.locator("#chat-input")).toBeVisible();
  await expect(page.locator("#chat-empty")).toBeVisible();

  // install the scripted wire (run turns + the grounded-answer text), then drive the REAL chat path
  await page.evaluate(([turns, qa]) => (window as any).__kipi.installChatWire({ turns, qaText: qa }), [RUN_TURNS, QA_TEXT] as const);

  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");

  // (a) STREAMING: a step is in #trail WHILE the run is still busy (turn 2 is delayed) — proven
  // before the final findings render. This is the warm-path assertion a mock can't fake.
  await expect(page.locator("#trail .step").first()).toBeVisible();
  await expect(page.locator("#chat-busy")).toBeVisible();
  // remove-chat-findings (2026-07-08): the mid-stream "#findings not yet populated" check is gone with the
  // column. The streaming proof above (a step in #trail while #chat-busy shows) stands on its own — and the
  // graph is NOT a valid "not done" signal (it grows live during the run, not only at finalize).

  // (b) COMPLETION: the completion bubble lands in the chat AND the cytoscape graph GREW (objective + ip)
  await expect(page.locator("#chat-messages")).toContainText("promoted", { timeout: 10_000 }); // the agent completion bubble
  await expect(page.locator("#chat-busy")).toBeHidden();
  expect((await page.evaluate(() => (window as any).__kipi.cyCounts())).nodes).toBe(2);

  // (c) TYPED COMMAND drives the canvas: "only ips" dims the non-ip node (the seed objective)
  await page.fill("#chat-input", "only ips");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("only ip");
  expect(await page.evaluate(() => (window as any).__kipi.cyDimmed())).toBeGreaterThan(0);

  // (d) GROUNDED Q&A: a question is answered from the run's findings, cited, and starts NO run
  const nodesBefore = (await page.evaluate(() => (window as any).__kipi.cyCounts())).nodes;
  await page.fill("#chat-input", "who runs example.com?");
  await page.click("#chat-send");
  await expect(page.locator("#chat-messages")).toContainText("93.184.216.34");
  await expect(page.locator(".sources")).toContainText("source"); // the grounded source chip
  await expect(page.locator("#chat-busy")).toBeHidden();
  expect((await page.evaluate(() => (window as any).__kipi.cyCounts())).nodes).toBe(nodesBefore); // no new run

  // (e) NO KEY LEAK across every surface the chat touches
  const innerHTML = await page.evaluate(() => document.documentElement.innerHTML);
  expect(innerHTML).not.toContain(KEY);
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(KEY);
  const trail = (await page.locator("#trail").textContent()) ?? "";
  expect(trail).not.toContain(KEY);
  const graphJson = await page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel()));
  expect(graphJson).not.toContain(KEY);

  // (f) NO unexpected egress (the scripted wire means zero real Anthropic/network calls)
  expect(external).toEqual([]);
});

// video-review 2026-06-25: a finished run shows the agent's actual CO-INVESTIGATOR briefing (model-written,
// "where we stand + bottom line + next move"), not the hardcoded "N promoted, N leads" count line. The briefing
// is composed via the qaFetch wire (a single judgment call); a distinctive scripted reply lets the assertion
// DISTINGUISH the briefing from the old template. Reference: 4_points case-037 op log.
test("a finished run shows the co-investigator BRIEFING, not the hardcoded count line", async ({ page }) => {
  // plain-words-legs (2026-07-08): the leg closes with the 3-part plain-words narrative (## headings render
  // as clean bold). A distinctive scripted reply lets the assertion DISTINGUISH the briefing from the count line.
  const BRIEFING = "We set out to map example.com.\n## What I found\nConfirmed one operating host, 93.184.216.34.\n## What I think\nThe seed resolves to live infra.\n## Where I'd go next\nDig 93.184.216.34.";
  await page.evaluate(([turns, qa]) => (window as any).__kipi.installChatWire({ turns, qaText: qa }), [RUN_TURNS, BRIEFING] as const);

  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");

  // the run completes → the chat shows the MODEL-WRITTEN 3-part briefing…
  await expect(page.locator("#chat-messages")).toContainText("What I found", { timeout: 10_000 });
  await expect(page.locator("#chat-messages")).toContainText("What I think");
  await expect(page.locator("#chat-messages")).toContainText("Where I'd go next");
  // …and NOT the hardcoded count template's distinctive tail (the briefing replaced it).
  await expect(page.locator("#chat-messages")).not.toContainText("Generate a brief below, or ask a question about what landed");
  expect(external).toEqual([]); // the briefing used the scripted wire — still zero real egress
});

// cd-buttons (founder 2026-06-24): the start/continue phrases must be CLICKABLE buttons in the chat, and
// submitting scope must START the investigation. These drive the REAL run path (runCase → investigateCase)
// via the scripted wire — the same warm path the typed "start investigation" affirmative hits.
test("the Start-investigation button drives a whole-case run (clickable, not only typed)", async ({ page }) => {
  await page.evaluate(([turns]) => (window as any).__kipi.installChatWire({ turns }), [RUN_TURNS] as const);

  const startBtn = page.locator("button.tc-start");
  await expect(startBtn).toBeVisible();
  await expect(startBtn).toContainText("Start investigation");

  await startBtn.click();
  // the REAL runCase path completes and the dock posts its whole-case summary
  await expect(page.locator("#chat-messages")).toContainText("Worked the whole case", { timeout: 10_000 });
  await expect(page.locator("#chat-busy")).toBeHidden();
  expect(external).toEqual([]);
});

test("submitting scope auto-starts the investigation (frame the question → go)", async ({ page }) => {
  await page.evaluate(([turns]) => (window as any).__kipi.installChatWire({ turns }), [RUN_TURNS] as const);

  // open the Scope form from its tradecraft button, fill the question, save
  await page.click('button.tc-step[data-step="scope"]');
  await expect(page.locator(".tc-scope")).toBeVisible();
  await page.fill(".tc-scope-q", "Who operates the FIFA-spoof domains?");
  await page.click(".tc-scope-save");

  // the new auto-start path: scope is recorded, THEN the whole-case run kicks off automatically
  await expect(page.locator("#chat-messages")).toContainText("scope captured — starting investigation");
  await expect(page.locator("#chat-messages")).toContainText("Worked the whole case", { timeout: 10_000 });
  await expect(page.locator(".tc-scope")).toBeHidden();
  expect(external).toEqual([]);
});

test("the in-trail Stop aborts a hanging run cleanly (real loop, real abort timing)", async ({ page }) => {
  // a single turn that HANGS until the AbortSignal fires — only the real awaited fetch can prove
  // that Stop cancels the in-flight request (a fake client can't reproduce this).
  await page.evaluate(() => (window as any).__kipi.installChatWire({ turns: [{ __waitForStop: true }] }));

  await page.fill("#chat-input", "investigate hang.example.com");
  await page.click("#chat-send");

  // the run is live: #stopBtn is shown (app.ts owns its visibility for the whole run lifecycle)
  await expect(page.locator("#stopBtn")).toBeVisible();
  await expect(page.locator("#chat-busy")).toBeVisible();

  await page.click("#stopBtn");

  // the in-flight awaited fetch rejects → the loop returns aborted → the run ends cleanly, and the dock
  // shows the shipped honest-error line "Run stopped." (chat/dock.ts) — NOT the word "aborted".
  await expect(page.locator("#chat-busy")).toBeHidden();
  await expect(page.locator("#stopBtn")).toBeHidden();
  await expect(page.locator("#chat-messages")).toContainText("Run stopped.");
  expect(external).toEqual([]);
});

// scope-scroll-fix (founder 2026-07-07): the run LOG is a BOUNDED, self-scrolling panel ABOVE the
// conversation — the founder wants the chat at the bottom by the input, with the log running on its own up
// top, never having to scroll up through the log to talk. This supersedes the old chat-dock-readable
// "one uncapped scroller" contract (the uncapped log reflowed the whole conversation as it streamed).
test("the run log is a bounded self-scrolling panel ABOVE the conversation (chat stays at the bottom)", async ({ page }) => {
  await page.evaluate(([turns]) => (window as any).__kipi.installChatWire({ turns }), [RUN_TURNS] as const);

  // the conversation scroller still flexes to fill the dock (no 30vh cap) — long answers are readable
  const scrollMaxH = await page.evaluate(() => getComputedStyle(document.getElementById("chat-scroll")!).maxHeight);
  expect(scrollMaxH).toBe("none");

  await page.fill("#chat-input", "investigate example.com");
  await page.click("#chat-send");
  // remove-chat-findings (2026-07-08): wait on the completion bubble, not the deleted #findings chip column.
  await expect(page.locator("#chat-messages")).toContainText("promoted", { timeout: 10_000 });

  // the LOG sits ABOVE the conversation in the DOM — 4 == Node.DOCUMENT_POSITION_FOLLOWING (#chat-scroll
  // comes AFTER #trail), i.e. the log is on top and the chat is beneath it, by the input.
  const logIsAboveChat = await page.evaluate(() => {
    const t = document.getElementById("trail")!;
    const s = document.getElementById("chat-scroll")!;
    return (t.compareDocumentPosition(s) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
  });
  expect(logIsAboveChat).toBe(true);

  // the conversation scroller still auto-follows to the newest turn (chat pinned to the bottom by the input).
  // Checked BEFORE expanding the log — expanding steals vertical space and re-pins, which is not what this asserts.
  const atBottom = await page.evaluate(() => {
    const s = document.getElementById("chat-scroll")!;
    return s.scrollTop + s.clientHeight >= s.scrollHeight - 2;
  });
  expect(atBottom).toBe(true);
  expect(external).toEqual([]);

  // hydra ISSUE-6/7: the log now COLLAPSES to a pill when a run ends. Expand it (click the header) and assert
  // it is its own bounded, drag-resizable scroll box — max-height cap + overflow:auto — NOT flowing in the chat.
  await page.click(".livetrail-toggle");
  const trail = await page.evaluate(() => {
    const cs = getComputedStyle(document.getElementById("trail")!);
    return { maxHeight: cs.maxHeight, overflowY: cs.overflowY, resize: cs.resize };
  });
  expect(trail.maxHeight).not.toBe("none"); // capped (78vh → a px value)
  expect(trail.overflowY).toBe("auto"); // its OWN scroll box, so its growth never reflows the chat
  expect(trail.resize).toBe("vertical"); // hydra ISSUE-7: drag the bottom edge to resize
});

// chat-feels-like-a-product: the run loop publishes redacted model tokens as agent_text_delta; the
// reducer types them into ONE live bubble so the reply composes in real time (was published + DROPPED —
// no consumer, so the answer popped in whole). scriptedFetch returns whole JSON (no SSE), so this drives
// the bridge the reducer calls — the deterministic unit of that behavior — and asserts a single growing
// bubble that streamEnd clears. Also asserts message identity (bylines) is present.
test("live streaming: agent_text_delta types into ONE bubble; streamEnd clears it; turns carry bylines", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.waitForFunction(() => !!(window as any).__kipiChat);

  // a durable agent turn -> "Investigator" byline (message identity is present, not just bubble color)
  await page.evaluate(() => (window as any).__kipiChat.pushAgent("hi there"));
  await expect(page.locator(".msg.agent .msg-byline").first()).toHaveText("Investigator");

  // stream three deltas -> exactly ONE streaming bubble, text accumulates
  await page.evaluate(() => (window as any).__kipiChat.streamDelta("Look"));
  await page.evaluate(() => (window as any).__kipiChat.streamDelta("ing at "));
  await page.evaluate(() => (window as any).__kipiChat.streamDelta("evil.com"));
  await expect(page.locator(".msg.streaming .stream-bubble")).toHaveCount(1);
  await expect(page.locator(".msg.streaming .stream-bubble")).toContainText("Looking at evil.com");

  // streamEnd removes the live bubble (the curated briefing arrives separately via pushAgent)
  await page.evaluate(() => (window as any).__kipiChat.streamEnd());
  await expect(page.locator(".msg.streaming")).toHaveCount(0);

  // XSS-safe: a hostile delta renders as literal text, never an injected element
  await page.evaluate(() => (window as any).__kipiChat.streamDelta("<img src=x onerror=alert(1)>"));
  await expect(page.locator(".stream-bubble img")).toHaveCount(0);
  await expect(page.locator(".msg.streaming .stream-bubble")).toContainText("<img src=x");
  await page.evaluate(() => (window as any).__kipiChat.streamEnd());
});
