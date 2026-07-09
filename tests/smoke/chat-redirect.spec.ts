import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// interrupt-redirect (founder 2026-07-03): the analyst must be able to STEER a running investigation from
// the chat — the composer was locked during a run so there was "no way to stop or redirect the task". This
// smoke drives the REAL chat path: type an objective → Send starts a run that HANGS → the composer is still
// live and Stop is a prominent control → type a NEW objective → Send ("Redirect") aborts the current run and
// starts a fresh one, with a "redirecting" aside and NO "Run stopped." noise. Only the Anthropic fetch is
// scripted (installChatWire); the hang + abort timing is the real loop a mock can't fake.

const KEY = "sk-ant-REDIRECT-secret-55";

// turn 1 emits a step; turn 2 HANGS until the AbortSignal fires (the redirect aborts it). The redirect's
// fresh run then draws from the now-empty queue → a clean immediate end_turn (0 findings) — enough to prove
// a SECOND run started.
const TURNS_HANG = [
  {
    content: [
      { type: "text", text: "Resolving evil.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "evil.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  { __waitForStop: true },
];

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

test("a live run can be redirected from the chat: the composer stays open, Stop is prominent, a new objective aborts + restarts", async ({ page }) => {
  await expect(page.locator("#chat-input")).toBeVisible();
  await page.evaluate((turns) => (window as any).__kipi.installChatWire({ turns }), TURNS_HANG);

  // start a run that hangs on its second turn
  await page.fill("#chat-input", "investigate evil.com");
  await page.click("#chat-send");
  await expect(page.locator("#chat-busy")).toBeVisible();

  // (a) the composer is NOT locked during the run — the whole point (you can type a redirect)
  await expect(page.locator("#chat-input")).toBeEnabled();
  // (b) Stop is a reachable, prominent control while the run is live
  await expect(page.locator("#stopBtn")).toBeVisible();
  // (c) Send has relabeled to "Redirect" so the mid-run action is discoverable
  await expect(page.locator("#chat-send")).toHaveText("Redirect");

  // the first run's step actually rendered — it was genuinely mid-flight (not just "about to start")
  await expect(page.locator("#trail .step").first()).toBeVisible();

  // (d) type a NEW objective and Send → REDIRECT: abort the hanging run, start a fresh one
  await page.fill("#chat-input", "investigate payments.evil.com");
  await page.click("#chat-send");

  // the redirecting aside names the new direction; the old "Run stopped." noise never appears
  await expect(page.locator("#chat-messages")).toContainText("redirecting");
  await expect(page.locator("#chat-messages")).toContainText("payments.evil.com");
  await expect(page.locator("#chat-messages")).not.toContainText("Run stopped.");

  // The first run can ONLY end via abort (its 2nd turn hangs on the AbortSignal), so a SECOND run
  // completing at all proves the interrupt fired. runEvents tracks the CURRENT run — assert it is now the
  // redirect target and it finalized. Both objective bubbles are in the transcript (one continuous convo).
  await expect
    .poll(() => page.evaluate(() => (window as any).__kipi.runEvents().objective))
    .toBe("payments.evil.com");
  await expect
    .poll(() => page.evaluate(() => (window as any).__kipi.runEvents().terminal))
    .toBe("run_finalized");
  await expect(page.locator("#chat-messages")).toContainText("investigate evil.com");
  await expect(page.locator("#chat-messages")).toContainText("investigate payments.evil.com");

  // the redirect run settles, and the composer resets to Send
  await expect(page.locator("#chat-busy")).toBeHidden({ timeout: 10_000 });
  await expect(page.locator("#chat-send")).toHaveText("Send");

  // belts: no key leak anywhere the redirect touched, no real Anthropic egress (the wire is scripted)
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(KEY);
  expect(external.filter((u) => u.includes("anthropic"))).toEqual([]);
});
