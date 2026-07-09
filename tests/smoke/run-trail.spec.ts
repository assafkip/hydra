import { test, expect } from "@playwright/test";

// r1-smoke (parity R1): prove the Runs & findings page renders the agent's REAL step trail + the
// finding->step provenance, in a real browser, fed by the scripted-run seam (injected fetch — no key,
// no network). The signature parity: a returning user can see HOW each finding was reached. Also
// guards key/master-password hygiene, XSS-safe literal rendering of a hostile entity, and zero egress.

const MASTER = "MASTER-runtrail-9182"; // the vault password — must never appear in the page
const KEY = "sk-ant-scripted-test"; // runScriptedInvestigation sets this dummy key when the vault has none
const XSS = "<img src=x onerror=alert(1)>"; // a hostile entity value — must render as literal text

const OBJECTIVE = "Investigate trail.example.com"; // clean (no key) so the run is not taint-dropped
const TURNS = [
  {
    content: [
      { type: "text", text: "Resolving trail.example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "Done.\n```json\n{\"findings\":[" +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          `{"entity":"${XSS}","entity_type":"person","confidence":"high"},` +
          `{"entity":"leak ${KEY}","entity_type":"person","confidence":"high"}` +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 30 },
  },
];

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); }); // D2: before goto
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate((pw) => (window as any).__kipi.createVault(pw), MASTER);
});

test("the Runs page renders the real step trail + finding provenance; no leak, no egress", async ({ page }) => {
  await page.evaluate(({ objective, turns }) => (window as any).__kipi.runScriptedInvestigation(objective, turns), { objective: OBJECTIVE, turns: TURNS });

  // navigate to the Runs page + expand the run card
  await page.evaluate((r) => { location.hash = "#" + r; }, "/runs"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".pg-title")).toHaveText("Runs & findings");
  await expect(page.locator(".run-card")).toContainText("trail.example.com");
  await page.locator(".run-head").first().click();

  // What it did: the real dns_lookup tool step + its emitted-entity result line
  await expect(page.locator(".run-trail")).toBeVisible();
  await expect(page.locator(".trail-tool").first()).toContainText("dns_lookup");
  await expect(page.locator(".trail-result")).toContainText("93.184.216.34");

  // What it found: the promoted IP finding shows the step that produced it
  await expect(page.locator(".run-finding-prov").first()).toContainText("from step");
  // and the bottom line is rendered
  await expect(page.locator(".run-bottomline-text")).toContainText("promoted");

  // XSS: the hostile entity value rendered as literal text — NO injected element under the page body
  await expect(page.locator(".pg-body")).toContainText(XSS); // textContent equals the literal markup
  await expect(page.locator(".pg-body img")).toHaveCount(0);
  await expect(page.locator(".pg-body script")).toHaveCount(0);

  // No secret in the page: neither the master password nor the Anthropic key (the key-echo finding is redacted)
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(MASTER);
  expect(body).not.toContain(KEY);

  // No off-allowlist egress at load OR run time (everything was injected)
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-run-trail.png", fullPage: true });
});
