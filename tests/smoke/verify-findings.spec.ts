import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-findings smoke (the load-bearing render gate, PRD review #9 — the parity gate is manifest/AST only
// and CANNOT see the render). Drives a scripted agent run (offline, zero egress, no key in the DOM) with
// a tool step + a findings block, navigates to /runs, expands the run, and proves the FULL Findings-view
// depth: the confidence pill with the CORRECT color CLASS (high→role-infra), the claim summary, the
// Discovered-assets rollup, the deterministic Next-moves pivots, and the Trail|Findings toggle hides the
// trail (default Findings). MANDATORY NEGATIVE assertion: the OLD one-line dot row (.run-finding-line) is
// GONE — a hollow flip can't pass. Live-verified by a Read screenshot.

const APIKEY = "sk-ant-FINDINGS-smoke-7777"; // must never appear in the DOM
const OBJECTIVE = "Investigate findings.example.com"; // clean (no key) so the run is not taint-dropped

// A tool_use step (dns_lookup on example.com → canned 93.184.216.34, an INFRA corroboration), then an
// end_turn findings block: the IP finding carries confidence:"high" + a claim and PROMOTES (grade A,
// infra type + infra source) → on-graph + the role-infra pill; a low-confidence, uncorroborated person
// finding stays a LEAD (grade D) and lands as an "investigate now" pivot (gate-faithful run findings
// always carry a grade — the blocked column is exercised by the runtrail.test.ts unit).
const CLAIM = "DNS resolved this A record via dns_lookup — a non-fakeable infra fact.";
const TURNS = [
  {
    content: [
      { type: "text", text: "Resolving findings.example.com." },
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
          `{"entity":"93.184.216.34","entity_type":"ip","confidence":"high","claim":"${CLAIM}"},` +
          '{"entity":"Jane Doe","entity_type":"person","confidence":"low","claim":"Name-only match, no crosslink."}' +
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

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}

test("runs: the Findings view renders the rich row (pill color + claim summary) + asset rollup + pivots + Trail|Findings toggle; the old dot row is GONE; no key, no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) Anthropic key via the real keys card (on the /account page).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");

  // (2) Back to the graph home, run the scripted investigation (real loop, scripted Anthropic + canned OSINT).
  await page.click('a[data-route="/"]');
  await page.evaluate(({ objective, turns }) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation(objective, turns), { objective: OBJECTIVE, turns: TURNS });

  // (3) Open /runs and expand the run card.
  await page.evaluate((r) => { location.hash = "#" + r; }, "/runs"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".pg-title")).toHaveText("Runs & findings");
  await expect(page.locator(".run-card")).toContainText("findings.example.com");
  await page.locator(".run-head").first().click();

  // (4) RICH ROW: the confidence pill with the CORRECT color class (high → role-infra), the entity title.
  const pill = page.locator(".run-finding .role-pill", { hasText: "high" }).first();
  await expect(pill).toBeVisible();
  await expect(pill).toHaveClass(/role-infra/); // EXACT color map: high → role-infra (runs.html:267-268)
  await expect(page.locator(".run-finding-name").first()).toContainText("93.184.216.34");

  // (4b) the low-confidence person finding renders its pill as role-source (low → role-source).
  await expect(page.locator(".run-finding .role-pill", { hasText: "low" }).first()).toHaveClass(/role-source/);

  // (5) CLAIM SUMMARY rendered via the inline markdown (escape-first), not absent.
  await expect(page.locator(".run-finding-summary").first()).toContainText("non-fakeable infra fact");

  // (6) ON-GRAPH state for the promoted IP (the present-and-functional analog of the signed-out Save button).
  await expect(page.locator(".run-finding-state.on-graph").first()).toContainText("on graph");

  // (7) DISCOVERED-ASSETS rollup: the IP, found via dns_lookup, on-graph.
  await expect(page.locator(".run-section-head", { hasText: "Discovered assets" })).toBeVisible();
  const asset = page.locator(".run-asset", { hasText: "93.184.216.34" }).first();
  await expect(asset).toBeVisible();
  await expect(asset).toContainText("dns_lookup");
  await expect(asset.locator(".run-asset-badge.on-graph")).toBeVisible();

  // (8) NEXT-MOVES: the held person lead is ranked as an entity to chase next (a single honest
  // "chase to corroborate" list — the server's reachability now/blocked split is a signed divergence).
  await expect(page.locator(".run-section-head", { hasText: "Next moves · chase to corroborate" })).toBeVisible();
  await expect(page.locator(".run-pivot")).toContainText("Jane Doe");

  // (9) TOGGLE: default Trail (faithful to the original /runs default) → the trail is visible; clicking
  // Findings hides it (emphasis on the findings), clicking Trail reveals it again. The findings list (4-8)
  // renders in BOTH views — only the trail toggles.
  await expect(page.locator(".run-trail-section")).toBeVisible();
  await expect(page.locator(".trail-tool").first()).toContainText("dns_lookup"); // the real step trail
  await page.locator(".run-view-btn", { hasText: "Findings" }).first().click();
  await expect(page.locator(".run-trail-section")).toBeHidden();
  await page.locator(".run-view-btn", { hasText: "Trail" }).first().click();
  await expect(page.locator(".run-trail-section")).toBeVisible();

  // (10) MANDATORY NEGATIVE: the OLD one-line dot row is GONE (a hollow flip would still have it).
  await expect(page.locator(".run-finding-line")).toHaveCount(0);

  // (11) No key in the DOM; no off-allowlist egress (everything was scripted/canned in-browser).
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(APIKEY);
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-findings.png", fullPage: true });
});
