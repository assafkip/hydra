import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sec-smoke (Goal-3 FAANG auth hardening, the live proof):
//   (1) NO in-memory case-state bleed — a vault-identity change (lock) clears the prior session's
//       decrypted graph (lastGraphModel) via the applyVault chokepoint, so it cannot surface in a new
//       vault. (HIGH finding.)
//   (2) the visible Lock / Sign-out control on /account actually locks the vault (zeroes the key,
//       returns to the login gate). (MED finding + the Goal-1 "no lock control" gap.)
//   (3) the window.__kipi debug bridge is build-flag gated — present in THIS (smoke) build because
//       playwright.config sets VITE_KIPI_DEBUG=1; a stripped prod build omits it. (MED finding.)

const KEY = "sk-ant-SECSMOKE-secret-7";

// a run that lands an IP + two domains, so lastGraphModel holds a non-trivial decrypted graph.
const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving ring.example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "ring.example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          'Done.\n```json\n{"findings":[' +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"co.example.com","entity_type":"domain","confidence":"low"}' +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

async function freshKeyedVault(page: Page, pw: string) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate((p) => (window as any).__kipi.createVault(p), pw);
  await gotoRoute(page, "/account"); // ac-ui: the key card lives on /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // back to the graph home for the run
}

test("no in-memory case-state bleed: locking clears the decrypted graph (HIGH)", async ({ page }) => {
  await freshKeyedVault(page, "a-pass");

  // run → the graph builds (objective + the landed IP); lastGraphModel now holds vault A's decrypted graph
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("investigate ring.example.com", turns), RUN_TURNS);
  await expect(page.locator("#trail")).toContainText("dns_lookup", { timeout: 10_000 });
  const before = await page.evaluate(() => (window as any).__kipi.graphModel());
  expect(before?.nodes?.length ?? 0).toBeGreaterThan(0); // A's decrypted graph is in memory
  expect(JSON.stringify(before)).toContain("93.184.216.34"); // and it holds the run's entity

  // LOCK — the applyVault(null) chokepoint must clear lastGraphModel (the bleed fix). Without it, the
  // stale model survives and would surface in the next vault on a non-home route.
  await page.evaluate(() => (window as any).__kipi.lock());
  expect(await page.evaluate(() => (window as any).__kipi.graphModel())).toBeNull();

  // a fresh vault B then carries NONE of A's entities in the in-memory graph
  await page.evaluate(() => (window as any).__kipi.createVault("b-pass"));
  const afterNew = await page.evaluate(() => (window as any).__kipi.graphModel());
  const newJson = JSON.stringify(afterNew ?? {});
  expect(newJson).not.toContain("93.184.216.34");
  expect(newJson).not.toContain("co.example.com");
});

test("the Lock / Sign-out control on /account locks the vault (MED)", async ({ page }) => {
  await freshKeyedVault(page, "lock-pass");

  // the Lock control lives on /account (the session card)
  await gotoRoute(page, "/account");
  await expect(page.locator("#lockBtn")).toBeVisible();
  await page.click("#lockBtn");

  // locked → the centered login gate (no graph/dock, #lockBtn gone), and the in-memory graph is cleared
  await expect(page.locator("#graph")).toHaveCount(0);
  await expect(page.locator("#cy")).toHaveCount(0);
  await expect(page.locator("#lockBtn")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__kipi.graphModel())).toBeNull();
});

test("the window.__kipi debug bridge is build-flag gated (present in the smoke build) (MED)", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  // VITE_KIPI_DEBUG=1 (playwright.config) keeps the bridge in THIS build; a prod build omits it.
  expect(await page.evaluate(() => typeof (window as any).__kipi)).toBe("object");
});
