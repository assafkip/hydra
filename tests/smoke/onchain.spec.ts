import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// oc-smoke: the keyless on-chain tools are reachable in the agent loop. A scripted run calls the
// ens_name tool (canned ensideas resolution: vitalik.eth → its 0x wallet); the resolved wallet is a
// gate-faithful T1 entity that LANDS in the entity DB; no off-allowlist egress occurs.

const KEY = "sk-ant-OC-smoke-9";
const ENS_ADDR = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";

// turn 1: the model calls ens_name on vitalik.eth. turn 2: it reports the resolved wallet as a finding.
const TURNS = [
  {
    content: [
      { type: "text", text: "Resolving the ENS name to its owning wallet." },
      { type: "tool_use", id: "t1", name: "ens_name", input: { name: "vitalik.eth" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text: 'Done.\n```json\n{"findings":[{"entity":"' + ENS_ADDR + '","entity_type":"wallet","confidence":"high"}]}\n```',
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 12 },
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

test("on-chain ens_name tool lands the resolved wallet through the gate; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  await freshVault(page);
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  const result = await page.evaluate(
    ([turns]) => (window as any).__kipi.runScriptedInvestigation("dig vitalik.eth", turns),
    [TURNS] as const,
  );
  // the resolved 0x wallet promoted (T1 on-chain, one authoritative source)
  expect(result.promoted).toContain(ENS_ADDR);

  // the wallet landed in the client entity DB
  const dbJson = await page.evaluate(() => JSON.stringify((window as unknown as { __kipi: { entityDb(): unknown } }).__kipi.entityDb()));
  expect(dbJson).toContain(ENS_ADDR);

  // the Anthropic key never leaks; no off-allowlist egress (the canned fetch handled the tool call)
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(KEY);
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-onchain.png", fullPage: true });
});
