import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// PRD cytoscape-graph-home-splitview hsv-smoke: prove the home is the graph-dominant split-view
// (graph fills + cytoscape-initialized ON UNLOCK before any run — D1), with the run-path ids each
// present exactly once (D5), a collapsible dock that persists + keeps the graph sized/painted on
// toggle (D3/D9), the locked view carrying NO graph/dock DOM (D8), no unexpected egress (D2), and
// the Anthropic key never leaking into the DOM (D7). The live run is the user's.

const KEY = "sk-ant-" + "splitview-secret-key-XYZ"; // a distinctive key for the D7 leak sweep
// The placeholder run controls were replaced by the cloned chat dock (cd-ui): the objective input
// + Run button became #chat-input + #chat-send; the run-output ids (#trail/#brief)
// + Stop + brief affordances are RETAINED by the chat, each exactly once (D7). remove-chat-findings
// (2026-07-08): #findings/#leads dropped — those results live on the graph + /runs now, not in the chat.
const RUN_PATH_IDS = ["#chat-input", "#chat-send", "#stopBtn", "#briefBtn", "#dlBriefBtn", "#trail", "#brief", "#graph", "#cy"];

const TURNS = [
  { content: [{ type: "text", text: "Resolving." }, { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
  { content: [{ type: "text", text: "Done.\n```json\n{\"findings\":[{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}]}\n```" }], stop_reason: "end_turn", usage: { output_tokens: 20 } },
];

function isExternal(url: string): boolean {
  try { const u = new URL(url); return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1"; }
  catch { return false; }
}
async function cyDims(page: Page) {
  return page.evaluate(() => { const el = document.getElementById("cy"); return el ? { w: el.clientWidth, h: el.clientHeight } : { w: 0, h: 0 }; });
}
async function canvasPainted(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    for (const c of Array.from(document.querySelectorAll("#cy canvas")) as HTMLCanvasElement[]) {
      if (!c.width || !c.height) continue;
      const ctx = c.getContext("2d"); if (!ctx) continue;
      const { data } = ctx.getImageData(0, 0, c.width, c.height);
      for (let i = 3; i < data.length; i += 4) if (data[i] !== 0) return true;
    }
    return false;
  });
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); }); // D2: before goto
  // Each test gets a fresh context, so sessionStorage starts empty -> the dock defaults OPEN (D9).
  // The persistence test toggles kipiDockOpen='0' and relies on it surviving a reload (same tab).
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
});

test("on unlock the graph fills + is sized before any run; run-path ids are single-instance; locked view has no graph/dock", async ({ page }) => {
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));

  // D1: the graph surface is visible + sized immediately after unlock, before any run
  await expect(page.locator("#graph")).toBeVisible();
  const dims = await cyDims(page);
  expect(dims.w).toBeGreaterThan(0);
  expect(dims.h).toBeGreaterThan(0);
  await expect(page.locator("#cy-empty")).toBeVisible(); // empty-state hint until a run

  // D5: each run-path id exists exactly once (the old Investigate card was MOVED, not duplicated)
  for (const sel of RUN_PATH_IDS) await expect(page.locator(sel)).toHaveCount(1);
  await expect(page.locator(".dock-bar")).toHaveCount(1);

  // D8: locking returns to the centered view with NO graph/dock DOM present. The lock affordance is the
  // real vault lock (lock() re-renders to the login gate) — there is no #lockBtn on the graph home.
  await page.evaluate(() => (window as any).__kipi.lock());
  await expect(page.locator("#graph")).toHaveCount(0);
  await expect(page.locator(".dock")).toHaveCount(0);

  expect(external).toEqual([]); // D2
});

test("dock toggle persists across reload and keeps the graph sized + painted; a dock run renders; key never leaks", async ({ page }) => {
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));

  // D7: save a distinctive key via the REAL #apikey path (the input is cleared after save)
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.locator("#saveKeyBtn").click();
  await expect(page.locator("#keychip")).toHaveText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  // a scripted run from the dock's controls populates the trail/findings + the cytoscape graph
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("Investigate example.com", turns), TURNS);
  await page.waitForTimeout(900);
  await expect(page.locator("#trail")).toContainText("dns_lookup");
  // remove-chat-findings (2026-07-08): findings prove via the graph growing, not the removed #findings column.
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes)).toBe(2); // objective + ip
  expect(await canvasPainted(page)).toBe(true);

  // D3: toggle the dock CLOSED then OPEN — the graph stays sized + painted in each state
  await page.locator("#dockToggle").click();
  await expect(page.locator("#dockBody")).toBeHidden();
  await page.waitForTimeout(300);
  expect((await cyDims(page)).h).toBeGreaterThan(0);
  expect(await canvasPainted(page)).toBe(true);
  await page.locator(".chat-reopen").click();
  await expect(page.locator("#dockBody")).toBeVisible();
  await page.waitForTimeout(300);
  expect(await canvasPainted(page)).toBe(true);

  // D9/D3: collapse, reload, unlock — the stored kipiDockOpen=0 is applied (dock stays collapsed)
  await page.locator("#dockToggle").click();
  await expect(page.locator("#dockBody")).toBeHidden();
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.unlock("pw"));
  await expect(page.locator("#graph")).toBeVisible();
  await expect(page.locator("#dockBody")).toBeHidden(); // persisted collapsed state

  // D7: the key is absent from every DOM surface, the graph model, and the cleared input
  const innerHTML = await page.evaluate(() => document.documentElement.innerHTML);
  expect(innerHTML).not.toContain(KEY);
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(KEY);
  const graphJson = await page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel()));
  expect(graphJson).not.toContain(KEY);
  expect(external).toEqual([]); // D2
});
