import { test, expect, type Page } from "@playwright/test";

// PRD cytoscape-graph cyg-smoke (interactive): the INTERACTIVE cytoscape graph in a real
// browser, driven by the scripted expand seam (injected fetch — no key, no network). Migrated
// from the own-SVG proof with the SAME guarantees on the cytoscape surface: grow WITHOUT
// re-pop (D1: existing model positions + viewport unchanged), finding<->finding cross-link
// dedup, real-mouse drag (moves only the dragged node, no node card) + wheel zoom (D6), no
// unexpected network (D2), no key leak, XSS-safe entity value (D9).

const KEY = "sk-ant-scripted-test"; // the dummy key runScriptedInvestigation/expandNode set

const INITIAL_TURNS = [
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
      {
        type: "text",
        text:
          "done\n```json\n{\"findings\":[" +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"Jane Roe","entity_type":"person","confidence":"high"}' +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

// expand findings: a NEW ip, the EXISTING Jane (cross-link), an XSS payload, and a key echo.
const EXPAND_TURNS = [
  {
    content: [
      {
        type: "text",
        text:
          "done\n```json\n{\"findings\":[" +
          '{"entity":"203.0.113.9","entity_type":"ip","confidence":"low"},' +
          '{"entity":"Jane Roe","entity_type":"person","confidence":"low"},' +
          '{"entity":"<img src=oops>","entity_type":"person","confidence":"low"},' +
          `{"entity":"leak ${KEY}","entity_type":"person","confidence":"low"}` +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
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

async function settle(page: Page, ms = 900): Promise<void> { await page.waitForTimeout(ms); }

async function renderInitial(page: Page): Promise<{ ipId: string; janeId: string }> {
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("Investigate example.com", turns), INITIAL_TURNS);
  await settle(page); // let the cose layout settle so model positions are final
  const model = await page.evaluate(() => (window as any).__kipi.graphModel());
  const ip = model.nodes.find((n: any) => n.entityType === "ip");
  const jane = model.nodes.find((n: any) => n.label === "Jane Roe");
  return { ipId: ip.id, janeId: jane.id };
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); }); // D2: before goto
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
});

test("expand GROWS the graph without re-popping; existing entity becomes a cross-edge, not a duplicate", async ({ page }) => {
  const { ipId, janeId } = await renderInitial(page);
  expect((await page.evaluate(() => (window as any).__kipi.cyCounts())).nodes).toBe(3); // kweb-live-graph keep-all: ip + Jane + the live query target example.com (kept; worthiness filter drops noise twins)

  const beforePos = await page.evaluate(() => (window as any).__kipi.graphPositions());
  const beforeVp = await page.evaluate(() => (window as any).__kipi.cyViewport());

  await page.evaluate(({ id, turns }) => (window as any).__kipi.expandNode(id, turns), { id: ipId, turns: EXPAND_TURNS });
  await settle(page, 500);

  // grew: +203.0.113.9, +<img src=oops>, +leak [REDACTED] (Jane deduped, no new node). Base is now 3
  // (ip + Jane + the live target example.com — kweb-live-graph keep-all) so 3 + 3 = 6 nodes (no objective hub).
  expect((await page.evaluate(() => (window as any).__kipi.cyCounts())).nodes).toBe(6);
  const model = await page.evaluate(() => (window as any).__kipi.graphModel());
  expect(model.nodes.filter((n: any) => n.label === "Jane Roe").length).toBe(1); // cross-link, not a dup

  // D1/codex-6: every PRE-EXISTING node holds its exact model position AND the viewport
  // (zoom/pan) is unchanged — the graph grew in place, it did not re-pop.
  const afterPos = await page.evaluate(() => (window as any).__kipi.graphPositions());
  for (const id of Object.keys(beforePos)) {
    expect(afterPos[id], `node ${id} must not move on grow`).toEqual(beforePos[id]);
  }
  expect(await page.evaluate(() => (window as any).__kipi.cyViewport())).toEqual(beforeVp);

  // the cross-edge (ip -> Jane) now exists in the model
  expect(model.edges.some((e: any) => e.from === ipId && e.to === janeId)).toBe(true);
});

test("wheel zoom changes the viewport; a node drag moves only that node and does NOT open the node card", async ({ page }) => {
  const { ipId, janeId } = await renderInitial(page);
  // sp-77a52e2c: no objective hub anymore — use Jane (another non-dragged entity node) for the held-position check.
  const otherId = janeId;
  const box = (await page.locator("#cy").boundingBox())!;

  // wheel zoom over the canvas changes the viewport zoom (proves canvas events reach cytoscape).
  // Dispatch in-page (a cancelable WheelEvent on the element at the point) — cytoscape's wheel
  // handler reads deltaY + the cursor position to zoom about the pointer.
  const zoomBefore = (await page.evaluate(() => (window as any).__kipi.cyViewport())).zoom;
  await page.evaluate(({ cx, cy }) => {
    const el = document.elementFromPoint(cx, cy) || document.getElementById("cy")!;
    el.dispatchEvent(new WheelEvent("wheel", { deltaY: -240, clientX: cx, clientY: cy, bubbles: true, cancelable: true }));
  }, { cx: box.x + box.width / 2, cy: box.y + box.height / 2 });
  await settle(page, 200);
  const zoomAfter = (await page.evaluate(() => (window as any).__kipi.cyViewport())).zoom;
  expect(zoomAfter).not.toBe(zoomBefore);

  // The graph surface sits below the fold (after the trail/findings) - scroll it INTO VIEW so
  // real OS-level mouse events land on the canvas. Then center the camera on the ip node so it
  // is on-canvas, and drive a REAL CDP mouse drag. Cytoscape distinguishes a drag from a tap
  // natively, so a drag moves the node (model position changes) WITHOUT opening a node card (D6).
  await page.locator("#cy").scrollIntoViewIfNeeded();
  await page.evaluate((id) => (window as any).__kipi.cyCenterOn(id), ipId);
  await settle(page, 200);
  const dragBox = (await page.locator("#cy").boundingBox())!;
  const before = await page.evaluate(() => (window as any).__kipi.graphPositions());
  const rp = (await page.evaluate((id) => (window as any).__kipi.cyRenderedPos(id), ipId))!;
  const sx = dragBox.x + rp.x, sy = dragBox.y + rp.y;
  await page.mouse.move(sx, sy);
  await page.mouse.down();
  await page.mouse.move(sx + 30, sy + 24, { steps: 5 });
  await page.mouse.move(sx + 75, sy + 60, { steps: 10 });
  await page.mouse.up();
  await settle(page, 300);

  const after = await page.evaluate(() => (window as any).__kipi.graphPositions());
  expect(after[ipId]).not.toEqual(before[ipId]); // the dragged node moved
  expect(after[otherId]).toEqual(before[otherId]); // a non-dragged node held its position
  await expect(page.locator(".node-card")).toHaveCount(0); // a drag is not a tap, so no node card
});

test("no unexpected network, no key leak (body/graphModel/getCase), XSS-safe label on expand", async ({ page }) => {
  const { ipId } = await renderInitial(page);
  await page.evaluate(({ id, turns }) => (window as any).__kipi.expandNode(id, turns), { id: ipId, turns: EXPAND_TURNS });
  await settle(page, 400);

  expect(external).toEqual([]); // all I/O injected — nothing left the page (D2)

  // the key echoed on the expand never reaches the graph model, the body, or a run record
  const graphJson = await page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel()));
  expect(graphJson).not.toContain(KEY);
  expect(graphJson).toContain("[REDACTED]");
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(KEY);
  const stored = await page.evaluate(() => JSON.stringify((window as any).__kipi.getCase("run:93.184.216.34")));
  expect(stored).not.toContain(KEY);

  // D9/codex-7: the markup entity from the expand is literal text in the Show-full-details chat message
  // (escape-first); no injected element appears under #graph or in chat.
  const xssId = await page.evaluate(() => (window as any).__kipi.graphModel().nodes.find((n: any) => n.label === "<img src=oops>")?.id);
  expect(xssId).toBeTruthy();
  await page.evaluate((id) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === id);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, xssId);
  await expect(page.locator("#chat-messages .msg.agent").last()).toContainText("<img src=oops>");
  await expect(page.locator("#graph img")).toHaveCount(0);
  await expect(page.locator("#graph script")).toHaveCount(0);
  await expect(page.locator("#chat-messages .msg.agent img")).toHaveCount(0);
  await expect(page.locator("#chat-messages .msg.agent script")).toHaveCount(0);
});
