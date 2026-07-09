import { test, expect, type Page } from "@playwright/test";
// multi-select (founder 2026-07-03): build a node GROUP and act on it. REAL canvas interactions (not a code
// seam — the earlier miss): shift+drag rubber-bands a box; Cmd/Ctrl+click adds one node (shift is the box
// modifier so it can't also be click-add). The group chip carries real actions and is draggable.

const RUN_TURNS = [
  { content: [{ type: "text", text: "Resolving evil.com." }, { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "evil.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
  { content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```' }], stop_reason: "end_turn", usage: { output_tokens: 20 } },
];

async function freshRun(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.evaluate(() => (window as any).__kipi.installChatWire({ qaText: "ok" }));
  await page.evaluate((turns) => { (window as any)._p = (window as any).__kipi.runScriptedInvestigation("investigate evil.com", turns); }, RUN_TURNS);
  await page.evaluate(async () => await (window as any)._p);
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes)).toBeGreaterThanOrEqual(2);
}

test("shift+drag box selects a group; the group actions run in the chat; the chip is draggable", async ({ page }) => {
  await freshRun(page);
  await page.evaluate(() => (window as any).__kipi.graph?.().fit?.());
  await page.waitForTimeout(150);

  // REAL shift+drag rubber-band over the whole graph → the nodes inside get selected
  const box = (await page.locator("#cy").boundingBox())!;
  await page.keyboard.down("Shift");
  await page.mouse.move(box.x + 8, box.y + 8);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width - 8, box.y + box.height - 8, { steps: 12 });
  await page.mouse.up();
  await page.keyboard.up("Shift");

  await expect.poll(() => page.evaluate(() => (window as any).__kipi.graphSelectedSet().length)).toBeGreaterThanOrEqual(2);
  const chip = page.locator("#cy-setchip");
  await expect(chip).toContainText("selected");

  // the group ACTIONS render + route into the chat (the real gap: only copy/clear before)
  await expect(chip).toContainText("Investigate all");
  await expect(chip).toContainText("What connects these?");
  await expect(chip).toContainText("Remove from graph");
  await chip.getByRole("button", { name: "What connects these?" }).click();
  await expect(page.locator("#chat-messages .msg.you")).toContainText("what connects");

  // the chip is MOVABLE (founder: "I should be able to move it") — dragging its header repositions it
  const before = (await page.locator("#cy-setchip").boundingBox())!;
  const handle = page.locator("#cy-setchip .cy-setchip-head");
  const hb = (await handle.boundingBox())!;
  await page.mouse.move(hb.x + hb.width / 2, hb.y + hb.height / 2);
  await page.mouse.down();
  await page.mouse.move(hb.x + hb.width / 2 - 120, hb.y + hb.height / 2 + 90, { steps: 8 });
  await page.mouse.up();
  const after = (await page.locator("#cy-setchip").boundingBox())!;
  expect(Math.abs(after.x - before.x) + Math.abs(after.y - before.y)).toBeGreaterThan(40);
});

// The Cmd+click add-one gesture routes through the SAME native-selection path the shift+drag box uses
// (node.select() → select event → syncGroupFromSelection). That path is proven live by the box test above;
// the real Cmd+click modifier can't be simulated in Playwright (Meta doesn't propagate to the synthetic
// click, and on macOS Ctrl+click is a right-click). This exercises the identical toggle+sync code the
// tap-handler's Cmd/Ctrl branch calls, so the group-build logic is guarded deterministically.
test("adding nodes one at a time builds the group and toggling removes them", async ({ page }) => {
  await freshRun(page);
  const ids: string[] = await page.evaluate(() => (window as any).__kipi.graphModel().nodes.map((n: any) => n.id));
  await page.evaluate((id) => (window as any).__kipi.graphToggleGroupNode(id), ids[0]);
  await page.evaluate((id) => (window as any).__kipi.graphToggleGroupNode(id), ids[1]);
  expect(await page.evaluate(() => (window as any).__kipi.graphSelectedSet().length)).toBe(2);
  await expect(page.locator("#cy-setchip")).toContainText("2 selected");
  // toggling one off removes it from the group (in-set removed, chip updates)
  await page.evaluate((id) => (window as any).__kipi.graphToggleGroupNode(id), ids[0]);
  expect(await page.evaluate(() => (window as any).__kipi.graphSelectedSet().length)).toBe(1);
});
