import { test, expect } from "@playwright/test";
import { gotoRoute } from "./_nav";
// PRD-3 p3-smoke (Playwright): prove the agent UI RENDERS in a real browser by
// driving a SCRIPTED run (injected fetch — no key, no network) through the same
// render path the Run button uses. The live model run is the user's (docs/agent-loop.md).

const TURNS = [
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
          'Done.\n```json\n{"findings":[' +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"Jane Roe","entity_type":"person","confidence":"high"}]}\n```',
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
});

test("saving a key flips the chip, then a scripted investigation renders trail/findings/leads", async ({ page }) => {
  // the real key-save path updates the status chip (the key card + chip live on /account now)
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await expect(page.locator("#keychip")).toContainText("add a key");
  await page.fill("#apikey", "sk-ant-anything");
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  const res = await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("Investigate example.com", turns), TURNS);
  expect(res.stopReason).toBe("end_turn");
  expect(res.promoted).toContain("93.184.216.34");
  expect(res.leads).toContain("Jane Roe");
  const events = await page.evaluate(() => (window as any).__kipi.runEvents());
  expect(events.types).toEqual(["run_started", "agent_step", "agent_step", "agent_observed", "agent_step", "run_finalized"]);
  expect(events.terminal).toBe("run_finalized");
  expect(JSON.stringify(events)).not.toContain("sk-ant-anything");

  // the DOM actually rendered (not just the return value)
  await expect(page.locator("#trail .step")).not.toHaveCount(0);
  // remove-chat-findings (2026-07-08): the #findings/#leads chat columns are gone. The promoted finding is
  // proven via res.promoted (above) + the GRAPH; the held lead via res.leads (above) — leads are not graphed.
  await expect.poll(() => page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel()))).toContain("93.184.216.34");
});

test("kweb-live-graph: observations grow the graph LIVE during the dig and STAY (keep-all, analyst prunes)", async ({ page }) => {
  // a scripted run RESOLVES a domain (canned dns → 93.184.216.34) but reports ZERO findings. The observed
  // entities are grown LIVE during the dig (liveGrowAdds > 0) and KEEP as real osint nodes even though
  // nothing was gated — the live-real-graph-build decision: dead-ends stay, the analyst prunes manually.
  const TURNS_EMPTY = [
    { content: [{ type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
    { content: [{ type: "text", text: 'No confirmed findings.\n```json\n{"findings":[]}\n```' }], stop_reason: "end_turn", usage: { output_tokens: 10 } },
  ];
  const res = await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("Investigate example.com", turns), TURNS_EMPTY);
  expect(res.promoted).toEqual([]); // nothing promoted at the gate
  expect(res.leads).toEqual([]); // and nothing reported as a lead
  const events = await page.evaluate(() => (window as any).__kipi.runEvents());
  expect(events.counts.agent_observed).toBeGreaterThan(0);
  expect(events.terminal).toBe("run_finalized");
  const grew = await page.evaluate(() => (window as any).__kipi.liveGrowAdds());
  expect(grew).toBeGreaterThan(0); // the dig grew the graph LIVE as observations arrived
  const model = await page.evaluate(() => (window as any).__kipi.graphModel());
  const labels = (model.nodes as { label: string }[]).map((n) => n.label);
  // keep-all: the OBSERVED cluster IP persists as a real osint node even with zero gated findings…
  expect(labels).toContain("93.184.216.34");
  // …and the worthiness filter (PRD live-graph-quality) means the canned ip-record never appears as a
  // nameserver/mailserver twin — exactly ONE node carries that value.
  expect(labels.filter((l) => l === "93.184.216.34")).toHaveLength(1);
});

test("Stop aborts an in-flight run (the agent's Stop button)", async ({ page }) => {
  // kick off a run whose first model turn hangs until the signal aborts
  await page.evaluate(() => {
    (window as any)._runP = (window as any).__kipi.runScriptedInvestigation("hang test", [{ __waitForStop: true }]);
  });
  // wait until the run has started (status set + AbortController live), then Stop
  await page.waitForFunction(() => document.getElementById("status")?.textContent?.includes("Investigating"));
  await page.click("#stopBtn");
  const res = await page.evaluate(() => (window as any)._runP);
  expect(res.stopReason).toBe("aborted");
  const events = await page.evaluate(() => (window as any).__kipi.runEvents());
  expect(events.terminal).toBe("run_aborted");
  expect(events.counts.run_aborted).toBe(1);
  expect(events.counts.run_finalized).toBe(0);
  await expect(page.locator("#status")).toContainText("aborted");
});
