import { test, expect, type Page } from "@playwright/test";

// gh-smoke (parity G1): prove the WHOLE-CASE graph HYDRATES on a fresh split-view mount. Two
// scripted runs (injected fetch — no key, no network) land distinct findings plus one SHARED
// entity; a lock+unlock forces a fresh mount; the graph must come back NON-EMPTY with both runs'
// nodes (the headline regression was a blank canvas on reload). A shared entity is ONE node
// (dedup), a third run GROWS the graph in place, and no secret (master password / Anthropic key)
// ever reaches the body, the graph, or __kipi.graphModel(); no off-allowlist egress at load OR run.

const MASTER = "MASTER-pw-7788"; // the vault password — must never appear in the DOM / graph
const KEY = "sk-ant-scripted-test"; // runScriptedInvestigation sets this dummy key when the vault has none

// Each run does a dns_lookup (the canned OSINT returns 93.184.216.34, so that ip PROMOTES and is the
// SHARED node) plus one run-specific person (no infra -> a lead node). Run 1 also echoes the key.
function turns(personLabel: string, echoKey = false): unknown[] {
  const findings =
    `{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},` +
    `{"entity":"${personLabel}","entity_type":"person","confidence":"high"}` +
    (echoKey ? `,{"entity":"leak ${KEY}","entity_type":"person","confidence":"high"}` : "");
  return [
    {
      content: [
        { type: "text", text: `Resolving for ${personLabel}.` },
        { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "example.com" } },
      ],
      stop_reason: "tool_use",
      usage: { output_tokens: 10 },
    },
    {
      content: [{ type: "text", text: 'done\n```json\n{"findings":[' + findings + "]}\n```" }],
      stop_reason: "end_turn",
      usage: { output_tokens: 20 },
    },
  ];
}

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

function labels(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const m = (window as any).__kipi.graphModel();
    return (m?.nodes ?? []).map((n: any) => n.label as string);
  });
}
function emptyHidden(page: Page): Promise<boolean> {
  return page.evaluate(() => !!(document.getElementById("cy-empty") as HTMLElement | null)?.hidden);
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

test("two seeded runs hydrate the whole-case graph on a fresh mount; shared entity dedups; a third run grows it", async ({ page }) => {
  // two runs with distinct people + one shared ip; run 1 echoes the key into a finding
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("Investigate one.example.com", t), turns("Alice One", true));
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("Investigate two.example.com", t), turns("Bob Two"));

  // force a FRESH split-view mount (the reload path): lock, then unlock
  await page.evaluate(() => (window as any).__kipi.lock());
  await page.evaluate((pw) => (window as any).__kipi.unlock(pw), MASTER);
  await page.waitForFunction(() => !!(window as any).__kipi.graphModel()); // hydrate ran on mount

  // NON-EMPTY on mount: the empty hint is hidden and both runs' nodes are present
  expect(await emptyHidden(page)).toBe(true);
  const afterMount = await labels(page);
  expect(afterMount).toContain("Alice One"); // run 1
  expect(afterMount).toContain("Bob Two");   // run 2
  expect(afterMount).toContain("93.184.216.34"); // the promoted, shared infra node
  // the shared ip is ONE node across both runs (dedup, not a duplicate per run)
  expect(afterMount.filter((l) => l === "93.184.216.34")).toHaveLength(1);

  const countBefore = afterMount.length;
  await page.waitForTimeout(1400); // let the cose layout settle + fit so the deliverable shot is centered, not mid-layout
  await page.screenshot({ path: "test-results/kipi-graph-hydration.png", fullPage: true });

  // a third run GROWS the hydrated graph in place: a new node appears, existing ones survive,
  // the shared ip is still ONE node
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("Investigate three.example.com", t), turns("Carol Three"));
  const afterGrow = await labels(page);
  expect(afterGrow).toContain("Carol Three");
  expect(afterGrow).toContain("Alice One"); // run 1 node survived the grow (no re-pop wipe)
  expect(afterGrow).toContain("Bob Two");
  expect(afterGrow.filter((l) => l === "93.184.216.34")).toHaveLength(1);
  expect(afterGrow.length).toBeGreaterThan(countBefore);

  // no secret anywhere: the master password and the Anthropic key are absent from the body, the
  // graph model, and the __kipi bridge
  const graphJson = await page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel()));
  expect(graphJson).not.toContain(MASTER);
  expect(graphJson).not.toContain(KEY);
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(MASTER);
  expect(body).not.toContain(KEY);

  // no off-allowlist egress at load OR run time (everything was injected)
  expect(external).toEqual([]);
});
