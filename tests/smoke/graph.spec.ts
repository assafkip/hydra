import { test, expect, type Page } from "@playwright/test";

// PRD cytoscape-graph cyg-smoke: prove the BUNDLED Cytoscape graph renders in a real browser,
// fed by the same scripted-run path the agent UI uses (injected fetch — no key, no network).
// Migrated from the own-SVG proof to the cytoscape surface with the SAME guarantees + the
// review's hardenings: a NON-BLANK canvas (D3), the no-network listener attached BEFORE goto
// (D2), no key leak into body/graph/hook (codex-2), and XSS-safe entity values across every
// DOM chrome surface under #graph (D9). The live model run is the user's (docs/agent-loop.md).

const TEST_KEY = "sk-ant-scripted-test"; // runScriptedInvestigation sets this when the vault has none
const OBJECTIVE = `Investigate example.com ${TEST_KEY}`; // carries the key — the redactor must strip it

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
          "Done.\n```json\n{\"findings\":[" +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"Jane Roe","entity_type":"person","confidence":"high"},' +
          '{"entity":"<img src=x>","entity_type":"person","confidence":"high"},' +
          '{"entity":"<svg><script>1</script></svg>","entity_type":"person","confidence":"high"}' +
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

// D2: the listener is attached BEFORE the first navigation so a load-time CDN/vendor/font fetch
// is caught, not just run-time I/O. Reset per test.
let external: string[] = [];

test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
});

async function runScripted(page: Page): Promise<{ promoted: string[] }> {
  return page.evaluate(({ objective, turns }) => (window as any).__kipi.runScriptedInvestigation(objective, turns), { objective: OBJECTIVE, turns: TURNS });
}
function findingId(page: Page, label: string): Promise<string | null> {
  return page.evaluate((l) => {
    const m = (window as any).__kipi.graphModel();
    const n = m?.nodes?.find((x: any) => x.label === l);
    return n ? n.id : null;
  }, label);
}

test("a scripted run renders the cytoscape graph (non-blank canvas) with the expected node/edge counts", async ({ page }) => {
  const res = await runScripted(page);
  expect(res.promoted).toContain("93.184.216.34");

  // counts via the cytoscape model: network-only first paint (NO objective hub — sp-77a52e2c).
  // kweb-live-graph keep-all: the dig grows its observations live + KEEPS them. 1 promoted IP + 3 person
  // leads + the live query TARGET (example.com, a real domain) = 5 nodes; the worthiness filter (PRD
  // live-graph-quality) drops tooling-noise twins so no junk inflates this. EDGES = just the ONE real
  // typed relationship the tool established (example.com resolves_to ip). Co-occurrence is NOT an edge
  // (founder 2026-06-24, no-cooccurrence-edges) — the old C(4,2)=6 co_occurs clique is gone.
  const counts = await page.evaluate(() => (window as any).__kipi.cyCounts());
  expect(counts).toEqual({ nodes: 5, edges: 1 });

  // D3: a real, non-blank render — the surface is sized, a cytoscape <canvas> exists, and at
  // least one canvas has painted (non-transparent) pixels. This is the §6 "actually renders,
  // not a blank canvas" gate that a model-count alone cannot prove.
  const dims = await page.evaluate(() => {
    const el = document.getElementById("cy")!;
    return { w: el.clientWidth, h: el.clientHeight, canvases: el.querySelectorAll("canvas").length };
  });
  expect(dims.w).toBeGreaterThan(0);
  expect(dims.h).toBeGreaterThan(0);
  expect(dims.canvases).toBeGreaterThanOrEqual(1);

  const nonBlank = await page.evaluate(() => {
    for (const c of Array.from(document.querySelectorAll("#cy canvas")) as HTMLCanvasElement[]) {
      if (!c.width || !c.height) continue;
      const ctx = c.getContext("2d");
      if (!ctx) continue;
      const { data } = ctx.getImageData(0, 0, c.width, c.height);
      for (let i = 3; i < data.length; i += 4) if (data[i] !== 0) return true; // any non-transparent pixel
    }
    return false;
  });
  expect(nonBlank, "the cytoscape canvas must have painted pixels (not blank)").toBe(true);

  await page.locator("#graph").screenshot({ path: "test-results/graph-render.png" }); // visual-DoD artifact
});

test("clicking a node selects it (no card); Show full details renders the entity + gate status in the chat", async ({ page }) => {
  await runScripted(page);
  // remove-cards (founder 2026-07-03): a node click NEVER renders a card.
  await expect(page.locator(".node-card")).toHaveCount(0);

  const id = await findingId(page, "93.184.216.34");
  expect(id).toBeTruthy();
  const ok = await page.evaluate((nid) => (window as any).__kipi.selectNode(nid), id);
  expect(ok).toBe(true);
  await expect(page.locator(".node-card")).toHaveCount(0); // still no card after selecting

  // the detail comes via the right-click "Show full details" → a chat MESSAGE (no card)
  await page.evaluate((nid) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === nid);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, id);
  const detail = page.locator("#chat-messages .msg.agent").last();
  await expect(detail).toContainText("93.184.216.34");
  await expect(detail).toContainText("promoted");
  await expect(page.locator(".node-card")).toHaveCount(0);
});

test("no unexpected network, no key leak (body/graph/hook), XSS-safe across every #graph chrome surface", async ({ page }) => {
  await runScripted(page);

  // D2/codex-6: the scripted run injected all I/O — nothing left the page, at load OR run time.
  expect(external).toEqual([]);

  // codex-2: the key (echoed in the objective) is redacted out of the graph model + hook + page.
  const graphJson = await page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel()));
  expect(graphJson).not.toContain(TEST_KEY);
  expect(graphJson).toContain("[REDACTED]"); // the objective FIELD label (kept on the model, no longer a node) was redacted
  const body = await page.evaluate(() => document.body.textContent || "");
  expect(body).not.toContain(TEST_KEY);

  // D9/codex-7/codex-9: the HTML-payload node's value renders as LITERAL TEXT in the Show-full-details chat
  // message (mdLiteral + escape-first markdown); no injected element appears anywhere under #graph or in chat.
  const xssId = await findingId(page, "<img src=x>");
  expect(xssId).toBeTruthy();
  await page.evaluate((nid) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === nid);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, xssId);
  await expect(page.locator("#chat-messages .msg.agent").last()).toContainText("<img src=x>");
  await expect(page.locator("#graph img")).toHaveCount(0);
  await expect(page.locator("#graph script")).toHaveCount(0);
  // no injected element in the chat message either (escape-first)
  await expect(page.locator("#chat-messages .msg.agent img")).toHaveCount(0);
  await expect(page.locator("#chat-messages .msg.agent script")).toHaveCount(0);
});
