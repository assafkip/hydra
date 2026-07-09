import { test, expect, type Page } from "@playwright/test";

// cg-network (PRD prd-case-graph-2026-06-22): the home/case graph is an entity↔entity NETWORK with
// NO objective hub and NO star spokes — the original api_graph shape (proven by the FIFA real-case
// model diff). This smoke drives the REAL app and asserts, on a live render:
//   1. after a fresh mount, graphModelForCase has ZERO objective nodes (the network-only contract);
//   2. a run-complete grow LANDS the run's new nodes on the case graph (the silent-drop guard);
//   3. a one-hop expand ATTACHES its new neighbor to the expanded entity.
// It is the live acceptance for the no-objective-hub change. Topology + role/shape parity is gated by
// the deterministic model diff (investigations/parity_review/fifa_model_diff.py); intake edges are
// CARVED OUT per the D1 graph carve-out (founder-blessed 2026-06-24) — D2 emits zero intake edges by
// design, gated separately by tests/agent/d2-clump-repro.test.ts (ingest edges==0, no objective hub).

const MASTER = "MASTER-pw-cg-1";
const KEY = "sk-ant-scripted-test"; // the dummy key the scripted seam sets when the vault has none

// each run: a dns_lookup whose canned result PROMOTES 93.184.216.34 (the SHARED ip) + one
// run-specific person (a lead). The two entities surfaced together → they co-occur (a network edge).
function turns(personLabel: string): unknown[] {
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
      content: [{
        type: "text",
        text:
          'done\n```json\n{"findings":[' +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          `{"entity":"${personLabel}","entity_type":"person","confidence":"high"}` +
          "]}\n```",
      }],
      stop_reason: "end_turn",
      usage: { output_tokens: 20 },
    },
  ];
}

// an expand off the ip: a NEW ip neighbor (low confidence → a lead node) attached to the source.
const EXPAND_TURNS = [
  {
    content: [{
      type: "text",
      text:
        'done\n```json\n{"findings":[' +
        '{"entity":"203.0.113.9","entity_type":"ip","confidence":"low"}' +
        "]}\n```",
    }],
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

function model(page: Page): Promise<{ nodes: { id: string; label: string; kind: string; entityType?: string }[]; edges: { from: string; to: string; kind: string }[] }> {
  return page.evaluate(() => (window as any).__kipi.graphModel());
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate((pw) => (window as any).__kipi.createVault(pw), MASTER);
});

test("case graph is a network with NO objective hub; a run-complete grow lands findings; expand attaches a neighbor", async ({ page }) => {
  // two scripted runs (shared ip), then a fresh mount so graphModelForCase builds the case graph
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("Investigate one.example.com", t), turns("Alice One"));
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("Investigate two.example.com", t), turns("Bob Two"));
  await page.evaluate(() => (window as any).__kipi.lock());
  await page.evaluate((pw) => (window as any).__kipi.unlock(pw), MASTER);
  await page.waitForFunction(() => !!(window as any).__kipi.graphModel());

  // 1) NETWORK-ONLY: the mounted case graph has zero objective nodes and no spoke-kind edges
  const mounted = await model(page);
  expect(mounted.nodes.some((n) => n.kind === "objective")).toBe(false); // the cg-network contract
  expect(mounted.edges.every((e) => e.kind !== "promoted" && e.kind !== "lead")).toBe(true); // no hub spokes
  // both runs' entities + the shared ip (deduped) are present — nothing dropped on hydrate
  expect(mounted.nodes.map((n) => n.label)).toEqual(expect.arrayContaining(["Alice One", "Bob Two", "93.184.216.34"]));
  expect(mounted.nodes.filter((n) => n.label === "93.184.216.34")).toHaveLength(1);
  // founder 2026-06-24 (no-cooccurrence-edges): the shared ip co-occurs with each run's person, but
  // co-occurrence is NOT a relationship — it draws no edge. Until a real link/expansion connects it (step
  // 3 below attaches a neighbor via expandNode), the ip carries no co-occurrence edge.
  const ipId = mounted.nodes.find((n) => n.label === "93.184.216.34")!.id;
  expect(mounted.edges.some((e) => e.from === ipId || e.to === ipId)).toBe(false);

  // 2) GROW LANDS FINDINGS: a third run's new node appears on the case graph (silent-drop guard)
  const before = mounted.nodes.length;
  await page.evaluate((t) => (window as any).__kipi.runScriptedInvestigation("Investigate three.example.com", t), turns("Carol Three"));
  const grown = await model(page);
  expect(grown.nodes.map((n) => n.label)).toContain("Carol Three"); // new finding landed
  expect(grown.nodes.map((n) => n.label)).toEqual(expect.arrayContaining(["Alice One", "Bob Two"])); // survivors
  expect(grown.nodes.some((n) => n.kind === "objective")).toBe(false); // still no hub after the grow
  expect(grown.nodes.length).toBeGreaterThan(before);

  // 3) EXPAND ATTACHES A NEIGHBOR: expand the ip one hop; the new ip neighbor attaches to it
  await page.evaluate(({ id, t }) => (window as any).__kipi.expandNode(id, t), { id: ipId, t: EXPAND_TURNS });
  await page.waitForFunction(() => ((window as any).__kipi.graphModel()?.nodes ?? []).some((n: any) => n.label === "203.0.113.9"));
  const expanded = await model(page);
  const neighbor = expanded.nodes.find((n) => n.label === "203.0.113.9")!;
  expect(neighbor).toBeTruthy(); // the one-hop finding landed
  expect(expanded.edges.some((e) => (e.from === ipId && e.to === neighbor.id) || (e.from === neighbor.id && e.to === ipId))).toBe(true); // attached to the source

  // G2a (video-review 2026-06-25): "Focus threats" is ON by default — the case graph leads with the promoted
  // threat spine, not a hairball. The low-confidence one-hop lead (203.0.113.9) is RECEDED (off-spine); toggling
  // focus OFF clears every dim (the full keep-all view is restored — founder Option 1, non-destructive).
  const offWithFocus = await page.evaluate(() => (window as any).__kipiGraph.offSpineCount());
  expect(offWithFocus).toBeGreaterThanOrEqual(1); // at least the held lead recedes while the spine stays lit
  await page.evaluate(() => (window as any).__kipiGraph.setSpineFocus(false));
  expect(await page.evaluate(() => (window as any).__kipiGraph.offSpineCount())).toBe(0); // reversible: show all
  await page.evaluate(() => (window as any).__kipiGraph.setSpineFocus(true));
  expect(await page.evaluate(() => (window as any).__kipiGraph.offSpineCount())).toBe(offWithFocus); // re-applies

  // no secret leak, no off-allowlist egress (everything injected)
  const json = JSON.stringify(expanded);
  expect(json).not.toContain(MASTER);
  expect(json).not.toContain(KEY);
  expect(external).toEqual([]);
});
