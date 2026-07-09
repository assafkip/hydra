import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// Signature-surface parity verification (PRD prd-kipi-web-signature-surfaces-2026-06-18).
// Proves the two VERIFY items the UI parity gate flagged are FAITHFUL against the running app,
// not just in a code read (RCA #2: "renders + a read != parity"):
//   G1 — the home graph HYDRATES from persisted runs across a re-mount (run -> navigate away ->
//        return -> the run's nodes are still there). The original /graph hydrates on every load.
//   R1 — the /runs page surfaces the FULL step trail (each tool call + result) with findings
//        attributed to the step that produced them ("from step N").
// Screenshots land in test-results/verify-*.png and are Read as the live evidence.

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving acme-pay.example and pivoting on its infra." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "acme-pay.example" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 12 },
  },
  {
    content: [
      { type: "text", text: "Checking certificate transparency for sibling hosts." },
      { type: "tool_use", id: "t2", name: "crtsh_subdomains", input: { domain: "acme-pay.example" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 12 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "Done.\n```json\n{\"findings\":[" +
          "{\"entity\":\"93.184.216.34\",\"entity_type\":\"ip\",\"confidence\":\"high\"}," +
          "{\"entity\":\"login.acme-pay.example\",\"entity_type\":\"domain\",\"confidence\":\"high\"}," +
          "{\"entity\":\"pay-acme.example\",\"entity_type\":\"domain\",\"confidence\":\"medium\"}" +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 28 },
  },
];

async function seedRun(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await page.evaluate(
    ([turns]) => (window as any).__kipi.runScriptedInvestigation("investigate acme-pay.example", turns),
    [RUN_TURNS] as const,
  );
}

test.use({ viewport: { width: 1440, height: 900 } });

// the 3 ENTITY nodes the seeded run produces (promoted ip + promoted domain + lead domain). The objective
// "acme-pay.example" is NOT a node — the home graph is an entity-only network (no objective hub, FIFA fix).
const SEEDED_ENTITIES = ["93.184.216.34", "login.acme-pay.example", "pay-acme.example"];

test("G1: home graph hydrates from persisted runs across a re-mount", async ({ page }) => {
  await seedRun(page);

  // the run record must actually be persisted (the thing graphModelForCase reads on re-mount)
  const runs = await page.evaluate(() => (window as any).__kipi.listRuns());
  expect(runs.map((r: { objective: string }) => r.objective)).toContain("investigate acme-pay.example");

  // land on home, let the graph mount + grow from the just-finished run
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await page.waitForTimeout(1000);
  const afterRun = await page.evaluate(() => (window as any).__kipi.cyCounts());

  // navigate AWAY (unmount the home graph), then BACK — the parity question is whether the
  // graph re-hydrates from persisted runs (graphModelForCase) or starts empty on each mount.
  await gotoRoute(page, "/entities");
  await page.waitForTimeout(500);
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });
  await page.waitForTimeout(1200);
  const afterReturn = await page.evaluate(() => (window as any).__kipi.cyCounts());
  const model = await page.evaluate(() => (window as any).__kipi.graphModel());

  await page.screenshot({ path: "test-results/verify-g1-home-after-return.png", fullPage: true });

  // STRENGTHENED: the re-mounted graph must be the SEEDED run's entity network (no objective hub). Every
  // seeded ENTITY is present by label, and the graph is EXACTLY the no-hub topology — 3 entity nodes + the
  // co-occurrence 3-clique (3 edges). Exact (===) so a re-introduced objective hub (4 nodes / 6 edges) FAILS.
  expect(afterRun.nodes, "graph should populate from the run on first mount").toBeGreaterThan(0);
  const labels: string[] = (model?.nodes ?? []).map((n: { label: string }) => n.label);
  const joined = labels.join(" | ");
  for (const ent of SEEDED_ENTITIES) {
    expect(joined, `re-hydrated graph must contain seeded entity ${ent} (G1)`).toContain(ent);
  }
  expect(model.nodes.length, "3 entity nodes, no objective hub").toBe(3);
  // founder 2026-06-24 (no-cooccurrence-edges): co-occurrence is NOT an edge — the 3 entities share a run
  // but have no real typed relationship, so the re-hydrated graph has ZERO edges (the old 3-clique is gone).
  expect(model.edges.length, "no co-occurrence edges — co-occurrence is not a relationship").toBe(0);
  expect(afterReturn.nodes, "rendered cytoscape node count == hydrated model").toBe(model.nodes.length);
  expect(afterReturn.edges, "rendered cytoscape edge count == hydrated model").toBe(model.edges.length);
});

test("R1: runs page surfaces the full step trail with findings attributed to steps", async ({ page }) => {
  await seedRun(page);

  await page.evaluate((r) => { location.hash = "#" + r; }, "/runs"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await page.waitForSelector(".run-card", { timeout: 10_000 });
  // expand the run
  await page.locator(".run-head").first().click();
  await page.waitForSelector(".run-detail .run-trail", { timeout: 10_000 });

  await page.screenshot({ path: "test-results/verify-r1-run-detail.png", fullPage: true });

  // STRENGTHENED (codex finding-2): prove the FULL trail shape, not just two tool names.
  // (1) all 5 ordered steps render (2 reasoning + 2 tool + 1 final), numbered #1..#5
  const stepNs = await page.locator(".run-trail .trail-n").allInnerTexts();
  expect(stepNs, "the full 5-step trail renders, numbered in order").toEqual(["#1", "#2", "#3", "#4", "#5"]);

  // (2) reasoning text is present (the agent's narration, not just tool rows)
  const reasoning = await page.locator(".run-trail .trail-reason .trail-text").allInnerTexts();
  expect(reasoning.join(" "), "reasoning steps show their text").toContain("pivoting on its infra");

  // (3) the real tool calls, with their INPUT and RESULT bodies
  const tools = await page.locator(".run-trail .trail-tool").allInnerTexts();
  expect(tools.join(" ")).toContain("dns_lookup");
  expect(tools.join(" ")).toContain("crtsh_subdomains");
  const inputs = await page.locator(".run-trail .trail-input").allInnerTexts();
  expect(inputs.join(" "), "tool input params render").toContain("acme-pay.example");
  const results = await page.locator(".run-trail .trail-result").allInnerTexts();
  expect(results.join(" "), "tool result bodies render").toMatch(/entities|error/);

  // (4) all 3 findings render, with the source-step attribution on the dns_lookup-derived ip
  const findings = await page.locator(".run-finding").allInnerTexts();
  expect(findings.length, "all 3 findings render").toBe(3);
  const provs = await page.locator(".run-finding-prov").allInnerTexts();
  expect(provs.join(" "), "a finding links to its source step + tool").toContain("from step 2");
  expect(provs.join(" ")).toContain("dns_lookup");

  // (5) the deterministic bottom line
  const bottom = await page.locator(".run-bottomline-text").innerText();
  expect(bottom, "the bottom line / next move renders").toMatch(/promoted|lead|Next/i);
});
