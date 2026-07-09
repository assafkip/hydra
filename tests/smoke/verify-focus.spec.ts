import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-focus smoke (the RENDER GATE): seed four entities, run Process with a scripted analyze pass that
// produces 2 clusters + a typed relationship John Smith --deployed--> alpha.example.com. After Process
// the case is SCORED (the score step), so /focus shows the threat-ranked top targets, the deterministic
// gaps, and the verbatim score-methodology block. Also assert the honest empty state pre-Process. Zero
// egress, no key in the DOM. (Mirrors verify-bridges / verify-process.)

const APIKEY = "sk-ant-FOCUS-smoke-5151";

const SCHEMA_TEXT = JSON.stringify({
  domain: "crypto rug-pull network",
  summary: "alias domains fronting a token drainer",
  entity_types: [{ name: "domain", description: "a web surface" }],
  roles: [
    { name: "operator", description: "the human running it", actor: true, weight: 5 },
    { name: "channel", description: "a comms / front surface", actor: false, weight: 3 },
    { name: "noise", description: "fragments", actor: false, weight: 0 },
  ],
  sub_roles: [{ name: "developer", description: "builds the drainer" }],
  noise_notes: "broken URLs and fragments are noise",
});
const CONSOLIDATE_TEXT = JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "same front, alias pair" }] });
const TYPE_TEXT = JSON.stringify({ types: [{ id: "e0", type: "url", confidence: "high", reason: "looks like a url" }] });
// 2 clusters (e0/e1 domains, e2/e3 persons) + a CROSS-cluster typed relationship e2 -> e0.
const ANALYZE_TEXT = JSON.stringify({
  clusters: [
    { name: "Drainer Infra", kind: "infrastructure_block", member_ids: ["e0", "e1"], description: "front domains" },
    { name: "Operator Ring", kind: "ring", member_ids: ["e2", "e3"], description: "the operators" },
  ],
  typed_relationships: [{ src_id: "e2", dst_id: "e0", rel_type: "deployed", confidence: "high", evidence: "deployed the drainer" }],
});
const SYNTHESIZE_TEXT = "# Case brief\n\nThe alias network fronts a token drainer.";
const DOSSIER_TEXT = "## Actor dossier\n\nHigh-value surface in the drainer network.";

const SEED_TURNS = [
  {
    content: [
      {
        type: "text",
        text:
          'Done.\n```json\n{"findings":[' +
          '{"entity":"alpha.example.com","entity_type":"domain"},' +
          '{"entity":"alpha-cdn.example.com","entity_type":"domain"},' +
          '{"entity":"John Smith","entity_type":"person"},' +
          '{"entity":"Smith John","entity_type":"person"}' +
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

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}

test("focus: /focus renders the score-ranked top targets + the deterministic gaps + the verbatim methodology block; honest empty state; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (0) BEFORE Process there are no scored entities -> /focus shows the honest empty state.
  await gotoRoute(page, "/focus");
  await expect(page.locator(".pg-title")).toHaveText("Focus");
  await expect(page.locator(".fc-empty-title")).toContainText("No focus brief yet");
  await expect(page.locator(".fc-item")).toHaveCount(0);

  // (1) Anthropic key via the real keys card (on the /account page).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");

  // (2) Seed the four entities + install the scripted Process wire.
  await page.click('a[data-route="/"]');
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("seed aliases", turns), SEED_TURNS);
  await page.evaluate(
    ({ s, c, t, a, sy, d }) => (window as unknown as { __kipi: { installChatWire(spec: unknown): void } }).__kipi.installChatWire({ schemaText: s, consolidateText: c, typeText: t, analyzeText: a, synthesizeText: sy, dossierText: d }),
    { s: SCHEMA_TEXT, c: CONSOLIDATE_TEXT, t: TYPE_TEXT, a: ANALYZE_TEXT, sy: SYNTHESIZE_TEXT, d: DOSSIER_TEXT },
  );

  // (3) Open /reports and run Process to score the case (clusters + typed rel + threat scores).
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".proc-panel")).toBeVisible();
  await page.getByRole("button", { name: "Process case" }).click();
  await expect(page.locator(".proc-step.proc-ok")).toHaveCount(10);
  await expect(page.locator(".proc-pct")).toHaveText("100%");

  // (4) The focus projection ranks the scored entities; the operator (a promoted SEED in the Operator
  //     Ring, tied to the infra domain) is a top target. Assert via the __kipi harness first.
  const focus = await page.evaluate(() =>
    (window as unknown as { __kipi: { focus(): { items: { name: string; role: string; score: number; promoted: boolean; clusters: { name: string }[]; topRelationships: { relType: string }[] }[]; gaps: { kind: string; title: string }[] } } }).__kipi.focus(),
  );
  expect(focus.items.length).toBeGreaterThan(0);
  const operator = focus.items.find((i) => i.name === "John Smith")!;
  expect(operator, "the operator is a ranked focus item").toBeTruthy();
  expect(operator.role).toBe("operator"); // the AI role overlay (operator weight 5 drives the score)
  expect(operator.score).toBeGreaterThan(0); // role×10 base points → a real attention score
  expect(operator.clusters.map((c) => c.name)).toContain("Operator Ring");
  expect(operator.topRelationships.some((r) => r.relType === "deployed")).toBe(true);
  // items are score-ranked descending (a TOTAL order).
  const scores = focus.items.map((i) => i.score);
  expect([...scores].sort((a, b) => b - a)).toEqual(scores);
  // the gaps fire (these entities are seen in only one run -> uncorroborated at minimum).
  expect(focus.gaps.some((g) => g.kind === "uncorroborated")).toBe(true);

  // (5) The /focus PAGE renders the ranked items, the gaps, and the methodology block (a faithful-but-
  //     hollow page would fail here).
  await gotoRoute(page, "/focus");
  await expect(page.locator(".fc-list-head")).toContainText("Top targets");
  await expect(page.locator(".fc-item").first()).toBeVisible();
  const johnRow = page.locator(".fc-item", { has: page.locator(".fc-name", { hasText: "John Smith" }) });
  await expect(johnRow).toBeVisible();
  await expect(johnRow.locator(".fc-clusters")).toContainText("Operator Ring");
  await expect(johnRow.locator(".fc-rels")).toContainText("deployed");
  // the gaps callout + the verbatim methodology block.
  await expect(page.locator(".fc-gaps-head")).toContainText("Gaps & what to look for next");
  await expect(page.locator(".fc-method-sum")).toContainText("How to read these scores");
  await page.locator(".fc-method-sum").click();
  await expect(page.locator(".fc-method-formula")).toContainText("role×10 + reports×5 + degree×1 + seed×30 + propagation");
  await expect(page.locator(".fc-method-body")).toContainText("rank-by-attention");
  await page.screenshot({ path: "test-results/kipi-focus.png", fullPage: true });

  // (6) No key in the page body; no off-allowlist egress.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(JSON.stringify(focus)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
