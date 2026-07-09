import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-report-builder smoke (the live proof): after a real Process run produces a case brief + actor dossiers,
// /report renders a BRANDED, print-ready deliverable — the analyst sets the title/client/prepared-by, the
// cover + Executive Summary (the brief) + Actor Dossiers render, and a Print / Save as PDF button is present.
// Offline, zero egress, no key leak. Two screenshots: the builder form + the branded render.

const APIKEY = "sk-ant-REPORT-smoke-9090";

const SCHEMA_TEXT = JSON.stringify({
  domain: "crypto rug-pull network",
  summary: "alias domains fronting a token drainer",
  entity_types: [{ name: "domain", description: "a web surface" }],
  roles: [
    { name: "operator", description: "the human", actor: true, weight: 5 },
    { name: "channel", description: "a front surface", actor: false, weight: 3 },
    { name: "noise", description: "fragments", actor: false, weight: 0 },
  ],
  sub_roles: [],
  noise_notes: "fragments are noise",
});
const CONSOLIDATE_TEXT = JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "alias pair" }] });
const TYPE_TEXT = JSON.stringify({ types: [] });
const ANALYZE_TEXT = JSON.stringify({
  clusters: [
    { name: "Drainer Infra", kind: "infrastructure_block", member_ids: ["e0", "e1"], description: "front domains" },
    { name: "Operator Ring", kind: "ring", member_ids: ["e2", "e3"], description: "the operators" },
  ],
  typed_relationships: [{ src_id: "e2", dst_id: "e0", rel_type: "deployed", confidence: "high", evidence: "deployed the drainer" }],
});
const SYNTHESIZE_TEXT = "# Case brief\n\nThe alias network fronts a token drainer across two front domains.";
const DOSSIER_TEXT = "## Actor dossier\n\nHigh-value channel surface in the drainer network; co-mentioned with the operators.";

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

test("report: /report renders a branded deliverable with the brief + a dossier + Print; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key, seed + Process wire, run Process -> brief:case + actor dossiers land.
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]');
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("seed aliases", turns), SEED_TURNS);
  await page.evaluate(
    ({ s, c, t, a, sy, d }) => (window as unknown as { __kipi: { installChatWire(spec: unknown): void } }).__kipi.installChatWire({ schemaText: s, consolidateText: c, typeText: t, analyzeText: a, synthesizeText: sy, dossierText: d }),
    { s: SCHEMA_TEXT, c: CONSOLIDATE_TEXT, t: TYPE_TEXT, a: ANALYZE_TEXT, sy: SYNTHESIZE_TEXT, d: DOSSIER_TEXT },
  );
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".proc-panel")).toBeVisible();
  await page.getByRole("button", { name: "Process case" }).click();
  await expect(page.locator(".proc-pct")).toHaveText("100%", { timeout: 30_000 });

  // (2) open /report — the builder form renders.
  await gotoRoute(page, "/report");
  await expect(page.locator(".pg-title")).toHaveText("Build a client report");
  await expect(page.locator(".report-form")).toBeVisible();
  await page.screenshot({ path: "test-results/kipi-report-form.png", fullPage: true });

  // (3) set the branding — title + client + prepared-by flow into the branded render.
  await page.locator(".rf-field", { hasText: "Report title" }).locator("input").fill("Q3 Threat Briefing");
  await page.locator(".rf-field", { hasText: "Client (prepared for)" }).locator("input").fill("Acme Corp");
  await page.locator(".rf-field", { hasText: "Prepared by" }).locator("input").fill("Analyst One");

  // (4) the branded .report-doc shows the cover + the brief (Executive Summary) + a dossier.
  const doc = page.locator(".report-doc");
  await expect(doc.locator(".rep-cover-title")).toHaveText("Q3 Threat Briefing");
  await expect(doc.locator(".rep-client")).toContainText("Prepared for Acme Corp");
  await expect(doc.locator(".rep-meta")).toContainText("Prepared by: Analyst One");
  await expect(doc.locator(".rep-section-title", { hasText: "Executive Summary" })).toBeVisible();
  await expect(doc).toContainText("fronts a token drainer"); // the synthesis brief rendered
  await expect(doc.locator(".rep-dossier").first()).toBeVisible(); // >= 1 actor dossier
  await expect(page.locator(".report-print")).toHaveText("Print / Save as PDF"); // the window.print() button

  await page.screenshot({ path: "test-results/kipi-report-render.png", fullPage: true });

  // (5) no key leak in the page, no off-allowlist egress.
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
