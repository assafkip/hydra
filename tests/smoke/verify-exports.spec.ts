import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
import { readFileSync } from "node:fs";

// sf-exports smoke (the live proof): after a real Process run models entities + clusters + a typed
// relationship, /exports DOWNLOADS a real STIX 2.1 bundle + entities CSV in-browser (the existing download()
// Blob primitive), each carrying the case data. Offline, zero egress, no key leak.

const APIKEY = "sk-ant-EXPORTS-smoke-8080";

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
const SYNTHESIZE_TEXT = "# Case brief\n\nThe alias network fronts a token drainer.";
const DOSSIER_TEXT = "## Actor dossier\n\nHigh-value channel surface.";

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

async function downloadText(page: Page, buttonName: string): Promise<string> {
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: buttonName }).click(),
  ]);
  const path = await download.path();
  return readFileSync(path, "utf-8");
}

test("exports: /exports downloads a real STIX bundle + entities CSV from the case; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key, seed + Process wire, run Process -> entities + clusters + the typed relationship land.
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

  // (2) /exports renders the three cards.
  await gotoRoute(page, "/exports");
  await expect(page.locator(".pg-title")).toHaveText("Exports");
  await expect(page.locator(".exp-card")).toHaveCount(3);

  // (3) the STIX download is a real STIX 2.1 bundle with the case entities + the typed relationship.
  const stixText = await downloadText(page, "Download stix_bundle.json");
  const bundle = JSON.parse(stixText);
  expect(bundle.type).toBe("bundle");
  expect(bundle.objects.some((o: { type: string }) => o.type === "domain-name" && String((o as { value?: string }).value).includes("example.com"))).toBe(true);
  const rel = bundle.objects.find((o: { type: string }) => o.type === "relationship");
  expect(rel.relationship_type).toBe("deployed");
  expect(stixText).not.toContain(APIKEY);

  // (4) the entities CSV download carries the entity rows (header + the domain + the person).
  const csvText = await downloadText(page, "Download entities.csv");
  expect(csvText.split("\r\n")[0]).toBe("id,name,type,role,threat_score,degree,report_count,clusters");
  expect(csvText).toContain("example.com");
  expect(csvText).toContain("John Smith");
  expect(csvText).not.toContain(APIKEY);

  await page.screenshot({ path: "test-results/kipi-exports.png", fullPage: true });

  // (5) no key leak in the page, no off-allowlist egress.
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
