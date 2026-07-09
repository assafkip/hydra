import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-activity smoke (the live proof): real actions land timestamped records, and /activity renders them as
// a reverse-chron "who did what, when" feed — a Process run ("processed the case"), an analyst correction
// ("asserted role → ..."), and an upload ("uploaded report.csv") all appear, newest-first, the correction
// carrying its analyst chip. No server activity table (projection over retained records). No key leak, no egress.

const APIKEY = "sk-ant-ACTIVITY-smoke-5050";

const SCHEMA_TEXT = JSON.stringify({
  domain: "crypto rug-pull network",
  summary: "alias domains fronting a token drainer",
  entity_types: [{ name: "domain", description: "a web surface" }],
  roles: [
    { name: "operator", description: "the human running it", actor: true, weight: 5 },
    { name: "channel", description: "a comms / front surface", actor: false, weight: 3 },
    { name: "noise", description: "fragments", actor: false, weight: 0 },
  ],
  sub_roles: [],
  noise_notes: "fragments are noise",
});
const CONSOLIDATE_TEXT = JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "alias pair" }] });
const TYPE_TEXT = JSON.stringify({ types: [] });
const ANALYZE_TEXT = JSON.stringify({ clusters: [{ name: "Drainer Infra", kind: "infrastructure_block", member_ids: ["e0", "e1"], description: "front domains" }], typed_relationships: [] });
const SYNTHESIZE_TEXT = "# Case brief\n\nThe alias network fronts a token drainer.";
const DOSSIER_TEXT = "## Actor dossier\n\nHigh-value channel surface in the drainer network.";

const SEED_TURNS = [
  {
    content: [
      {
        type: "text",
        text:
          'Done.\n```json\n{"findings":[' +
          '{"entity":"alpha.example.com","entity_type":"domain"},' +
          '{"entity":"alpha-cdn.example.com","entity_type":"domain"}' +
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

test("activity feed: a Process + a correction + an upload appear reverse-chron with the analyst; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key, seed + Process wire, run Process -> "processed the case" + entities land.
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
  // wait for Process to COMPLETE (this seed skips synthesize/dossiers/correlate — no person aliases/wire — so
  // the ok-count is <10; the analysis record's updatedAt is stamped whenever Process finishes, which is what
  // the "processed the case" activity row reads).
  await expect(page.locator(".proc-pct")).toHaveText("100%", { timeout: 30_000 });

  // (2) an analyst correction -> "asserted role -> operator" (carries the analyst).
  await page.evaluate(() =>
    (window as unknown as { __kipi: { applyCorrection(t: string, v: string, p: string, n: string): Promise<unknown> } }).__kipi.applyCorrection("domain", "alpha-cdn.example.com", "role", "operator"),
  );

  // (3) an upload — a file-ingest run carries ingestedAt + title (seed an OLD one so it sorts LAST). run: is
  // not a protected key, so putCase seeds it exactly as the ingest path would.
  await page.evaluate(() =>
    (window as unknown as { __kipi: { putCase(k: string, v: unknown): Promise<unknown> } }).__kipi.putCase("run:file: report.csv #old001", {
      objective: "file: report.csv #old001", steps: [], promoted: [], leads: [], usage: { input: 0, output: 0 },
      stopReason: "end_turn", ingestedAt: "2020-01-01T00:00:00.000Z", title: "report.csv", sourceType: "csv",
    }),
  );

  // (4) the /activity feed renders all three, newest-first.
  await gotoRoute(page, "/activity");
  await expect(page.locator(".pg-title")).toHaveText("Activity");
  await expect(page.locator(".act-row", { hasText: "processed the case" })).toBeVisible();
  const corrRow = page.locator(".act-row", { hasText: "asserted role → operator" });
  await expect(corrRow).toBeVisible();
  await expect(corrRow.locator(".act-analyst")).toBeVisible(); // the correction carries its analyst chip
  await expect(corrRow.locator(".act-entity")).toContainText("alpha-cdn.example.com");
  await expect(page.locator(".act-row", { hasText: "uploaded report.csv" })).toBeVisible();

  // reverse-chron: the OLD upload (2020) sorts AFTER the just-now correction in DOM order.
  const order = await page.evaluate(() => Array.from(document.querySelectorAll(".act-row")).map((r) => (r.textContent || "")));
  const idxCorr = order.findIndex((t) => t.includes("asserted role → operator"));
  const idxUpload = order.findIndex((t) => t.includes("uploaded report.csv"));
  expect(idxCorr).toBeGreaterThanOrEqual(0);
  expect(idxUpload).toBeGreaterThan(idxCorr); // the 2020 upload is below the now-correction

  await page.screenshot({ path: "test-results/kipi-activity.png", fullPage: true });

  // (5) no key leak anywhere, no off-allowlist egress.
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  const recJson = await page.evaluate(() => JSON.stringify((window as unknown as { __kipi: { analysisRecord(): unknown } }).__kipi.analysisRecord()));
  expect(recJson).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
