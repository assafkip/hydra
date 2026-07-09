import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-bridges smoke (the RENDER GATE): seed two alias-like entity pairs, run Process with a scripted
// analyze pass that produces 2 clusters (Drainer Infra: domains; Operator Ring: persons) + a typed
// relationship John Smith --deployed--> alpha.example.com that TIES the two clusters. That cross-cluster
// edge makes both the operator and the (consolidate-survivor) infra domain bridge entities. Navigate
// the REAL router to /bridges and assert the bridge rows + their bridged clusters render. Also assert
// the honest empty state with no clusters. Zero egress, no key in the DOM. (Mirrors verify-process.)

const APIKEY = "sk-ant-BRIDGES-smoke-6262";

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

test("bridges: /bridges renders the cross-cluster bridge entities + their bridged clusters; honest empty state; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (0) BEFORE Process there are no clusters -> /bridges shows the honest empty state.
  await gotoRoute(page, "/bridges");
  await expect(page.locator(".pg-title")).toHaveText("Connectors");
  await expect(page.locator(".pg-empty")).toContainText("No entities span this many clusters");
  await expect(page.locator(".br-card")).toHaveCount(0);

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

  // (3) Open /reports and run Process to model the 2 clusters + the cross-cluster typed relationship.
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".proc-panel")).toBeVisible();
  await page.getByRole("button", { name: "Process case" }).click();
  await expect(page.locator(".proc-step.proc-ok")).toHaveCount(10);
  await expect(page.locator(".proc-pct")).toHaveText("100%");

  // (4) The bridge projection finds both endpoints of the cross-cluster edge spanning 2 clusters. The
  // operator (display label "John Smith") + the consolidate-survivor infra domain are the two bridges.
  // (Live truth: consolidate MERGES the alias domain pair into one entity; the survivor's canonical
  // identity is the domain that won the merge. Assert by the STABLE ref.type identity, not the AI
  // display type, since the typing step relabels the domain's display type to 'url'.)
  const bridges = await page.evaluate(() =>
    (window as unknown as { __kipi: { bridges(): { ref: { type: string }; label: string; clusterCount: number; clusters: { name: string }[]; crossRelCount: number; threatScore: number }[] } }).__kipi.bridges(),
  );
  expect(bridges.length).toBe(2); // exactly the two endpoints of the single cross-cluster relationship
  const operator = bridges.find((b) => b.ref.type === "person")!;
  const domain = bridges.find((b) => b.ref.type === "domain")!;
  expect(operator, "the operator (person) bridges the two clusters").toBeTruthy();
  expect(domain, "the infra domain bridges the two clusters").toBeTruthy();
  expect(operator.label).toBe("John Smith"); // the first-seen DISPLAY label (not lowercased)
  for (const b of [operator, domain]) {
    expect(b.clusterCount).toBe(2);
    expect(b.clusters.map((c) => c.name).sort()).toEqual(["Drainer Infra", "Operator Ring"]);
    expect(b.crossRelCount).toBe(1);
  }
  // the operator outranks the domain (higher threat score) -> sorted first (the original ORDER BY).
  expect(bridges[0].ref.type).toBe("person");

  // (5) The /bridges PAGE renders the bridge rows + their bridged-cluster chips (a faithful-but-hollow
  // page would fail here).
  await gotoRoute(page, "/bridges");
  await expect(page.locator(".pg-sub")).toContainText("2 connector entities");
  await expect(page.locator(".br-card")).toHaveCount(2);
  const johnCard = page.locator(".br-card", { has: page.locator(".br-name", { hasText: "John Smith" }) });
  await expect(johnCard).toBeVisible();
  await expect(johnCard.locator(".br-clusters")).toContainText("Drainer Infra");
  await expect(johnCard.locator(".br-clusters")).toContainText("Operator Ring");
  await expect(johnCard.locator(".br-clusters")).toContainText("cross-cluster edge");
  await expect(johnCard.locator(".br-meta")).toContainText("2 clusters");
  await page.screenshot({ path: "test-results/kipi-bridges.png", fullPage: true });

  // (6) No key in the page body; no off-allowlist egress.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(JSON.stringify(bridges)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
