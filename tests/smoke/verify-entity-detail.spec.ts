import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-entity-detail smoke (the live proof): after a real Process run lands scores + typed relationships +
// graph metrics, the /entities-page DETAIL fold renders the entity.html depth — §1+2 attention score +
// breakdown (with centrality metrics), §3 assert form, §4 corrections-audit slice, §6 EDITABLE analyst
// dossier (save round-trips through the vault), §7 typed relationships, §8 appears-in — and the graph
// node card MIRRORS §1+2/§7/§8 (the built-not-wired scar: both folds reach the same depth). No key leak,
// no egress. The two screenshots (fold + node card) are the manual visual-parity check vs entity.html.

const APIKEY = "sk-ant-" + "ENTITYDETAIL-smoke-7070";

// Reuse the proven verify-process seed: two alias domains + a person pair, then the scripted Process
// chain produces the analytics (clusters, a "deployed" typed relationship, threat scores, metrics).
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
const ANALYZE_TEXT = JSON.stringify({
  clusters: [
    { name: "Drainer Infra", kind: "infrastructure_block", member_ids: ["e0", "e1"], description: "front domains" },
    { name: "Operator Ring", kind: "ring", member_ids: ["e2", "e3"], description: "the operators" },
  ],
  typed_relationships: [{ src_id: "e2", dst_id: "e0", rel_type: "deployed", confidence: "high", evidence: "deployed the drainer" }],
});
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

test("entity detail fold: score+breakdown+metrics, assert form, corrections slice, EDITABLE dossier, typed rels, appears-in; node card mirrors §1+2/§7/§8; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key via the /account card, back to home, seed + install the scripted Process wire.
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

  // (2) run Process to completion (the 10-step chain produces scores + typed rels + metrics).
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".proc-panel")).toBeVisible();
  await page.getByRole("button", { name: "Process case" }).click();
  await expect(page.locator(".proc-step.proc-ok")).toHaveCount(10, { timeout: 30_000 });
  await expect(page.locator(".proc-pct")).toHaveText("100%");

  // (3) find the entity that is a typed-relationship endpoint — it is in the relationship adjacency, so it
  // is GUARANTEED to carry both a threat score (score step) and a typed relationship (the rendered fold).
  // Read it from the analysis record + entity DB (projection-independent — the typed_rel graph EDGES only
  // appear once the home graph re-projects; the fold reads typedRelationshipsFor straight off the record).
  const target = await page.evaluate(() => {
    const rec = (window as unknown as { __kipi: { analysisRecord(): { relationships?: { srcKey: string; dstKey: string }[]; entityScores?: Record<string, unknown> } | null } }).__kipi.analysisRecord();
    const ents = (window as unknown as { __kipi: { entityDb(): { entities: Record<string, { label: string; ref: { type: string; value: string } }> } } }).__kipi.entityDb().entities;
    if (!rec?.relationships?.length) return null;
    for (const r of rec.relationships) {
      for (const key of [r.dstKey, r.srcKey]) {
        const e = ents[key];
        // correct via the entity's REF (its canonKey source), not the display type — the typing pass can
        // change the display type (domain→url), which would build a non-matching correction key.
        if (e) return { key, label: e.label, refType: e.ref.type, refValue: e.ref.value, scored: !!rec.entityScores?.[key] };
      }
    }
    return null;
  });
  expect(target, "a typed-relationship endpoint entity must exist after Process").toBeTruthy();
  expect(target!.scored, "the endpoint entity carries a real threat score").toBe(true);

  // (4) open /entities, expand THAT entity's fold.
  await gotoRoute(page, "/entities");
  await page.locator(".ent-top", { hasText: target!.label }).first().click();

  // §1+2: the attention-score header (scored branch, not the "No attention score yet" empty) + the
  // breakdown whose total == the stored score + the centrality metrics.
  await expect(page.locator(".ent-score-value").first()).toBeVisible();
  await page.locator(".ent-score-breakdown summary").first().click(); // open the <details>
  await expect(page.locator(".ent-score-total .ent-score-rowpts").first()).toBeVisible();
  await expect(page.locator(".ent-score-metrics").first()).toContainText("eigenvector");

  // §7: the typed relationships are ALWAYS shown (the "deployed" rel survived the vocab gate), with a
  // clickable other-entity.
  await expect(page.locator(".ent-typedrel-head").first()).toContainText("Typed relationships");
  await expect(page.locator(".ent-typedrel-other").first()).toBeVisible();

  // §8: the appears-in list.
  await expect(page.locator(".ent-appears-head").first()).toContainText("Appears in");

  // §3: the assert form (the analyst top-authority entry point).
  await expect(page.locator(".ent-assert-head").first()).toContainText("assert a value");

  // §6: the EDITABLE analyst dossier — save a note and it round-trips through the vault (the open fold
  // stays open: setDossierOverride does NOT global-render, the section paints in place).
  await expect(page.locator(".ent-override-title").first()).toContainText("Analyst dossier");
  await page.locator(".ent-override").first().getByRole("button", { name: "Edit dossier" }).click();
  await page.locator(".ent-override-ta").first().fill("Analyst note: confirmed staging host for the drainer.");
  await page.locator(".ent-override").first().getByRole("button", { name: "Save" }).click();
  await expect(page.locator(".ent-override-body").first()).toContainText("confirmed staging host");
  await expect(page.locator(".ent-override-badge").first()).toBeVisible(); // analyst-edited badge

  await page.screenshot({ path: "test-results/kipi-entity-detail-fold.png", fullPage: true });

  // (5) §4: an analyst correction on the entity surfaces in the per-entity corrections-audit slice.
  await page.evaluate(({ type, value }) =>
    (window as unknown as { __kipi: { applyCorrection(t: string, v: string, p: string, n: string): Promise<unknown> } }).__kipi.applyCorrection(type, value, "role", "operator"),
    { type: target!.refType, value: target!.refValue });
  // the correction re-renders the page; re-expand the fold and the slice is there.
  await page.locator(".ent-top", { hasText: target!.label }).first().click();
  await expect(page.locator(".ent-corr-head").first()).toContainText("Active overrides");
  await expect(page.locator(".ent-corr-pred").first()).toContainText("role → operator");

  // (6) the graph NODE CARD mirrors §1+2/§7/§8 (both folds reach the same depth). Go home, find the
  // node by label (the home graph re-projects with the typed_rel edges), select it, open its drawer,
  // push it to chat → the node card shows the attention score + the typed relationship.
  await page.click('a[data-route="/"]');
  const nodeId = await page.evaluate((label) => {
    const m = (window as unknown as { __kipi: { graphModel(): { nodes: { id: string; label: string }[] } | null } }).__kipi.graphModel();
    return m?.nodes.find((n) => n.label === label)?.id ?? null;
  }, target!.label);
  expect(nodeId, "the entity has a node on the home graph").toBeTruthy();
  await page.evaluate((id) => (window as unknown as { __kipi: { selectNode(id: string): boolean } }).__kipi.selectNode(id as string), nodeId);
  // remove-cards (founder 2026-07-03): the node-card §1+2/§7/§8 MIRROR is now the "Show full details" chat
  // MESSAGE (formatNodeDetail) — same deterministic depth (score + typed rels + appears-in), no card.
  await expect(page.locator(".node-card")).toHaveCount(0);
  await page.evaluate((id) => {
    const n = (window as unknown as { __kipi: { graphModel(): { nodes: { id: string; label: string; full_name?: string; type?: string; entityType?: string; kind?: string }[] } } }).__kipi.graphModel().nodes.find((x) => x.id === id);
    (window as unknown as { __kipiChat: { showNodeDetails(node: unknown): void } }).__kipiChat.showNodeDetails({ ...n, full_name: n!.full_name || n!.label, type: n!.type || n!.entityType, kind: n!.kind || "entity" });
  }, nodeId);
  const detail = page.locator("#chat-messages .msg.agent").last();
  await expect(detail).toContainText("attention score"); // §1+2 the score header
  await expect(detail).toContainText("Typed relationships"); // §7 the typed rels mirror
  await page.screenshot({ path: "test-results/kipi-entity-detail-drawer.png", fullPage: true });

  // (7) the data-level mirror: entityView carries score + typedRels + appearances (not the empty view).
  const view = await page.evaluate((id) => (window as unknown as { __kipi: { entityView(id: string): { score: unknown; typedRels: unknown[]; appearances: unknown[] } } }).__kipi.entityView(id as string), nodeId);
  expect(view.score, "the node's entityView carries the score breakdown").not.toBeNull();
  expect(view.typedRels.length, "the node's entityView carries typed rels").toBeGreaterThan(0);
  expect(view.appearances.length, "the node's entityView carries appearances").toBeGreaterThan(0);

  // (8) no key leak anywhere, no off-allowlist egress.
  const viewJson = await page.evaluate((id) => JSON.stringify((window as unknown as { __kipi: { entityView(id: string): unknown } }).__kipi.entityView(id as string)), nodeId);
  expect(viewJson).not.toContain(APIKEY);
  const recJson = await page.evaluate(() => JSON.stringify((window as unknown as { __kipi: { analysisRecord(): unknown } }).__kipi.analysisRecord()));
  expect(recJson).not.toContain(APIKEY);
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
