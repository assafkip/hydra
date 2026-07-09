import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// pf-process smoke (the live proof, PRD INC-1): with two alias-like entities seeded, the /reports page
// exposes the Process pipeline panel; clicking "Process case" runs the orchestrated chain
// (auto-schema → consolidate → typing) entirely offline (scripted LLM wire, zero egress); the live
// progress UI checklist runs ◐→✓ to 3/3 + 100% and the log shows the modeled domain; the AI roles land
// in the analysis:<case> record + surface in /entities THROUGH applyAnalysis; an analyst role correction
// then WINS over the Process-assigned role (analyst is top authority); the Anthropic key leaks nowhere.

const APIKEY = "sk-ant-PROCESS-smoke-4242";

// the schema understand pass output (python-shaped JSON, snake_case — validateCaseSchema accepts it)
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
// consolidate: merge the two aliases + assign role 'channel' (a CONSOLIDATE_ROLE → a valid AI overlay)
const CONSOLIDATE_TEXT = JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "same front, alias pair" }] });
// typing: refine e0's surface type to 'url' (a SURFACE_TYPE → a valid AI type overlay)
const TYPE_TEXT = JSON.stringify({ types: [{ id: "e0", type: "url", confidence: "high", reason: "looks like a url" }] });
// analyze (INC-3): 2 LLM clusters over the 4 entities (e0/e1 domains, e2/e3 persons) + a typed rel.
// → the graph gets 2 distinct cluster-color fills (cap-cluster-colors); /clusters lists both names.
const ANALYZE_TEXT = JSON.stringify({
  clusters: [
    { name: "Drainer Infra", kind: "infrastructure_block", member_ids: ["e0", "e1"], description: "front domains" },
    { name: "Operator Ring", kind: "ring", member_ids: ["e2", "e3"], description: "the operators" },
  ],
  typed_relationships: [{ src_id: "e2", dst_id: "e0", rel_type: "deployed", confidence: "high", evidence: "deployed the drainer" }],
});
// INC-4b: the synthesize step (case brief) + the dossiers step (per-actor profile) return MARKDOWN.
const SYNTHESIZE_TEXT = "# Case brief\n\nThe alias network fronts a token drainer. Operators deployed it across two front domains.";
const DOSSIER_TEXT = "## Actor dossier\n\nHigh-value channel surface in the drainer network; co-mentioned with the operators.";

// two alias-like domains + a person alias pair (name reorder = 1.0 token overlap → an alias link).
// Domains sort first (localeCompare: 'a' < 'j'/'s'), so they stay e0/e1 for the consolidate/type wire;
// the persons are e2/e3 and feed the INC-2 correlate alias pass. No tool corroboration → leads, but in
// the entity DB. (entity_type 'person' is what auto_link_aliases filters on.)
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

test("reports: Process pipeline runs the chain (schema→consolidate→typing→correlate→cross_domain→analyze→score→graph_metrics→synthesize→dossiers), surfaces AI roles + alias links + analytic clusters + typed edges + threat scores + graph metrics + case brief + dossiers, correction wins; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) Anthropic key via the real keys card (now on the /account page — moved off the graph home).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");

  // (2) Back to the graph home, seed two alias entities + install the scripted Process wire.
  await page.click('a[data-route="/"]');
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("seed aliases", turns), SEED_TURNS);
  await page.evaluate(
    ({ s, c, t, a, sy, d }) => (window as unknown as { __kipi: { installChatWire(spec: unknown): void } }).__kipi.installChatWire({ schemaText: s, consolidateText: c, typeText: t, analyzeText: a, synthesizeText: sy, dossierText: d }),
    { s: SCHEMA_TEXT, c: CONSOLIDATE_TEXT, t: TYPE_TEXT, a: ANALYZE_TEXT, sy: SYNTHESIZE_TEXT, d: DOSSIER_TEXT },
  );

  // (3) Open /reports and run Process.
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".proc-panel")).toBeVisible();
  await page.getByRole("button", { name: "Process case" }).click();

  // (4) The live progress UI runs the 8 steps (…→analyze→score→graph_metrics→synthesize→dossiers) to done + 100%, the log
  // shows the modeled domain, and the INC-2/INC-3/INC-4a steps logged their counts.
  await expect(page.locator(".proc-step.proc-ok")).toHaveCount(10);
  await expect(page.locator(".proc-pct")).toHaveText("100%");
  await expect(page.locator(".proc-log")).toContainText("crypto rug-pull network"); // schema step logged
  await expect(page.locator(".proc-schema")).toContainText("crypto rug-pull network"); // schema summary shown
  await expect(page.locator(".proc-log")).toContainText("alias link"); // INC-2 correlate step ran
  await expect(page.locator(".proc-log")).toContainText("cross-type link"); // INC-2 cross_domain step ran
  await expect(page.locator(".proc-log")).toContainText("2 cluster(s)"); // INC-3 analyze step ran
  await expect(page.locator(".proc-log")).toContainText("typed relationship"); // INC-4a: relationships persisted
  await expect(page.locator(".proc-log")).toContainText("entity score(s)"); // INC-4a score step ran
  await expect(page.locator(".proc-log")).toContainText("node metric(s)"); // INC-4a graph_metrics step ran
  await expect(page.locator(".proc-log")).toContainText("case brief generated"); // INC-4b synthesize step ran
  await expect(page.locator(".proc-log")).toContainText("dossier(s) generated"); // INC-4b dossiers step ran
  await page.screenshot({ path: "test-results/kipi-process.png", fullPage: true });

  // (5) The AI role landed in the analysis record + surfaces THROUGH applyAnalysis in the entity DB.
  const aiRole = await page.evaluate(() =>
    (window as unknown as { __kipi: { entityDb(): { entities: Record<string, { label: string; role: string }> } } }).__kipi
      .entityDb()
      .entities,
  );
  const aliasKey = Object.keys(aiRole).find((k) => aiRole[k].label === "alpha-cdn.example.com")!;
  expect(aiRole[aliasKey].role).toBe("channel"); // AI overlay through applyAnalysis

  // (6) An analyst role correction on the SAME entity WINS over the Process-assigned role (top authority).
  await page.evaluate(() =>
    (window as unknown as { __kipi: { applyCorrection(t: string, v: string, p: string, n: string): Promise<unknown> } }).__kipi.applyCorrection(
      "domain",
      "alpha-cdn.example.com",
      "role",
      "operator",
    ),
  );
  const afterCorrection = await page.evaluate(() =>
    (window as unknown as { __kipi: { entityDb(): { entities: Record<string, { label: string; role: string }> } } }).__kipi
      .entityDb()
      .entities,
  );
  const k2 = Object.keys(afterCorrection).find((k) => afterCorrection[k].label === "alpha-cdn.example.com")!;
  expect(afterCorrection[k2].role).toBe("operator"); // analyst wins, not the AI 'channel'

  // (7) The INC-2 alias capability surfaces on entity detail (codex D7 — DOM-asserted, not just a
  // screenshot): open /entities, expand the person, and the "Also known as" section names the
  // reordered twin (computeAliasLinks live view).
  await gotoRoute(page, "/entities");
  await page.locator(".ent-top", { hasText: "John Smith" }).first().click();
  await expect(page.locator(".ent-aka-head")).toContainText("Also known as");
  await expect(page.locator(".ent-aka")).toContainText("Smith John");
  await page.screenshot({ path: "test-results/kipi-aliases.png", fullPage: true });

  // (7b) INC-3: the analyze pass persisted the 2 LLM clusters, /clusters lists them by NAME, and the
  // graph colors nodes by the REAL analytic cluster (>1 distinct cluster on the model = not all slate).
  const clusterNames = await page.evaluate(() =>
    (window as unknown as { __kipi: { clusters(): { label: string; size: number }[] } }).__kipi.clusters().map((c) => c.label).sort(),
  );
  expect(clusterNames).toEqual(["Drainer Infra", "Operator Ring"]); // /clusters reads the REAL record clusters
  await gotoRoute(page, "/clusters");
  await expect(page.getByText("Drainer Infra")).toBeVisible();
  await expect(page.getByText("Operator Ring")).toBeVisible();
  await page.screenshot({ path: "test-results/kipi-clusters.png", fullPage: true });
  // The home graph colors by the real clusters: >1 distinct node.cluster (applyClustersToModel).
  await page.click('a[data-route="/"]');
  await page.waitForFunction(() => {
    const m = (window as unknown as { __kipi: { graphModel(): { nodes: { cluster?: string }[] } | null } }).__kipi.graphModel();
    if (!m) return false;
    const set = new Set(m.nodes.map((n) => n.cluster).filter(Boolean));
    return set.size > 1; // both Drainer Infra + Operator Ring fills present (not the slate fallback)
  });
  await page.screenshot({ path: "test-results/kipi-graph-clusters.png", fullPage: true });

  // (7c) INC-4a: the finalized graph carries the analytics — a typed_rel edge with the gated rel_type
  // ("deployed" survives normalizeRel on the schema-approved/allowNovel path), a real threatScore on a
  // node (the score step, not the grade proxy), and a Louvain community on a node (graph_metrics).
  const graph = await page.evaluate(() =>
    (window as unknown as {
      __kipi: { graphModel(): { nodes: { threatScore?: number; community?: number }[]; edges: { kind: string; relType?: string }[] } | null };
    }).__kipi.graphModel(),
  );
  const typedEdge = graph!.edges.find((e) => e.kind === "typed_rel");
  expect(typedEdge, "a typed_rel edge must render from the persisted relationship").toBeTruthy();
  expect(typedEdge!.relType).toBe("deployed"); // the clean schema label survived the vocab gate (codex P1)
  expect(graph!.nodes.some((n) => typeof n.threatScore === "number"), "a node carries a real threat score").toBe(true);
  expect(graph!.nodes.some((n) => typeof n.community === "number"), "a node carries a Louvain community").toBe(true);

  // the analysis record persisted the relationships + scores + metrics (the queryable source of truth)
  const rec4a = await page.evaluate(() =>
    (window as unknown as { __kipi: { analysisRecord(): { relationships?: unknown[]; entityScores?: Record<string, unknown>; nodeMetrics?: Record<string, unknown> } | null } }).__kipi.analysisRecord(),
  );
  expect(rec4a!.relationships!.length).toBeGreaterThan(0);
  expect(Object.keys(rec4a!.entityScores ?? {}).length).toBeGreaterThan(0);
  expect(Object.keys(rec4a!.nodeMetrics ?? {}).length).toBeGreaterThan(0);

  // (7d) INC-4b: the synthesize step persisted a case brief (brief:case) + the dossiers step persisted
  // >=1 actor dossier (the dossiers step was proc-ok, which only happens with >=1 dossier). Key-redacted.
  const brief = await page.evaluate(() =>
    (window as unknown as { __kipi: { getCase(k: string): { value: { brief?: string } | null } } }).__kipi.getCase("brief:case").value,
  );
  expect(brief?.brief, "the synthesize step must persist a case brief").toContain("Case brief");
  expect(JSON.stringify(brief)).not.toContain(APIKEY);

  // (8) No key in the analysis record, the entity DB, or the page body.
  const recJson = await page.evaluate(() => JSON.stringify((window as unknown as { __kipi: { analysisRecord(): unknown } }).__kipi.analysisRecord()));
  expect(recJson).not.toContain(APIKEY);
  expect(recJson).toContain("channel"); // the record holds the real AI role overlay
  expect(recJson).toContain("crypto rug-pull network"); // and the modeled schema
  expect(recJson).toContain("Drainer Infra"); // and the INC-3 analyze clusters
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);

  // (9) No off-allowlist egress — the whole pipeline ran in-browser on scripted wires.
  expect(external).toEqual([]);
});
