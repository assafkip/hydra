import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// cl-smoke (the live proof, modernized for INC-3): clusters are an ANALYZE output now — the Process
// pipeline's analyze step writes them through the redacted putAnalysis chokepoint, and clustersFor
// projects them (co-occurrence auto-clustering was replaced). This drives the REAL analyze pass: two
// seeded entities are grouped into one analytic cluster whose NAME embeds the saved Anthropic key, and
// we prove (1) the /clusters page + node drawer render the cluster (NOT port-pending), and (2) the key
// is REDACTED out of the persisted+rendered cluster name (D8 — redact on write AND on read). No
// off-allowlist egress; the secret hook is refused. (Deep full-pipeline coverage: verify-process.spec.)

const KEY = "sk-ant-CLSMOKE-secret-5151";

// two domains that the analyze wire groups into one cluster. They sort e0/e1 (localeCompare).
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

// the Process wire (python-shaped JSON the validators accept), mirroring verify-process.spec.
const SCHEMA_TEXT = JSON.stringify({
  domain: "crypto rug-pull network",
  summary: "alias domains fronting a token drainer",
  entity_types: [{ name: "domain", description: "a web surface" }],
  roles: [
    { name: "channel", description: "a comms / front surface", actor: false, weight: 3 },
    { name: "noise", description: "fragments", actor: false, weight: 0 },
  ],
  sub_roles: [],
  noise_notes: "broken URLs and fragments are noise",
});
const CONSOLIDATE_TEXT = JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "same front, alias pair" }] });
const TYPE_TEXT = JSON.stringify({ types: [{ id: "e0", type: "url", confidence: "high", reason: "looks like a url" }] });
// the analyze cluster NAME embeds the saved key — to prove putAnalysis redacts it on write AND clustersFor
// re-redacts on read (D8). One cluster over both domains.
const ANALYZE_TEXT = JSON.stringify({
  clusters: [{ name: `Drainer ${KEY} Infra`, kind: "infrastructure_block", member_ids: ["e0", "e1"], description: "front domains" }],
  typed_relationships: [],
});
const SYNTHESIZE_TEXT = "# Case brief\n\nThe alias network fronts a token drainer.";
const DOSSIER_TEXT = "## Actor dossier\n\nHigh-value channel surface in the drainer network.";

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // back to the graph home for the run
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await freshKeyedVault(page);
});

test("the analyze pass produces a cluster that renders on /clusters + the drawer; a key in the cluster name is redacted; no egress", async ({ page }) => {
  // (1) seed two entities + install the scripted Process wire (analyze groups them into one cluster)
  await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("seed cluster", turns), SEED_TURNS);
  await page.evaluate(
    ({ s, c, t, a, sy, d }) => (window as any).__kipi.installChatWire({ schemaText: s, consolidateText: c, typeText: t, analyzeText: a, synthesizeText: sy, dossierText: d }),
    { s: SCHEMA_TEXT, c: CONSOLIDATE_TEXT, t: TYPE_TEXT, a: ANALYZE_TEXT, sy: SYNTHESIZE_TEXT, d: DOSSIER_TEXT },
  );

  // (2) run the Process pipeline (the analyze step writes the cluster through putAnalysis)
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await expect(page.locator(".proc-panel")).toBeVisible();
  await page.getByRole("button", { name: "Process case" }).click();
  await expect(page.locator(".proc-pct")).toHaveText("100%", { timeout: 30_000 });

  // (3) __kipi.clusters(): exactly ONE cluster over the two domains; the key in its name is REDACTED (D8)
  const clusters = await page.evaluate(() => (window as any).__kipi.clusters());
  expect(clusters).toHaveLength(1);
  expect(clusters[0].size).toBe(2);
  const members = clusters[0].members.map((m: any) => m.value).sort();
  expect(members).toEqual(["alpha-cdn.example.com", "alpha.example.com"]); // BOTH exact members (codex: size alone is gameable)
  const cjson = JSON.stringify(clusters);
  expect(cjson).not.toContain(KEY);
  expect(cjson.toLowerCase()).toContain("[redacted]"); // the key-bearing cluster name, redacted (D8)

  // (4) the /clusters PAGE lists the cluster with its members + the redacted name (NOT port-pending)
  await gotoRoute(page, "/clusters");
  await expect(page.locator(".pg-title")).toHaveText("Clusters");
  await expect(page.locator(".cl-card")).toHaveCount(1);
  await expect(page.locator(".cl-members")).toContainText("alpha.example.com");
  await expect(page.locator(".cl-members")).toContainText("alpha-cdn.example.com"); // both members render
  await expect(page.locator(".cl-name")).not.toContainText(KEY);

  // (5) the node DRAWER shows the cluster membership for a domain node (NOT port-pending)
  await page.click('a[data-route="/"]');
  const dom = await page.evaluate(() => {
    const m = (window as any).__kipi.graphModel();
    const n = m.nodes.find((x: any) => x.entityType === "domain");
    return n ? { id: n.id, label: n.label } : null;
  });
  await page.evaluate((id) => (window as any).__kipi.selectNode(id), dom!.id);
  // remove-cards (founder 2026-07-03): selecting a clustered node renders NO card; the detail is a chat
  // MESSAGE via "Show full details".
  await expect(page.locator(".node-card")).toHaveCount(0);
  await page.evaluate((id) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === id);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, dom!.id);
  await expect(page.locator("#chat-messages .msg.agent").last()).toContainText(dom!.label);

  // (6) no key on the page; the secret hook refused; no off-allowlist egress
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(KEY);
  const secretThrows = await page.evaluate(() => {
    try { (window as any).__kipi.getCase("secret:anthropic_key"); return false; } catch { return true; }
  });
  expect(secretThrows).toBe(true);
  expect(external, `unexpected egress: ${external.join(", ")}`).toHaveLength(0);

  await page.screenshot({ path: "test-results/kipi-clusters.png", fullPage: true });
});
