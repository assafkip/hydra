import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// ed-smoke (the keystone proof): a REAL scripted run lands gated entities into the client
// entity DB, and the chat node card + edge card render REAL typed connections /
// dossier / co-occurrence / edge evidence — no more "port pending" for those. The malicious-echo
// half proves redaction: a key echoed into a finding (injected via the run: record + the entity DB
// path, NOT the live trail) is REDACTED out of the store, the views, and the node card. The saved key
// never leaks; no off-allowlist egress.
//
// Why the echo goes through the entity-DB path (putCase a run: record), not the agent's text: the
// live #trail renders the model's raw reasoning verbatim (a separate, pre-existing surface). This
// chunk owns the ENTITY DB surfaces, so the proof drives the key through THEM and asserts THEY redact.

const KEY = "sk-ant-" + "ENTITYDB-secret-4242"; // distinctive saved key for the no-leak sweep

// A clean run: the IP promotes (canned dns infra), a second domain is a held lead — so the two
// CO-OCCUR (real typed connection). No key anywhere in the model's output (the trail stays clean).
const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving echo.example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "echo.example.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          'Done.\n```json\n{"findings":[' +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"co.example.com","entity_type":"domain","confidence":"low"}' +
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

async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await freshKeyedVault(page);
});

test("a real run lands entities -> node card + edge card show REAL connections/dossier/evidence (no port-pending); malicious echo is redacted; no leak/egress", async ({ page }) => {
  await expect(page.locator("#chat-input")).toBeVisible();

  // (1) drive the REAL chat run path (scripted Anthropic wire; no key needed for the wire, no network)
  await page.evaluate(([turns]) => (window as any).__kipi.installChatWire({ turns }), [RUN_TURNS] as const);
  await page.fill("#chat-input", "investigate echo.example.com");
  await page.click("#chat-send");
  // remove-chat-findings (2026-07-08): the #findings column is gone — wait for the ip to land on the GRAPH.
  await expect.poll(() => page.evaluate(() => JSON.stringify((window as any).__kipi.graphModel())), { timeout: 10_000 }).toContain("93.184.216.34");

  // the graph grew: objective + ip + domain = 3 nodes
  expect((await page.evaluate(() => (window as any).__kipi.cyCounts())).nodes).toBe(3);

  // (2) the entity DB has the gated entities (the keystone: it's no longer empty)
  const ids = await page.evaluate(() => {
    const m = (window as any).__kipi.graphModel();
    const node = (pred: (n: any) => boolean) => m.nodes.find(pred);
    return {
      ip: node((n: any) => n.entityType === "ip")?.id,
      dom: node((n: any) => n.label === "co.example.com")?.id, // pin the FINDING domain (keep-all also adds the live query-target domain example.com — this test checks the finding's co_occurs edge)
      obj: node((n: any) => n.kind === "objective")?.id,
      entityCount: Object.keys((window as any).__kipi.entityDb().entities).length,
    };
  });
  expect(ids.entityCount).toBe(3); // kweb-live-graph keep-all: ip + co.example.com + the live query target example.com (a real domain the dig touched, kept)
  expect(ids.ip).toBeTruthy();
  expect(ids.dom).toBeTruthy();

  // (3) entityView for the IP node: found, dossier, real connections (surfaced_in + co_occurs)
  const ipView = await page.evaluate((id) => (window as any).__kipi.entityView(id), ids.ip);
  expect(ipView.found).toBe(true);
  expect(ipView.dossier).not.toBeNull();
  const rels = ipView.connections.map((c: any) => c.relType);
  expect(rels).toContain("surfaced_in");
  expect(rels).toContain("co_occurs");

  // (4) remove-cards (founder 2026-07-03): "Show full details" renders the REAL deterministic detail
  // (dossier + connections + appears-in) as a chat MESSAGE, not a card. (The per-node OSINT-transform menu +
  // style-rules editor were card-only affordances — node OSINT is now Dig/Investigate + /enrich.)
  await page.evaluate((id) => (window as any).__kipi.selectNode(id), ids.ip);
  await expect(page.locator(".node-card")).toHaveCount(0);
  await page.evaluate((id) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === id);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, ids.ip);
  const ipDetail = page.locator("#chat-messages .msg.agent").last();
  await expect(ipDetail).toContainText("Connections"); // the REAL derived connections section
  await expect(ipDetail).toContainText("Appears in"); // the surfaced-in / appears-in projection

  // (6) the EDGE CARD shows REAL edge evidence (resolved by node id, D1). co-occurrence stays in the entity
  // DB as a relatedness SIGNAL (clusters / dossiers / the edge card read it via edgeEvidence) — the founder
  // removed it only as a GRAPH EDGE (no-cooccurrence-edges, sp-7a5d7ff2 resolved), not as data.
  // the edge EVIDENCE is still real deterministic data (edgeView), read by clusters/dossiers. The edge CARD
  // is gone (remove-cards): edge detail is asked in chat ("what connects X and Y"), not rendered as a card.
  const edgeEv = await page.evaluate(([a, b]) => (window as any).__kipi.edgeView(a, b), [ids.ip, ids.dom] as const);
  expect(edgeEv.found).toBe(true);
  expect(edgeEv.evidence.relType).toBe("co_occurs");

  // (7) MALICIOUS ECHO: inject a tainted run: record (the saved KEY embedded in a lead finding) that
  // shares the IP, then re-open the node card. It enters via the entity-DB path and must be REDACTED.
  await page.evaluate((key) =>
    (window as any).__kipi.putCase("run:taint-run", {
      objective: "taint-run",
      steps: [],
      promoted: [{ entity: "93.184.216.34", entity_type: "ip", source_count: 2, infra_source_count: 2 }],
      leads: [{ finding: { entity: `${key}.leak.example.com`, entity_type: "domain" }, verdict: { promote: false, grade: "D", reason: "lead" } }],
      usage: { input: 0, output: 0 },
      stopReason: "end_turn",
    }), KEY);
  // re-render the detail (the tainted echo enters via the entity-DB path → must be redacted in the message)
  await page.evaluate((id) => {
    const n = (window as any).__kipi.graphModel().nodes.find((x: any) => x.id === id);
    (window as any).__kipiChat.showNodeDetails({ ...n, full_name: n.full_name || n.label, type: n.type || n.entityType, kind: n.kind || "entity" });
  }, ids.ip);
  const taintDetail = page.locator("#chat-messages .msg.agent").last();
  await expect(taintDetail).toContainText("REDACTED"); // the echo was caught + redacted
  expect(await taintDetail.textContent()).not.toContain(KEY);

  // (8) NO KEY LEAK across the entity-DB surfaces (and the page, since the echo never hit the trail)
  const storeJson = await page.evaluate(() => JSON.stringify((window as any).__kipi.entityDb()));
  expect(storeJson).not.toContain(KEY);
  expect(storeJson).toContain("REDACTED"); // positive: redaction ran, the echo was not merely dropped
  const ipViewJson = await page.evaluate((id) => JSON.stringify((window as any).__kipi.entityView(id)), ids.ip);
  expect(ipViewJson).not.toContain(KEY);
  const edgeViewJson = await page.evaluate(([a, b]) => JSON.stringify((window as any).__kipi.edgeView(a, b)), [ids.ip, ids.dom] as const);
  expect(edgeViewJson).not.toContain(KEY);
  expect(await page.evaluate(() => document.body.textContent || "")).not.toContain(KEY);
  // the secret namespace is never readable via the debug hook
  const secretThrew = await page.evaluate(() => {
    try { (window as any).__kipi.getCase("secret:anthropic_key"); return false; } catch { return true; }
  });
  expect(secretThrew).toBe(true);

  // (9) NO unexpected egress (the scripted wire + the entity DB make zero real network calls)
  expect(external).toEqual([]);

  // (10) screenshot for the manual visual-parity check vs the webapp node card (D11, not automated)
  await page.screenshot({ path: "test-results/kipi-entity-db.png", fullPage: true });
});
