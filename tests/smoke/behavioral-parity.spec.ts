import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// clu-behavioral-smoke (the founder's DONE-GATE): drive the REAL front door through the actual UI — the
// chat intake (attach a fixture file + an image) -> retained entity DB -> the report, while the home graph
// remains a discovery-grow surface. This is the structural fix for "a wrong-data graph shipped green":
// extraction parity is checked against the committed original-derived baseline, while graph rendering follows
// the founder-approved discovery-grow carve-out.
//
// The baseline is produced by behavioral_baseline_gen.py from the ORIGINAL's OWN code — extract_all
// (entities) AND infer_relationships (co-occurrence edges, proximity-based) — so the diff is a true
// cross-implementation comparison, never a re-stated kipi assumption (codex).
//
// Parity assertions (UPDATED — D1 graph carve-out, founder 2026-06-24):
//   - entities: kipi EQUALS the original (same extraction — the deterministic extractors are untouched).
//   - edges: ZERO at ingest. The behavioral reference for graph-edge growth is re-pointed from the webapp
//     to the 4_points ops-log: a file dump renders typed pivot points, NOT the intake co-occurrence
//     hairball (reproduced at 13 nodes / 54 edges). The coOccur signal is preserved for the agent and Q&A
//     relatedness; the agent draws *investigated* edges as it digs. Recorded in parity-manifest
//     binding_directive; certified by tests/agent/d2-clump-repro.test.ts.
// NOT a __kipi scripted run — intake goes through the real #chat-file input.

const BASELINE = JSON.parse(
  readFileSync(fileURLToPath(new URL("../fixtures/behavioral-baseline.json", import.meta.url)), "utf8"),
) as { entities: string[]; edges: string[] };
const FIXTURE_TEXT = readFileSync(fileURLToPath(new URL("../fixtures/behavioral-fixture.txt", import.meta.url)), "utf8");

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    // t0.gstatic.com = the domain-node favicon (founder decision 2026-06-24, CSP-allowed): a CONFIRMED
    // domain node fetches its favicon from Google — bare domain only, no key/content, intentional egress
    // (kweb-live-graph keep-all persists promoted domain nodes here). Not an unexpected leak.
    if (u.hostname === "t0.gstatic.com") return false;
    const remote = u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
    // any ws(s)/http(s) to a non-local host is egress — the zero-retention invariant covers websockets too (codex)
    return remote && /^(https?|wss?):$/.test(u.protocol);
  } catch {
    return false;
  }
}

type EntityEdge = { pair: string; kind: string };
async function graphCanonical(page: Page): Promise<{ entities: string[]; edges: EntityEdge[] }> {
  return page.evaluate(() => {
    const m = (window as unknown as { __kipi: { graphModel(): { nodes: { id: string; kind: string; label: string }[]; edges: { from: string; to: string; kind: string }[] } | null } }).__kipi.graphModel();
    if (!m) return { entities: [], edges: [] };
    const obj = m.nodes.find((n) => n.kind === "objective");
    const objId = obj ? obj.id : "";
    const labelById = new Map(m.nodes.map((n) => [n.id, n.label]));
    const entities = m.nodes.filter((n) => n.kind !== "objective").map((n) => n.label).sort();
    // entity-entity edges = anything NOT touching the objective hub (any kind — so a co_occurs->linked
    // regression is visible, not silently re-typed).
    const edges = m.edges
      .filter((e) => e.from !== objId && e.to !== objId)
      .map((e) => ({ pair: [labelById.get(e.from), labelById.get(e.to)].sort().join("::"), kind: e.kind }));
    return { entities, edges };
  });
}

async function retainedEntities(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const db = (window as unknown as { __kipi: { entityDb(): { entities: Record<string, { label: string }> } } }).__kipi.entityDb();
    return Object.values(db.entities).map((e) => e.label).sort();
  });
}

let external: string[] = [];

test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  page.on("websocket", (ws) => { if (isExternal(ws.url())) external.push(ws.url()); }); // codex: ws egress counts
  await page.goto("/");
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
});

test("the real front door keeps upload entities in retained surfaces while the graph waits for discovery-grow", async ({ page }) => {
  test.setTimeout(120_000);

  // (1) REAL front door: attach the fixture FILE via the chat dock's file input (the 📎 path).
  await page.setInputFiles("#chat-file", { name: "behavioral-fixture.txt", mimeType: "text/plain", buffer: Buffer.from(FIXTURE_TEXT, "utf8") });
  await expect(page.locator(".msg.agent").filter({ hasText: "Intake complete" }).first()).toBeVisible({ timeout: 30_000 });

  // (2) PARITY DIFF vs the ORIGINAL baseline: extraction is unchanged and retained in the entity DB.
  // Discovery-grow means a raw upload does NOT dump nodes onto the graph. The graph grows when a dig
  // promotes a lead.
  await expect.poll(async () => retainedEntities(page), { timeout: 10_000 }).toEqual(BASELINE.entities);
  const got = await graphCanonical(page);
  expect(got.entities).toEqual([]);
  expect(got.edges.length).toBe(0);

  // (3) The report AUTO-EXISTS and names EVERY one of the fixture's known entities (codex: not just 3).
  await page.evaluate((r) => { location.hash = "#" + r; }, "/report");
  await expect(page.locator(".report-doc")).toBeVisible();
  for (const e of BASELINE.entities) {
    await expect(page.locator(".report-doc")).toContainText(e);
  }

  // (4) The image OCR intake path works through the same front door and retains a known entity.
  await page.evaluate((r) => { location.hash = "#" + r; }, "/");
  const dataUrl = await page.evaluate(() => {
    const c = document.createElement("canvas");
    c.width = 640; c.height = 160;
    const ctx = c.getContext("2d")!;
    ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, c.width, c.height);
    ctx.fillStyle = "#000000"; ctx.font = "bold 56px sans-serif";
    ctx.fillText("8.8.8.8", 40, 100); // a clean IP — digits OCR very reliably
    return c.toDataURL("image/png");
  });
  const imgBuffer = Buffer.from(dataUrl.split(",")[1], "base64");
  await page.setInputFiles("#chat-file", { name: "scan.png", mimeType: "image/png", buffer: imgBuffer });
  // Wait directly for the OCR'd entity to reach retained entity storage, not for an "Intake complete" message. Chat
  // history now persists + replays across the nav-home above (clu-chat-persist), so a STALE "Intake
  // complete" from the earlier .txt intake is already on screen; matching it would short-circuit the wait
  // before this image's async OCR finishes. Polling the retained entity DB asserts the real outcome and is
  // robust to replayed history.
  await expect.poll(async () => retainedEntities(page), { timeout: 90_000 })
    .toContain("8.8.8.8");
  const afterImage = await retainedEntities(page);
  expect(afterImage.length).toBeGreaterThan(BASELINE.entities.length);
  const afterImageGraph = await graphCanonical(page);
  expect(afterImageGraph.entities).toEqual([]);
  expect(afterImageGraph.edges).toEqual([]);

  // (5) zero off-allowlist egress (http(s) AND ws(s)) across the whole real-path run.
  expect(external).toEqual([]);
});
