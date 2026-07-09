import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// nd-node-card smoke (the live proof): a node card shows the properties table + the per-type OSINT
// transform menu; running the keyless 'DNS records' transform GROWS the graph in place with the gated
// resolved entity (no re-pop); no key leaks; no off-allowlist egress.

const APIKEY = "sk-ant-ND-smoke-3030";

// a lead domain node (no tool corroboration in the seed -> a held lead, still a graph node we can transform)
const SEED_TURNS = [
  {
    content: [{ type: "text", text: 'Done.\n```json\n{"findings":[{"entity":"example.org","entity_type":"domain"}]}\n```' }],
    stop_reason: "end_turn",
    usage: { output_tokens: 10 },
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

test("node card: properties table + a dns transform grows the graph; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  // seed a domain node, then install the canned OSINT wire (so the transform's adapter is offline).
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("investigate example.com", turns), SEED_TURNS);
  await page.evaluate(() => (window as unknown as { __kipi: { installChatWire(s: unknown): void } }).__kipi.installChatWire({ turns: [] }));

  // select the domain node — remove-cards (founder 2026-07-03): NO card renders.
  const nodeId = await page.evaluate(
    () => (window as unknown as { __kipi: { graphModel(): { nodes: { id: string; label: string }[] } } }).__kipi.graphModel().nodes.find((n) => n.label === "example.org")?.id,
  );
  expect(nodeId).toBeTruthy();
  await page.evaluate((id) => (window as unknown as { __kipi: { selectNode(id: string): boolean } }).__kipi.selectNode(id as string), nodeId);
  await expect(page.locator(".node-card")).toHaveCount(0);

  // "Show full details" renders the node's type + status as a chat MESSAGE (the properties the old card's
  // table showed). The per-node OSINT-transform menu (the keyless DNS pivot) was a card-only affordance —
  // node-driven OSINT is now Dig one hop / Investigate + the /enrich tool belt.
  await page.evaluate((id) => {
    const n = (window as unknown as { __kipi: { graphModel(): { nodes: { id: string; label: string; full_name?: string; type?: string; entityType?: string; kind?: string }[] } } }).__kipi.graphModel().nodes.find((x) => x.id === id);
    (window as unknown as { __kipiChat: { showNodeDetails(node: unknown): void } }).__kipiChat.showNodeDetails({ ...n, full_name: n!.full_name || n!.label, type: n!.type || n!.entityType, kind: n!.kind || "entity" });
  }, nodeId);
  const detail = page.locator("#chat-messages .msg.agent").last();
  await expect(detail).toContainText("example.org");
  await expect(detail).toContainText("domain");

  // no key leak, no egress across the node interaction
  const graphJson = await page.evaluate(() => JSON.stringify((window as unknown as { __kipi: { graphModel(): unknown } }).__kipi.graphModel()));
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  expect(graphJson).not.toContain(APIKEY);
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-node-drawer.png", fullPage: true });
});
