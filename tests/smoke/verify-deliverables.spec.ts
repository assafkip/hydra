import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-deliverables smoke (the RENDER GATE — review finding 7): the /deliverables surface renders the case
// brief as MARKDOWN (not the old raw <pre>), and the page Regenerate/Generate-brief button drives the
// OFFLINE synthesizeFetch (scripted wire, no key on the wire, zero egress). This is what makes the
// sf-deliverables flip honest — a hollow flip that left the <pre> in place fails here (the manifest
// one-liner cannot see the render).

const APIKEY = "sk-ant-DELIV-smoke-7777";

// the scripted case brief — exercises every renderBriefMarkdown construct: h1/h2, a [[entity]] nav, an
// http(s) link, and a GFM table. The renderer must turn these into elements, never literal ## tokens.
const BRIEF_MD = [
  "# Investigation brief",
  "",
  "## Executive summary",
  "",
  "The alias network fronts a token drainer. See [[alpha.example.com]] and the [docs](https://example.com/docs).",
  "",
  "| actor | role |",
  "| --- | --- |",
  "| alpha.example.com | channel |",
].join("\n");

// a seed run with two findings → entries in the case so synthesizeCaseBrief actually calls the scripted
// wire (a case with zero promoted+leads writes a no-evidence brief WITHOUT an LLM call).
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

test("deliverables: the case brief renders as MARKDOWN (not <pre>) and the Generate/Regenerate button drives the offline synthesizeFetch; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) key via the real /account card, then seed a run + install the scripted synthesize wire.
  await gotoRoute(page, "/account");
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]');
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("seed deliverables", turns), SEED_TURNS);
  await page.evaluate((sy) => (window as unknown as { __kipi: { installChatWire(spec: unknown): void } }).__kipi.installChatWire({ synthesizeText: sy }), BRIEF_MD);

  // (2) /deliverables with no brief yet → the affordance reads "Generate brief". Click it: this drives the
  // page synthesize PageDep → synthesizeCaseBrief via the scripted wire (offline).
  await gotoRoute(page, "/deliverables");
  await page.getByRole("button", { name: "Generate brief" }).click();

  // (3) the brief renders as MARKDOWN inside a .markdown card — the under-render is GONE.
  const body = page.locator(".markdown.del-body");
  await expect(body.locator("h1")).toContainText("Investigation brief");
  await expect(body.locator("h2")).toContainText("Executive summary");
  // the [[entity]] nav renders as a CSP-safe clickable span (no inline onclick).
  await expect(body.locator("span.brief-entity")).toContainText("alpha.example.com");
  // the http(s) link renders as an anchor; the GFM table renders as a <table>.
  await expect(body.locator('a[href="https://example.com/docs"]')).toBeVisible();
  await expect(body.locator("table td", { hasText: "channel" })).toBeVisible();

  // (4) NO raw <pre class="del-body"> for the brief body (the old under-render) and NO literal ## token.
  await expect(page.locator("pre.del-body")).toHaveCount(0);
  await expect(page.locator(".del-body")).not.toContainText("## Executive");

  // (5) the button now reads "Regenerate brief" (a brief exists) — clicking it re-drives synthesizeFetch.
  await page.getByRole("button", { name: "Regenerate brief" }).click();
  await expect(page.locator(".markdown.del-body h2")).toContainText("Executive summary");

  await page.screenshot({ path: "test-results/kipi-deliverables.png", fullPage: true });

  // (6) the brief was persisted at brief:case with a builtOn count (the stale-banner input), key-redacted.
  const brief = await page.evaluate(() =>
    (window as unknown as { __kipi: { getCase(k: string): { value: { brief?: string; builtOn?: number } | null } } }).__kipi.getCase("brief:case").value,
  );
  expect(brief?.brief, "synthesize persisted the case brief").toContain("Executive summary");
  expect(typeof brief?.builtOn, "the brief carries a builtOn run count for the stale banner").toBe("number");
  expect(JSON.stringify(brief)).not.toContain(APIKEY);

  // (7) no key in the page body, and no off-allowlist egress (the whole flow ran on the scripted wire).
  const pageText = await page.evaluate(() => document.body.innerText);
  expect(pageText).not.toContain(APIKEY);
  expect(external).toEqual([]);
});
