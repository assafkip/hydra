import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// ct-wire smoke (the live proof): with two alias-like entities seeded, the /entities page exposes the
// case-level Consolidate + Refine-types affordances; a scripted classify wire returns a merge group + a
// type suggestion; a model reason of <img onerror> renders as LITERAL text (codex D7); the Anthropic key
// leaks nowhere; no off-allowlist egress.

const APIKEY = "sk-ant-CONSOL-smoke-9090";
const XSS = "<img src=x onerror=alert(1)>"; // the model reason — must render literally, never as markup

// seed two alias-like domains (no tool corroboration -> leads, but in the entity DB) via a scripted run
const SEED_TURNS = [
  {
    content: [
      {
        type: "text",
        text: 'Done.\n```json\n{"findings":[{"entity":"alpha.example.com","entity_type":"domain"},{"entity":"alpha-cdn.example.com","entity_type":"domain"}]}\n```',
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];
const CONSOLIDATE_TEXT = JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: XSS }] });
const TYPE_TEXT = JSON.stringify({ types: [{ id: "e0", type: "url", confidence: "high", reason: "looks like a url" }] });

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

test("entities: consolidate + typing AI suggestions render (textContent-only); no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) Anthropic key via the real home keys card.
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", APIKEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  // (2) Seed two alias entities + install the scripted classify wire.
  await page.evaluate((turns) => (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation("seed aliases", turns), SEED_TURNS);
  await page.evaluate(
    ({ c, t }) => (window as unknown as { __kipi: { installChatWire(s: unknown): void } }).__kipi.installChatWire({ consolidateText: c, typeText: t }),
    { c: CONSOLIDATE_TEXT, t: TYPE_TEXT },
  );

  // (3) Open /entities and run Consolidate.
  await gotoRoute(page, "/entities");
  await expect(page.locator(".ent-row")).toHaveCount(2);
  await page.getByRole("button", { name: "Consolidate (AI)" }).click();
  await expect(page.locator(".cons-merges")).toBeVisible();
  await expect(page.locator(".cons-merges")).toContainText("role channel");
  await expect(page.locator(".cons-merges")).toContainText("alpha-cdn.example.com");
  await expect(page.locator(".cons-merges")).toContainText("lead"); // member status shown (D3/D11)

  // (4) XSS is literal text, not markup (D7).
  await expect(page.locator(".cons-reason").first()).toHaveText(XSS);
  expect(await page.locator("img[onerror]").count()).toBe(0);

  // (5) Run Refine types.
  await page.getByRole("button", { name: "Refine types (AI)" }).click();
  await expect(page.locator(".cons-types")).toContainText("domain → url");

  // (6) No key leak in the body, the __kipi suggestions, or the rendered suggestions.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(APIKEY);
  const hookJson = await page.evaluate(async () => JSON.stringify(await (window as unknown as { __kipi: { consolidate(): Promise<unknown> } }).__kipi.consolidate()));
  expect(hookJson).not.toContain(APIKEY);
  expect(hookJson).toContain("channel"); // the hook returns the real suggestions

  // (7) No off-allowlist egress.
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-consolidate.png", fullPage: true });
});
