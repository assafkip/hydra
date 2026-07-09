import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// m3-smoke (the live proof): with a Shodan key saved, the investigator agent EXPOSES + CALLS the
// enrich_shodan tool mid-dig (the keyed tool is in the loop), its returned entity lands as a gated
// node, and a MALICIOUS provider echo of the key is redacted everywhere on the AGENT path — the tool
// step, the persisted run record, the graph, and the page — with NO off-allowlist egress. The canned
// Shodan body (in app.ts cannedOsintFetch) echoes this exact key; the smoke + app.ts share the literal.

const KEY = "shdnagentecho7777"; // == the org/domain echo in cannedOsintFetch's Shodan branch
const OBJECTIVE = "Investigate 8.8.8.8 with Shodan";

// the scripted model: turn 1 calls enrich_shodan on the IP; turn 2 reports the clean hostname.
const TURNS = [
  {
    content: [
      { type: "text", text: "Enriching the IP with the user's Shodan key." },
      { type: "tool_use", id: "e1", name: "enrich_shodan", input: { target: "8.8.8.8" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text: 'Done.\n```json\n{"findings":[{"entity":"good.example.com","entity_type":"domain","confidence":"high"}]}\n```',
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    // t0.gstatic.com = the domain-node favicon (founder decision 2026-06-24, CSP-allowed): a CONFIRMED
    // domain node fetches its favicon from Google. It carries the bare domain only (no key, no case
    // content) and is intentional egress, so it is NOT an unexpected leak. (kweb-live-graph: keep-all now
    // persists a promoted domain node here, which legitimately fetches its favicon.)
    if (u.hostname === "t0.gstatic.com") return false;
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

test("the agent uses a configured Shodan key mid-dig; entity lands gated; no key leak; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) Set the Anthropic key through the real home keys card (flips the chip).
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", "sk-ant-anything");
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run

  // (2) Save the Shodan key through the REAL /enrich DOM (no __kipi.saveProviderKey bridge).
  await page.click('a[data-route="/enrich"]');
  // each active provider is now an .enr-card with its key in the in-card keypanel (.enr-key); saving
  // re-renders /enrich, so re-locate the Shodan card and assert its "saved locally" source pill.
  const shodanCard = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await shodanCard.locator(".enr-key").fill(KEY);
  await shodanCard.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.locator(".enr-card", { hasText: "Shodan" }).first().locator(".enr-keysrc")).toContainText("saved locally");

  // (3) Back home, run a scripted investigation whose model turn calls enrich_shodan.
  await page.click('a[data-route="/"]');
  const res = await page.evaluate(
    ({ obj, turns }) =>
      (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<{ stopReason: string; promoted: string[] }> } }).__kipi.runScriptedInvestigation(obj, turns),
    { obj: OBJECTIVE, turns: TURNS },
  );
  expect(res.stopReason).toBe("end_turn");
  // the enrich tool's returned hostname landed as a gated, promoted node (proving the keyed tool is in the loop)
  expect(res.promoted).toContain("good.example.com");

  // (4) The persisted run record proves the enrich_shodan tool ran AND the malicious echo was redacted.
  const recJson = await page.evaluate(
    (obj) => JSON.stringify((window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("run:" + obj)),
    OBJECTIVE,
  );
  expect(recJson).toContain("enrich_shodan"); // the tool is in the loop's step trail
  expect(recJson).not.toContain(KEY); // the key never reaches the record (URL-borne + malicious echo)
  expect(recJson).toContain("[REDACTED]"); // proof the echoed key was actually scrubbed

  // (5) The key is absent from the graph model and the page body.
  const graphJson = await page.evaluate(() =>
    JSON.stringify((window as unknown as { __kipi: { graphModel(): unknown } }).__kipi.graphModel() ?? {}),
  );
  expect(graphJson).not.toContain(KEY);
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(KEY);

  // (6) The secret namespace stays unreadable through the bridge.
  const refused = await page.evaluate(() => {
    try {
      (window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("secret:shodan_key");
      return "NO_THROW";
    } catch {
      return "THREW";
    }
  });
  expect(refused).toBe("THREW");

  // (7) No off-allowlist egress: every provider/model call was the canned in-page fetch.
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-agent-enrich.png", fullPage: true });
});
