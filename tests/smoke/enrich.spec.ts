import { test, expect, type Page } from "@playwright/test";

// en-smoke: the live enrich proof. The real Keys & providers surface renders (NOT the old
// port-pending card); a provider key is saved through the REAL DOM (D4 — no __kipi.saveProviderKey
// bridge); a scripted enrich whose canned provider response ECHOES the key lands the clean gated
// entity while the key is REDACTED out of the store, the record, and the page; the secret namespace
// stays unreadable via the bridge; and no off-allowlist egress occurs (the scripted fetch is the
// only "provider" call).

const KEY = "shdn-SMOKE-secret-5151"; // distinctive provider key for the no-leak sweep

// A MALICIOUS Shodan response: it echoes the saved key in an entity value (a domain) AND in a note
// (the org -> the asn note), alongside a clean infra entity. Redaction must scrub both.
const MALICIOUS = {
  ip_str: "8.8.8.8",
  hostnames: ["good.example.com"],
  domains: [`evil-${KEY}.com`], // entity VALUE embeds the key
  asn: "AS15169",
  org: KEY, // -> the asn entity NOTE embeds the key
  ports: [443],
};

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

test("enrich: real settings render, scripted enrich lands gated entities, no key leak, no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await freshVault(page);

  // (1) The REAL provider catalog + the blocked-providers section render.
  await page.click('a[data-route="/enrich"]');
  await expect(page.locator(".pg-title")).toHaveText("OSINT enrichment");
  await expect(page.locator(".enr-h2").first()).toHaveText("Enrich an entity"); // ux-enrich: page now leads with the entity-first action
  const shodanRow = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await expect(shodanRow.locator(".pg-chip").first()).toContainText("not configured");
  await expect(page.locator(".enr-blocked", { hasText: "VirusTotal" })).toContainText("needs your Worker URL"); // PRD-5b: the user-proxy tier is built (unset state)

  // (2) Save the provider key through the REAL DOM (D4: no __kipi.saveProviderKey bridge).
  await shodanRow.locator(".enr-key").fill(KEY);
  await shodanRow.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.locator(".enr-card", { hasText: "Shodan" }).first().locator(".pg-chip").first()).toContainText("configured");

  // (3) Run a scripted enrich whose canned response echoes the key AND returns a clean infra entity.
  const result = await page.evaluate(
    (resp) => (window as unknown as { __kipi: { runScriptedEnrich(id: string, t: string, r: unknown): Promise<{ count: number; objective: string }> } }).__kipi.runScriptedEnrich("shodan", "8.8.8.8", resp),
    MALICIOUS,
  );
  expect(result.count).toBeGreaterThanOrEqual(1);
  expect(result.objective).toBe("enrich: shodan 8.8.8.8");

  // (4) The gated entity LANDED in the client entity DB.
  const dbJson = await page.evaluate(() => JSON.stringify((window as unknown as { __kipi: { entityDb(): unknown } }).__kipi.entityDb()));
  expect(dbJson).toContain("good.example.com");

  // (5) The key is ABSENT from the entity DB, the stored run record, and the page body.
  expect(dbJson).not.toContain(KEY);
  const recJson = await page.evaluate(() =>
    JSON.stringify((window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("run:enrich: shodan 8.8.8.8")),
  );
  expect(recJson).not.toContain(KEY);
  expect(recJson).toContain("[REDACTED]"); // proof the malicious echo was actually scrubbed
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(KEY);

  // (6) The secret namespace is unreadable via the bridge.
  const refused = await page.evaluate(() => {
    try {
      (window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("secret:shodan_key");
      return "NO_THROW";
    } catch {
      return "THREW";
    }
  });
  expect(refused).toBe("THREW");

  // (7) No off-allowlist egress: the scripted fetch was the only "provider" call.
  expect(external).toEqual([]);

  await page.screenshot({ path: "test-results/kipi-enrich.png", fullPage: true });
});
