import { test, expect, type Page } from "@playwright/test";

// sf-enrich parity verification (PRD prd-kipi-web-enrich-2026-06-18, codex finding-1).
// The ported /enrich page was a REDUCED copy; this proves the BUILD reaches the original's structure:
// a stats header (NO $), a per-provider metadata card grid (category + description + docs link), a key
// panel (show/hide + Save + Clear + a key-source pill), a per-provider run, a Recent-runs TABLE, and a
// Run-detail MODAL. Offline-safe: reset → createVault → save a key through the real DOM → a scripted
// enrich (canned response, zero egress) lands a run → the table + modal reflect it. RCA #2: live, not a
// code read. The $-cost metering is intentionally absent (founder 2026-06-18: BYO-key, no metering).

const KEY = "shdn-VERIFY-7788";
const CANNED = { ip_str: "8.8.8.8", hostnames: ["dns.example.com"], domains: ["resolver.example.com"], asn: "AS15169", org: "ExampleNet", ports: [443] };

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    // t0.gstatic.com = the domain-node favicon (founder decision 2026-06-24, CSP-allowed): a CONFIRMED
    // domain node fetches its favicon from Google — bare domain only, no key/content, intentional egress
    // (kweb-live-graph keep-all persists promoted domain nodes). Not an unexpected leak.
    if (u.hostname === "t0.gstatic.com") return false;
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

async function freshVault(page: Page): Promise<void> {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
}

// ux-enrich (brief §18 P1): the per-provider key-cards now live under a "Configure providers" <details>
// that auto-collapses once any key is saved. Open it before interacting with a card.
async function openConfig(page: Page): Promise<void> {
  const details = page.locator(".enr-configure");
  const open = await details.evaluate((el) => (el as HTMLDetailsElement).open);
  if (!open) await page.locator(".enr-configure-summary").click();
}

test.use({ viewport: { width: 1440, height: 1200 } });

test("enrich page is built to the original structure: stats + metadata cards + key panel + run + recent-runs table + modal", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => { if (isExternal(r.url())) external.push(r.url()); });

  await freshVault(page);
  await page.click('a[data-route="/enrich"]');

  // (1) STATS HEADER — run count + entities enriched, and NO $ anywhere on the page.
  await expect(page.locator(".pg-title")).toHaveText("OSINT enrichment");
  await expect(page.locator(".enr-stats")).toContainText("0 runs");
  await expect(page.locator(".enr-stats")).toContainText("0 entities enriched");

  // (1b) ENTITY-FIRST PATH (brief §18 P0) — the page leads with "Enrich an entity" + the run-all action.
  await expect(page.locator(".enr-h2").first()).toHaveText("Enrich an entity");
  await expect(page.getByRole("button", { name: "Run all applicable providers" })).toBeVisible();

  // (2) PROVIDER METADATA CARD — under the "Configure providers" details (open on a fresh, 0-key vault).
  await expect(page.locator(".enr-configure-summary")).toContainText("Configure providers");
  await expect(page.locator(".enr-configure-summary")).toContainText("0/9 configured");
  await openConfig(page);
  const shodan = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await expect(shodan.locator(".enr-cat")).toHaveText("host-scan");
  await expect(shodan.locator(".enr-desc")).toContainText("IP host record");
  await expect(shodan.locator("a.enr-docs")).toHaveAttribute("href", /shodan/);

  // (3) KEY PANEL — show/hide toggle, key-source pill (not set), Save; Run disabled until configured.
  await expect(shodan.locator(".enr-keysrc")).toContainText("not set");
  await expect(shodan.locator(".enr-run-btn")).toBeDisabled();
  const keyInput = shodan.locator(".enr-key");
  await expect(keyInput).toHaveAttribute("type", "password");
  await shodan.getByRole("button", { name: "show", exact: true }).click();
  await expect(keyInput).toHaveAttribute("type", "text"); // show/hide really toggles the input type
  await shodan.getByRole("button", { name: "hide", exact: true }).click();
  await expect(keyInput).toHaveAttribute("type", "password");

  // save a key through the real DOM → the pill flips to "saved locally", Clear appears, Run enables
  await keyInput.fill(KEY);
  await shodan.getByRole("button", { name: "Save", exact: true }).click();
  await openConfig(page); // saving a key re-renders + auto-collapses the config; re-open to inspect the card
  const shodanAfter = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await expect(shodanAfter.locator(".enr-keysrc")).toContainText("saved locally");
  await expect(shodanAfter.getByRole("button", { name: "Clear", exact: true })).toBeVisible();
  await expect(shodanAfter.locator(".enr-run-btn")).toBeEnabled();

  // (4) PER-PROVIDER RUN — a scripted enrich lands a run (canned response, no live network).
  await page.evaluate(
    (resp) => (window as unknown as { __kipi: { runScriptedEnrich(id: string, t: string, r: unknown): Promise<{ count: number }> } }).__kipi.runScriptedEnrich("shodan", "8.8.8.8", resp),
    CANNED,
  );
  await page.click('a[data-route="/"]');
  await page.click('a[data-route="/enrich"]'); // re-render so the table + stats pick up the run

  // (5) RECENT RUNS TABLE — header columns + a row for the run; NO "Cost"/"$" column.
  const table = page.locator(".enr-table");
  await expect(table).toBeVisible();
  await expect(table.locator("thead th")).toContainText(["#", "Provider", "Target", "Status", "Entity", "When"]);
  await expect(table.locator("thead")).not.toContainText("Cost");
  const row = table.locator(".enr-run-row").first();
  await expect(row).toContainText("shodan");
  await expect(row).toContainText("success");
  await expect(row.locator(".enr-td-target")).toHaveText("8.8.8.8"); // the run's target column
  await expect(row.locator(".enr-td-when")).not.toHaveText("—"); // a real timestamp, not the legacy blank
  await expect(page.locator(".enr-stats")).toContainText("1 run");

  // (6) RUN-DETAIL MODAL — a row click opens it with the run's extracted findings; close works.
  await expect(page.locator(".enr-modal")).toBeHidden();
  await row.click();
  const modal = page.locator(".enr-modal");
  await expect(modal).toBeVisible();
  await expect(modal.locator(".enr-modal-title")).toContainText("shodan");
  await expect(modal.locator(".enr-finding").first()).toBeVisible();
  await page.screenshot({ path: "test-results/verify-enrich-modal.png", fullPage: true });
  await modal.getByRole("button", { name: "✕" }).click();
  await expect(modal).toBeHidden();

  // (7) CLEAR truly reverts: clicking Clear on the Shodan card drops the pill to "not set" + disables Run.
  await openConfig(page); // the re-render after the scripted run re-collapsed the config
  const shodanCard = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await shodanCard.getByRole("button", { name: "Clear", exact: true }).click();
  const shodanCleared = page.locator(".enr-card", { hasText: "Shodan" }).first();
  await expect(shodanCleared.locator(".enr-keysrc")).toContainText("not set");
  await expect(shodanCleared.locator(".enr-run-btn")).toBeDisabled();

  // (8) free/pro split (founder 2026-07-08): the CORS-blocked providers show as a locked "Pro" teaser (no
  // worker setup in the free tool); NO $-cost metering anywhere; zero egress.
  await expect(page.locator(".enr-blocked", { hasText: "VirusTotal" })).toContainText("Pro");
  await expect(page.locator('input[placeholder="https://<name>.workers.dev"]')).toHaveCount(0); // worker setup removed
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(KEY);
  expect(body).not.toContain("$"); // no $-cost metering on the client page (founder-signed divergence)
  expect(external, "zero external egress").toEqual([]);

  await page.screenshot({ path: "test-results/verify-enrich.png", fullPage: true });
});
