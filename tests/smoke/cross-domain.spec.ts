import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// td-smoke (the live proof): two runs of DIFFERENT detected types (crypto-fraud + intrusion-apt)
// share a bridge entity, so it surfaces on Cross-domain with BOTH type labels (NOT the old
// port-pending info card). The bridge entity value echoes the saved key (via putCase, clean
// objective) and is REDACTED (D8). No off-allowlist egress; the secret hook is refused.

const KEY = "sk-ant-XDSMOKE-secret-2424";

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.hostname === "t0.gstatic.com" && u.pathname === "/faviconV2") return false;
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

test("two differently-typed runs share a bridge entity -> it surfaces on Cross-domain with both types; redacted; no egress", async ({ page }) => {
  // seed two runs whose objectives + entities drive DIFFERENT detected types, sharing one (key-bearing)
  // bridge domain. The objectives are key-clean (so the runs are not dropped); the bridge value carries
  // the key (so the redaction path is exercised — D8).
  await page.evaluate((key) => {
    const k = (window as any).__kipi;
    const bridge = `leaked-${key}-bridge.example`;
    const a = (entity: string, type: string) => ({ entity, entity_type: type, grade: "A", source_count: 2, infra_source_count: 2 });
    const run = (objective: string, promoted: unknown[]) => ({ objective, steps: [], promoted, leads: [], usage: {}, stopReason: "end_turn" });
    return Promise.all([
      k.putCase("run:rugpull drainer wallet probe", run("rugpull drainer wallet probe", [a("0xabc", "wallet"), a(bridge, "domain")])),
      k.putCase("run:malware c2 backdoor probe", run("malware c2 backdoor probe", [a("1.1.1.1", "ip"), a("deadbeef", "hash_sha256"), a(bridge, "domain")])),
    ]);
  }, KEY);

  // __kipi.crossDomain(): the bridge entity is listed with BOTH exact type labels (D10); key redacted (D8)
  const xd = await page.evaluate(() => (window as any).__kipi.crossDomain());
  expect(xd.length).toBeGreaterThanOrEqual(1);
  const bridge = xd.find((e: any) => e.label.includes("bridge.example"));
  expect(bridge).toBeTruthy();
  expect(bridge.types).toContain("crypto-fraud");
  expect(bridge.types).toContain("intrusion-apt");
  const xjson = JSON.stringify(xd);
  expect(xjson).not.toContain(KEY);
  expect(xjson.toLowerCase()).toContain("[redacted]");

  // the /cross-domain PAGE shows the entity + the two type chips; the old port-pending card is GONE
  await gotoRoute(page, "/cross-domain");
  await expect(page.locator(".pg-title")).toHaveText("Cross-type");
  await expect(page.locator(".xd-row")).toHaveCount(1);
  await expect(page.locator(".xd-types")).toContainText("crypto-fraud");
  await expect(page.locator(".xd-types")).toContainText("intrusion-apt");
  await expect(page.locator(".pg-body")).not.toContainText("not yet ported");
  await expect(page.locator(".pg-body")).not.toContainText("later client chunk");

  // no key on the page; the secret hook refused; no off-allowlist egress
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(KEY);
  const secretThrows = await page.evaluate(() => {
    try { (window as any).__kipi.getCase("secret:anthropic_key"); return false; } catch { return true; }
  });
  expect(secretThrows).toBe(true);
  expect(external, `unexpected egress: ${external.join(", ")}`).toHaveLength(0);

  await page.screenshot({ path: "test-results/kipi-cross-domain.png", fullPage: true });
});
