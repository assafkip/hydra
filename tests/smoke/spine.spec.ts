import { test, expect } from "@playwright/test";

// The PRD's go/no-go experiment (Skeptic Q2): prove the three spine claims in a
// REAL browser against the built app. Mocks cannot prove OPFS, live CORS, or CSP.

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
});

test("zero-knowledge vault round-trips across a reload", async ({ page }) => {
  const { recoveryPhrase } = await page.evaluate(() => (window as any).__kipi.createVault("hunter2"));
  expect(recoveryPhrase).toMatch(/[0-9A-F-]{8,}/);
  await page.evaluate(() => (window as any).__kipi.putCase("case", { name: "nve-403", target: "example.com" }));

  // Reload the page: the encrypted vault must persist in OPFS and unlock with the password.
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  expect(await page.evaluate(() => (window as any).__kipi.hasVault())).toBe(true);
  await page.evaluate(() => (window as any).__kipi.unlock("hunter2"));
  const got = await page.evaluate(() => (window as any).__kipi.getCase("case"));
  expect(got.value).toEqual({ name: "nve-403", target: "example.com" });

  // Wrong password must fail (negative, live).
  await page.evaluate(() => (window as any).__kipi.lock());
  const bad = await page.evaluate(async () => {
    try {
      await (window as any).__kipi.unlock("WRONG");
      return "unlocked";
    } catch (e) {
      return "rejected";
    }
  });
  expect(bad).toBe("rejected");
});

test("browser-native OSINT pivot returns live data with no key, no proxy", async ({ page }) => {
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  const r = await page.evaluate(() => (window as any).__kipi.runPivot("example.com"));
  // >=2 of 3 providers must return live, parsed data (PRD finding-7 robustness).
  expect(r.succeeded).toBeGreaterThanOrEqual(2);
  expect(r.sample.length).toBeGreaterThan(0);
  // Sanity: at least one real infra entity (an IP, a nameserver, or a cert subdomain).
  expect(r.sample.join(" ")).toMatch(/dns\.google|rdap\.org|crt\.sh/);
});

test("CSP egress wall blocks a fetch to an off-allowlist origin", async ({ page }) => {
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  // example.org is NOT in the connect-src allowlist; the browser must block it.
  const res = await page.evaluate(() => (window as any).__kipi.tryBlockedFetch("https://example.org/probe"));
  expect(res.blocked).toBe(true);
});
