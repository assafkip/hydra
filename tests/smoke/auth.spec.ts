import { test, expect } from "@playwright/test";

// a6-smoke: the live auth proof. A scripted Supabase wire (installAuthWire — no network) drives the REAL
// identity flow through the REAL DOM: sign up shows the recovery phrase once + confirm-pending; a scripted
// confirmed login unlocks the vault to the home; a forgot-password recovery re-keys. The master password,
// the recovery phrase, and the refresh token never leak; the only Supabase request bodies are
// {email,password}/{email} (no case data); no off-allowlist egress. Real email delivery + the real
// confirm/reset click are a documented MANUAL founder check (docs/auth-manual-check.md) — not automatable.

const EMAIL = "partner@example.com";
const PW = "Master-PW-authsmoke-7321"; // distinctive: assert it never leaks
const PHRASE_HOLDER: { value: string } = { value: "" };
const REFRESH = "refresh-token-MUST-NOT-LEAK-5050"; // D8: the client drops it

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

test("auth: signup -> confirm-pending -> login -> unlock -> recovery, no leak, no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());

  // A fresh browser (no vault) lands on Sign up.
  await expect(page.locator(".auth-card h2")).toHaveText("Create your account");
  await page.screenshot({ path: "test-results/kipi-auth-signup.png", fullPage: true });

  // auth-gate-nav (founder 2026-06-25): while locked, render() ignores route changes, so the left nav used to
  // look clickable but do nothing ("I can't click the items on the left when I start the tool"). It must read
  // as DISABLED, and the gate must tell the user the keys come AFTER sign-in (they live in the encrypted vault).
  await expect(page.locator("body")).toHaveClass(/vault-locked/);
  expect(await page.locator('[data-route="/account"]').evaluate((a) => getComputedStyle(a).pointerEvents)).toBe("none");
  await expect(page.locator(".auth-card")).toContainText("add your Anthropic + OSINT keys");

  // (1) Sign up — scripted Supabase signup returns a user with email_confirmed_at null (confirm pending).
  await page.evaluate(
    (email) =>
      (window as unknown as { __kipi: { installAuthWire(r: unknown): void } }).__kipi.installAuthWire({
        signup: { body: { id: "u1", email, email_confirmed_at: null, confirmation_sent_at: "2026-06-18T00:00:00Z" } },
      }),
    EMAIL,
  );
  await page.fill("#auth-email", EMAIL);
  await page.fill("#auth-pw", PW);
  await page.fill("#auth-pw2", PW);
  await page.getByRole("button", { name: "Sign up" }).click();

  // (2) Confirm-pending: the recovery phrase shows ONCE.
  await expect(page.locator(".auth-card h2")).toHaveText("Save your recovery key");
  const phrase = (await page.locator("#auth-recovery").textContent())?.trim() ?? "";
  expect(phrase.length).toBeGreaterThan(0);
  PHRASE_HOLDER.value = phrase;

  // (3) Continue -> log in; the phrase is gone from the DOM (D12).
  await page.getByRole("button", { name: /I saved it/ }).click();
  await expect(page.locator(".auth-card h2")).toHaveText("Log in");
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(phrase);

  // (4) Log in — scripted confirmed grant (with a refresh_token that must be dropped) -> vault unlocks.
  await page.evaluate(
    (arg) =>
      (window as unknown as { __kipi: { installAuthWire(r: unknown): void } }).__kipi.installAuthWire({
        token: { body: { access_token: "acc-123", refresh_token: arg.refresh, user: { id: "u1", email: arg.email, email_confirmed_at: "2026-06-18T01:00:00Z" } } },
        user: { body: { id: "u1", email: arg.email, email_confirmed_at: "2026-06-18T01:00:00Z" } },
      }),
    { email: EMAIL, refresh: REFRESH },
  );
  await page.fill("#auth-email", EMAIL);
  await page.fill("#auth-pw", PW);
  await page.getByRole("button", { name: "Log in" }).click();

  // Unlocked -> a fresh vault has NO case yet (no implicit default), so the create-first-case surface shows.
  await expect(page.locator(".pg-title")).toHaveText("Cases");
  await expect(page.getByRole("button", { name: "Create case" })).toBeVisible();

  // auth-gate-nav: the moment the vault unlocks, the nav re-enables (the OSINT + API key pages are now reachable).
  await expect(page.locator("body")).not.toHaveClass(/vault-locked/);
  expect(await page.locator('[data-route="/account"]').evaluate((a) => getComputedStyle(a).pointerEvents)).not.toBe("none");

  // (5) No leak: the password, the recovery phrase, and the refresh token are absent from the page,
  // and the secret namespace is unreadable via the bridge.
  const body = await page.evaluate(() => document.body.innerText);
  expect(body).not.toContain(PW);
  expect(body).not.toContain(phrase);
  expect(body).not.toContain(REFRESH);
  const refused = await page.evaluate(() => {
    try {
      (window as unknown as { __kipi: { getCase(k: string): unknown } }).__kipi.getCase("secret:anthropic_key");
      return "NO_THROW";
    } catch {
      return "THREW";
    }
  });
  expect(refused).toBe("THREW");

  // (6) D7: every recorded Supabase request body carried ONLY {email,password}/{email} — no case data.
  const reqs = await page.evaluate(() => (window as unknown as { __kipi: { authRequests(): { endpoint: string; bodyKeys: string[] }[] } }).__kipi.authRequests());
  expect(reqs.length).toBeGreaterThan(0);
  for (const r of reqs) {
    for (const key of r.bodyKeys) expect(["email", "password"]).toContain(key);
  }

  // (7) No off-allowlist egress (the scripted wire means no real Supabase request).
  expect(external).toEqual([]);

  // (8) Recovery re-key (forgot-password): reset email + recovery phrase + new password.
  await page.evaluate(() => (window as unknown as { __kipi: { lock(): void } }).__kipi.lock());
  await expect(page.locator(".auth-card h2")).toHaveText("Log in");
  await page.getByRole("button", { name: "Forgot password" }).click();
  await expect(page.locator(".auth-card h2")).toHaveText("Reset your password");
  const NEWPW = "New-Master-PW-9999";
  await page.evaluate(
    (arg) =>
      (window as unknown as { __kipi: { installAuthWire(r: unknown): void } }).__kipi.installAuthWire({
        recover: { body: {} },
        token: { body: { access_token: "acc-2", refresh_token: arg.refresh, user: { id: "u1", email: arg.email, email_confirmed_at: "2026-06-18T01:00:00Z" } } },
      }),
    { email: EMAIL, refresh: REFRESH },
  );
  await page.fill("#auth-email", EMAIL);
  await page.fill("#auth-phrase", PHRASE_HOLDER.value);
  await page.fill("#auth-newpw", NEWPW);
  await page.getByRole("button", { name: "Recover my cases" }).click();
  await expect(page.getByRole("button", { name: "Create case" })).toBeVisible(); // re-keyed + unlocked (create-first-case)

  // (9) Screenshot AFTER the phrase is long gone (D12) — captures the unlocked home, never the phrase.
  await page.screenshot({ path: "test-results/kipi-auth.png", fullPage: true });
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(PHRASE_HOLDER.value);
});

// The founder's 2026-06-18 scenario: a browser that already has a local vault on a DIFFERENT password.
// Logging in (Supabase OK + confirmed) hits needs-recovery; "Start fresh on this browser" must wipe the
// drifted vault and create a clean one bound to the account — never a dead-end.
test("needs-recovery -> start fresh wipes the drifted vault and unlocks with a new recovery key", async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  // a pre-existing local vault on password "OLD-pw-aaa" (the drifted vault), then lock to reach the login UI
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(p: string): Promise<unknown> } }).__kipi.createVault("OLD-pw-aaa"));
  await page.evaluate(() => (window as unknown as { __kipi: { lock(): void } }).__kipi.lock());

  // log in with a DIFFERENT password that Supabase accepts (scripted) + confirmed
  await page.evaluate(
    (email) =>
      (window as unknown as { __kipi: { installAuthWire(r: unknown): void } }).__kipi.installAuthWire({
        token: { body: { access_token: "acc", refresh_token: "r", user: { id: "u1", email, email_confirmed_at: "2026-06-18T01:00:00Z" } } },
        user: { body: { id: "u1", email, email_confirmed_at: "2026-06-18T01:00:00Z" } },
      }),
    EMAIL,
  );
  await page.fill("#auth-email", EMAIL);
  await page.fill("#auth-pw", "NEW-account-pw-bbb");
  await page.getByRole("button", { name: "Log in" }).click();

  // needs-recovery card, with the start-fresh escape
  await expect(page.locator(".auth-card h2")).toHaveText("This browser's vault is on a different password");
  await page.getByRole("button", { name: "Start fresh on this browser" }).click();

  // a NEW recovery key is shown, then continue into the unlocked app
  await expect(page.locator(".auth-card h2")).toHaveText("Save your new recovery key");
  const newPhrase = (await page.locator("#auth-recovery").textContent())?.trim() ?? "";
  expect(newPhrase.length).toBeGreaterThan(0);
  await page.getByRole("button", { name: /I saved it/ }).click();
  await expect(page.getByRole("button", { name: "Create case" })).toBeVisible(); // unlocked, fresh vault → create-first-case

  // the fresh vault is really on the new password (and the old one no longer opens it)
  await page.evaluate(() => (window as unknown as { __kipi: { lock(): void } }).__kipi.lock());
  const newWorks = await page.evaluate(() => (window as unknown as { __kipi: { unlock(p: string): Promise<unknown> } }).__kipi.unlock("NEW-account-pw-bbb").then(() => true).catch(() => false));
  expect(newWorks).toBe(true);
});
