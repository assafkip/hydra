import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { Vault } from "../../src/vault/vault";
import { memoryStorage, type VaultStorage } from "../../src/vault/store";
import { VAULT_FILE } from "../../src/vault/location";
import { Identity, type AuthClient } from "../../src/auth/identity";
import { AuthError, type AuthUser, type SignInResult, type SignUpResult } from "../../src/auth/supabase";

// a6-identity: the identity <-> vault orchestration. A fake AuthClient + memory storage exercise every
// flow; the real vault crypto is unchanged. Secret hygiene: the password + recovery phrase never reach
// the persisted vault file; src/auth/* persists nothing outside the vault (D13).

const PW = "master-PW-aaa-1111";
const PW2 = "master-PW-bbb-2222";

class FakeClient implements AuthClient {
  signUpError: AuthError | null = null;
  signInError: AuthError | null = null;
  /** emailConfirmedAt returned by both the grant user and getUser. */
  confirmedAt: string | null = "2026-06-18T00:00:00Z";
  /** if set, signInPassword throws unless the password matches (simulates the live Supabase password). */
  supabasePassword: string | null = null;
  resetRequested: string | null = null;
  resendRequested: string | null = null;

  async signUp(email: string): Promise<SignUpResult> {
    if (this.signUpError) throw this.signUpError;
    return { user: { id: "u", email, emailConfirmedAt: null }, confirmationRequired: true };
  }
  async signInPassword(email: string, password: string): Promise<SignInResult> {
    if (this.signInError) throw this.signInError;
    if (this.supabasePassword !== null && password !== this.supabasePassword) {
      throw new AuthError("invalid_grant", "Invalid login credentials");
    }
    return { accessToken: "access-tok", user: { id: "u", email, emailConfirmedAt: this.confirmedAt } };
  }
  async getUser(): Promise<AuthUser> {
    return { id: "u", email: "a@b.co", emailConfirmedAt: this.confirmedAt };
  }
  async requestPasswordReset(email: string): Promise<void> {
    this.resetRequested = email;
  }
  async resendConfirmation(email: string): Promise<void> {
    this.resendRequested = email;
  }
}

function setup(): { storage: VaultStorage; client: FakeClient; id: Identity } {
  const storage = memoryStorage();
  const client = new FakeClient();
  return { storage, client, id: new Identity({ client, storage }) };
}

describe("Identity.resendConfirmation", () => {
  it("delegates to the client (resends the signup confirmation, no vault interaction)", async () => {
    const { client, id } = setup();
    await id.resendConfirmation("a@b.co");
    expect(client.resendRequested).toBe("a@b.co");
  });
});

describe("Identity.signUp", () => {
  it("creates the local vault + returns a recovery phrase, confirm-pending", async () => {
    const { storage, id } = setup();
    const r = await id.signUp("a@b.co", PW);
    expect(r.status).toBe("confirm-pending");
    expect(r.recoveryPhrase.length).toBeGreaterThan(0);
    expect(await Vault.exists(storage)).toBe(true);
    await expect(Vault.unlock(storage, PW)).resolves.toBeInstanceOf(Vault); // the vault really uses PW
  });

  it("refuses to overwrite an existing vault (D5)", async () => {
    const { storage, id } = setup();
    await Vault.create(storage, PW); // a pre-existing vault on PW
    await expect(id.signUp("a@b.co", PW2)).rejects.toBeInstanceOf(AuthError);
    await expect(Vault.unlock(storage, PW)).resolves.toBeInstanceOf(Vault); // unchanged
    await expect(Vault.unlock(storage, PW2)).rejects.toBeTruthy(); // never re-keyed to PW2
  });

  it("a Supabase signup error creates NO vault (no half-state)", async () => {
    const { storage, client, id } = setup();
    client.signUpError = new AuthError("user_already_exists", "User already registered");
    await expect(id.signUp("a@b.co", PW)).rejects.toBeInstanceOf(AuthError);
    expect(await Vault.exists(storage)).toBe(false);
  });

  it("neither the password nor the recovery phrase reaches the persisted vault file", async () => {
    const { storage, id } = setup();
    const r = await id.signUp("a@b.co", PW);
    const raw = await storage.read(VAULT_FILE);
    const text = new TextDecoder().decode(raw!);
    expect(text).not.toContain(PW);
    expect(text).not.toContain(r.recoveryPhrase);
  });
});

describe("Identity.logIn", () => {
  it("unlocks the vault when Supabase confirms + the password matches", async () => {
    const { id } = setup();
    await id.signUp("a@b.co", PW);
    const out = await id.logIn("a@b.co", PW);
    expect(out.status).toBe("unlocked");
    if (out.status === "unlocked") expect(out.vault.locked).toBe(false);
  });

  it("blocks an unconfirmed email via the email_confirmed_at gate (D9)", async () => {
    const { client, id } = setup();
    await id.signUp("a@b.co", PW);
    client.confirmedAt = null; // grant issues a token but the user is unconfirmed; getUser also unconfirmed
    await expect(id.logIn("a@b.co", PW)).rejects.toMatchObject({ code: "email_not_confirmed" });
  });

  it("propagates the grant error when Supabase rejects an unconfirmed login", async () => {
    const { client, id } = setup();
    await id.signUp("a@b.co", PW);
    client.signInError = new AuthError("email_not_confirmed", "Email not confirmed");
    await expect(id.logIn("a@b.co", PW)).rejects.toBeInstanceOf(AuthError);
  });

  it("returns 'no-vault' when confirmed but no local vault exists (D2)", async () => {
    const { id } = setup(); // no signup -> no vault
    const out = await id.logIn("a@b.co", PW);
    expect(out.status).toBe("no-vault");
  });

  it("returns 'needs-recovery' when the vault password drifted (D4)", async () => {
    const { client, id } = setup();
    await id.signUp("a@b.co", PW); // vault on PW
    client.supabasePassword = null; // Supabase accepts any password here (simulates a drift)
    const out = await id.logIn("a@b.co", PW2); // Supabase OK + confirmed, but the vault is on PW
    expect(out.status).toBe("needs-recovery");
  });
});

describe("Identity recovery", () => {
  it("requestReset asks Supabase to send the reset email", async () => {
    const { client, id } = setup();
    await id.requestReset("a@b.co");
    expect(client.resetRequested).toBe("a@b.co");
  });

  it("completeRecovery re-keys the vault to the new password (verified against Supabase, D4)", async () => {
    const { storage, client, id } = setup();
    const r = await id.signUp("a@b.co", PW);
    client.supabasePassword = PW2; // the user reset their Supabase password to PW2 out-of-band
    const out = await id.completeRecovery("a@b.co", r.recoveryPhrase, PW2);
    expect(out.status).toBe("recovered");
    await expect(Vault.unlock(storage, PW2)).resolves.toBeInstanceOf(Vault); // new password works
    await expect(Vault.unlock(storage, PW)).rejects.toBeTruthy(); // old password no longer works
  });

  it("completeRecovery rejects when the new password does not match Supabase (no drift left behind)", async () => {
    const { storage, client, id } = setup();
    const r = await id.signUp("a@b.co", PW);
    client.supabasePassword = PW2; // Supabase is on PW2
    await expect(id.completeRecovery("a@b.co", r.recoveryPhrase, "WRONG-pw-zzz")).rejects.toBeInstanceOf(AuthError);
    await expect(Vault.unlock(storage, PW)).resolves.toBeInstanceOf(Vault); // vault untouched, still on PW
  });
});

describe("auth layer persists no secret outside the vault (D13)", () => {
  it("src/auth/* uses no localStorage/sessionStorage/indexedDB/cookie/Cache", () => {
    // Match actual USAGE (a trailing . [ or () — not a mention in a "this is forbidden" comment.
    for (const f of ["src/auth/config.ts", "src/auth/supabase.ts", "src/auth/identity.ts"]) {
      const src = readFileSync(f, "utf8");
      expect(src).not.toMatch(/(?:localStorage|sessionStorage|indexedDB)[.[(]|document\.cookie|caches\.[a-z]/);
    }
  });
});
