// Chunk-6 auth: the identity <-> vault orchestration. Binds Supabase identity (email + password, email
// confirmation ON) to the existing local vault crypto, WITHOUT touching the crypto spine. The master
// password is used for BOTH, derived independently — Supabase hashes its own server-side; the vault
// derives its own KDF key locally. The data key is generated + kept in the browser and NEVER reaches
// Supabase. The vault is written ONLY through the existing Vault API (the single-writer chokepoint in
// src/vault/store.ts is untouched), and this layer persists NO secret outside the vault (no
// localStorage/sessionStorage/IndexedDB/cookie/Cache — codex D13; an access token from a grant is used
// in-memory for the confirmation check then dropped).

import { Vault } from "../vault/vault.js";
import type { VaultStorage } from "../vault/store.js";
import { AuthError, type AuthUser, type SignUpResult, type SignInResult } from "./supabase.js";

/** The subset of SupabaseAuth identity uses (so tests inject a fake client). SupabaseAuth satisfies it. */
export interface AuthClient {
  signUp(email: string, password: string): Promise<SignUpResult>;
  signInPassword(email: string, password: string): Promise<SignInResult>;
  getUser(accessToken: string): Promise<AuthUser>;
  requestPasswordReset(email: string): Promise<void>;
  resendConfirmation(email: string): Promise<void>;
}

export interface IdentityDeps {
  client: AuthClient;
  storage: VaultStorage;
}

export type SignUpOutcome = { status: "confirm-pending"; recoveryPhrase: string };
export type LogInOutcome =
  | { status: "unlocked"; vault: Vault }
  | { status: "no-vault" } // confirmed login, no local vault on this browser — UI offers import OR create-fresh (D2)
  | { status: "needs-recovery" }; // confirmed login but the local vault password drifted — UI offers recovery (D4)
export type RecoverOutcome = { status: "recovered"; vault: Vault };

export class Identity {
  constructor(private readonly deps: IdentityDeps) {}

  /**
   * Sign up: register the email at Supabase (confirmation email sent), then create the LOCAL vault with
   * the same password and return the recovery phrase to show ONCE. D5: refuses if a vault already exists
   * on this backend (never overwrites an encrypted vault). A Supabase error (email taken / weak password)
   * throws BEFORE any vault is created (no half-vault). The user is confirm-pending: they must click the
   * email link, then log in to unlock (the vault is persisted + locked here, not handed back for use).
   */
  async signUp(email: string, password: string): Promise<SignUpOutcome> {
    if (await Vault.exists(this.deps.storage)) {
      throw new AuthError("vault_exists", "A vault already exists on this browser. Log in, or import your vault file.");
    }
    await this.deps.client.signUp(email, password); // throws AuthError on email-taken/weak-pw -> no vault
    const { vault, recoveryPhrase } = await Vault.create(this.deps.storage, password); // persists the encrypted vault
    vault.lock(); // zero the key bytes; the user unlocks on first login (after confirming the email)
    return { status: "confirm-pending", recoveryPhrase };
  }

  /**
   * Log in: prove identity (Supabase password grant — fails for an unconfirmed email) AND verify
   * email_confirmed_at (D9, defense-in-depth), THEN unlock the local vault with the same password. The
   * access token is used only for the confirmation check and dropped (never stored). Returns 'no-vault'
   * when confirmed but no local vault (new device or a half-signup — the UI offers import OR create-fresh,
   * D2), and 'needs-recovery' when the vault exists but its password drifted (D4).
   */
  async logIn(email: string, password: string): Promise<LogInOutcome> {
    const { accessToken, user } = await this.deps.client.signInPassword(email, password); // throws on unconfirmed/wrong-pw
    let confirmedAt = user.emailConfirmedAt;
    if (!confirmedAt) {
      // some configs issue a token even when unconfirmed — double-check the authoritative user (D9)
      confirmedAt = (await this.deps.client.getUser(accessToken)).emailConfirmedAt;
    }
    if (!confirmedAt) throw new AuthError("email_not_confirmed", "Confirm your email before logging in.");
    // identity proven + confirmed; the access token is now discarded (not stored).
    if (!(await Vault.exists(this.deps.storage))) return { status: "no-vault" };
    try {
      const vault = await Vault.unlock(this.deps.storage, password);
      return { status: "unlocked", vault };
    } catch {
      return { status: "needs-recovery" }; // Supabase OK but the vault password drifted — offer recovery
    }
  }

  /** Trigger the Supabase password-reset email (owner- or user-initiated). */
  async requestReset(email: string): Promise<void> {
    await this.deps.client.requestPasswordReset(email);
  }

  /** Resend the Supabase signup-confirmation email for a user who didn't receive the first one. No vault
   *  interaction — a pure identity call (the user has no session yet). */
  async resendConfirmation(email: string): Promise<void> {
    await this.deps.client.resendConfirmation(email);
  }

  /**
   * Finish recovery after the user reset their Supabase password out-of-band. D4: VERIFY the new password
   * actually works for Supabase FIRST (proving the two flows agree), THEN re-key the local vault via the
   * recovery phrase. A mismatch (wrong Supabase password) throws before any vault change; a wrong recovery
   * phrase throws inside recoverWithPhrase before persisting — neither leaves a drifted vault.
   */
  async completeRecovery(email: string, recoveryPhrase: string, newPassword: string): Promise<RecoverOutcome> {
    await this.deps.client.signInPassword(email, newPassword); // throws AuthError if Supabase pw != newPassword
    const vault = await Vault.recoverWithPhrase(this.deps.storage, recoveryPhrase, newPassword); // throws on wrong phrase
    return { status: "recovered", vault };
  }
}
