// Chunk-6 auth: a thin, hand-written Supabase GoTrue client — NOT supabase-js, so the bundle carries
// ZERO third-party runtime code (the src/llm/client.ts precedent). It calls /auth/v1/* with the public
// anon key in the `apikey` header. Key hygiene: the password rides ONLY the POST body to the Supabase
// origin over HTTPS (never a URL/query/log); the refresh_token from a password grant is DROPPED at parse
// and never returned/exposed/stored (codex D8); errors carry ONLY server-supplied fields, never the
// request body. The data key NEVER touches this layer — Supabase is identity only.

import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./config.js";
import type { FetchLike } from "../osint/types.js";

const AUTH = `${SUPABASE_URL}/auth/v1`;

/** A typed auth failure. `code` is the GoTrue error code; `message` is server-supplied (the UI maps it
 *  to a sanitized line — D11). Neither ever contains the password (GoTrue does not echo it). */
export class AuthError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export interface AuthUser {
  id: string;
  email: string;
  /** ISO timestamp when the email was confirmed, or null if not yet confirmed (gate — D9). */
  emailConfirmedAt: string | null;
}
export interface SignUpResult {
  user: AuthUser;
  /** True when Supabase issued NO session (email confirmation required before login). */
  confirmationRequired: boolean;
}
export interface SignInResult {
  accessToken: string;
  user: AuthUser;
}

export class SupabaseAuth {
  constructor(
    // Arrow default (not a bare `= fetch`) so the receiver is correct in the browser (the llm/client scar).
    private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
  ) {}

  private headers(accessToken?: string): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json", apikey: SUPABASE_ANON_KEY };
    if (accessToken) h.authorization = `Bearer ${accessToken}`;
    return h;
  }

  /** Sign up. With email-confirmation ON, Supabase returns the User (no session) → confirmationRequired. */
  async signUp(email: string, password: string): Promise<SignUpResult> {
    const json = await this.post(`${AUTH}/signup`, { email, password });
    const hasSession = typeof (json as Record<string, unknown>).access_token === "string";
    const userRaw = hasSession ? (json as Record<string, unknown>).user : json;
    return { user: toUser(userRaw), confirmationRequired: !hasSession };
  }

  /** Password grant. Returns ONLY {accessToken, user}; the refresh_token is dropped here (D8). */
  async signInPassword(email: string, password: string): Promise<SignInResult> {
    const json = (await this.post(`${AUTH}/token?grant_type=password`, { email, password })) as Record<string, unknown>;
    const accessToken = typeof json.access_token === "string" ? json.access_token : "";
    if (!accessToken) throw new AuthError("no_session", "Login did not return a session.");
    // json.refresh_token exists but is intentionally NOT read — never returned/stored.
    return { accessToken, user: toUser(json.user) };
  }

  /** Fetch the authenticated user (used to verify email_confirmed_at — D9). */
  async getUser(accessToken: string): Promise<AuthUser> {
    return toUser(await this.get(`${AUTH}/user`, accessToken));
  }

  /** Trigger the password-reset email. Supabase always 200s (it does not reveal whether the email exists). */
  async requestPasswordReset(email: string): Promise<void> {
    await this.post(`${AUTH}/recover`, { email });
  }

  /** Resend the SIGNUP confirmation email (for a user who never received the first one). type:"signup"
   *  targets the confirmation link specifically (not a magic-link/recovery). Supabase 200s regardless of
   *  whether the address exists or is already confirmed (anti-enumeration); a 429 means the per-email
   *  send-rate limit was hit — surfaced as an AuthError the caller maps to a "wait a minute" message. */
  async resendConfirmation(email: string): Promise<void> {
    await this.post(`${AUTH}/resend`, { type: "signup", email });
  }

  async signOut(accessToken: string): Promise<void> {
    await this.post(`${AUTH}/logout`, {}, accessToken);
  }

  private async post(url: string, body: unknown, accessToken?: string): Promise<unknown> {
    return this.parse(await this.send(url, { method: "POST", headers: this.headers(accessToken), body: JSON.stringify(body) }));
  }
  private async get(url: string, accessToken: string): Promise<unknown> {
    return this.parse(await this.send(url, { method: "GET", headers: this.headers(accessToken) }));
  }

  private async send(url: string, init: RequestInit): Promise<Response> {
    try {
      return await this.fetchImpl(url, init);
    } catch {
      throw new AuthError("network", "Could not reach the login service. Check your connection.");
    }
  }

  private async parse(res: Response): Promise<unknown> {
    let json: unknown = {};
    try {
      json = await res.json();
    } catch {
      json = {}; // 204 / empty body (logout)
    }
    if (!res.ok) {
      const o = (json ?? {}) as Record<string, unknown>;
      const code = String(o.error_code ?? o.code ?? o.error ?? `http_${res.status}`);
      const message = String(o.msg ?? o.error_description ?? o.error ?? `Auth error (HTTP ${res.status}).`);
      throw new AuthError(code, message); // server fields ONLY — never the request body/password
    }
    return json;
  }
}

function toUser(raw: unknown): AuthUser {
  const o = (raw ?? {}) as Record<string, unknown>;
  const confirmed =
    typeof o.email_confirmed_at === "string"
      ? o.email_confirmed_at
      : typeof o.confirmed_at === "string"
        ? o.confirmed_at
        : null;
  return { id: String(o.id ?? ""), email: String(o.email ?? ""), emailConfirmedAt: confirmed };
}
