import { describe, it, expect } from "vitest";
import { SupabaseAuth, AuthError } from "../../src/auth/supabase";
import { SUPABASE_ANON_KEY } from "../../src/auth/config";
import type { FetchLike } from "../../src/osint/types";

const PW = "PW-supatest-secret-7788"; // distinctive: assert it never escapes the body
const REFRESH = "refresh-token-MUST-be-dropped-9090"; // D8: must never surface

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

function capturing(response: unknown, init: { ok?: boolean; status?: number } = {}): {
  fetchImpl: FetchLike;
  calls: Captured[];
} {
  const calls: Captured[] = [];
  const fetchImpl = (async (url: string, req?: RequestInit) => {
    calls.push({
      url: String(url),
      method: String(req?.method ?? "GET"),
      headers: (req?.headers as Record<string, string>) ?? {},
      body: req?.body as string | undefined,
    });
    return { ok: init.ok ?? true, status: init.status ?? 200, json: async () => response };
  }) as unknown as FetchLike;
  return { fetchImpl, calls };
}

describe("SupabaseAuth thin client", () => {
  it("signUp with confirmation ON returns the user + confirmationRequired (no session)", async () => {
    const { fetchImpl, calls } = capturing({ id: "u1", email: "a@b.co", email_confirmed_at: null, confirmation_sent_at: "2026-06-18T00:00:00Z" });
    const r = await new SupabaseAuth(fetchImpl).signUp("a@b.co", PW);
    expect(r.confirmationRequired).toBe(true);
    expect(r.user.email).toBe("a@b.co");
    expect(r.user.emailConfirmedAt).toBeNull();
    // endpoint + apikey header + password in BODY not URL
    expect(calls[0].url).toBe("https://yvermtklysygaeetxcyb.supabase.co/auth/v1/signup");
    expect(calls[0].headers.apikey).toBe(SUPABASE_ANON_KEY);
    expect(calls[0].url).not.toContain(PW);
    expect(calls[0].body).toContain(PW);
  });

  it("signInPassword returns {accessToken, user} and DROPS the refresh_token (D8)", async () => {
    const { fetchImpl, calls } = capturing({
      access_token: "access-123",
      refresh_token: REFRESH,
      token_type: "bearer",
      user: { id: "u1", email: "a@b.co", email_confirmed_at: "2026-06-18T00:00:00Z" },
    });
    const r = await new SupabaseAuth(fetchImpl).signInPassword("a@b.co", PW);
    expect(r.accessToken).toBe("access-123");
    expect(r.user.emailConfirmedAt).toBe("2026-06-18T00:00:00Z");
    // the refresh token must NOT appear anywhere in the returned value (D8)
    expect(JSON.stringify(r)).not.toContain(REFRESH);
    // grant_type is in the query; the password is NOT in the URL
    expect(calls[0].url).toContain("grant_type=password");
    expect(calls[0].url).not.toContain(PW);
    expect(calls[0].body).toContain(PW);
  });

  it("signInPassword on an unconfirmed email throws a typed AuthError (no password in the message)", async () => {
    const { fetchImpl } = capturing({ error_code: "email_not_confirmed", msg: "Email not confirmed" }, { ok: false, status: 400 });
    const auth = new SupabaseAuth(fetchImpl);
    await expect(auth.signInPassword("a@b.co", PW)).rejects.toBeInstanceOf(AuthError);
    try {
      await auth.signInPassword("a@b.co", PW);
    } catch (e) {
      expect((e as AuthError).code).toBe("email_not_confirmed");
      expect((e as AuthError).message).not.toContain(PW);
    }
  });

  it("a wrong-password grant surfaces the invalid-credentials AuthError, password-free", async () => {
    const { fetchImpl } = capturing({ error: "invalid_grant", error_description: "Invalid login credentials" }, { ok: false, status: 400 });
    try {
      await new SupabaseAuth(fetchImpl).signInPassword("a@b.co", PW);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AuthError);
      expect((e as AuthError).message).not.toContain(PW);
      expect((e as AuthError).message.toLowerCase()).toContain("invalid login credentials");
    }
  });

  it("resendConfirmation POSTs /resend with type:signup + the email (no password)", async () => {
    const { fetchImpl, calls } = capturing({});
    await new SupabaseAuth(fetchImpl).resendConfirmation("a@b.co");
    expect(calls[0].url).toContain("/resend");
    expect(calls[0].method).toBe("POST");
    expect(JSON.parse(calls[0].body!)).toMatchObject({ type: "signup", email: "a@b.co" });
  });

  it("getUser parses email_confirmed_at and sends the Bearer token (D9)", async () => {
    const { fetchImpl, calls } = capturing({ id: "u1", email: "a@b.co", email_confirmed_at: "2026-06-18T01:00:00Z" });
    const u = await new SupabaseAuth(fetchImpl).getUser("access-123");
    expect(u.emailConfirmedAt).toBe("2026-06-18T01:00:00Z");
    expect(calls[0].headers.authorization).toBe("Bearer access-123");
    expect(calls[0].url).toBe("https://yvermtklysygaeetxcyb.supabase.co/auth/v1/user");
  });

  it("requestPasswordReset posts {email} only (no password) to /recover", async () => {
    const { fetchImpl, calls } = capturing({});
    await new SupabaseAuth(fetchImpl).requestPasswordReset("a@b.co");
    expect(calls[0].url).toBe("https://yvermtklysygaeetxcyb.supabase.co/auth/v1/recover");
    expect(calls[0].body).toBe(JSON.stringify({ email: "a@b.co" }));
    expect(calls[0].body).not.toContain(PW);
  });

  it("a network failure becomes a clean, password-free AuthError", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as FetchLike;
    try {
      await new SupabaseAuth(fetchImpl).signInPassword("a@b.co", PW);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AuthError);
      expect((e as AuthError).code).toBe("network");
      expect((e as AuthError).message).not.toContain(PW);
    }
  });
});
