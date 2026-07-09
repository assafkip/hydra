# Auth — manual founder check (chunk 6)

The Playwright smoke (`tests/smoke/auth.spec.ts`) scripts the Supabase responses, so it proves the
identity↔vault wiring, the no-leak contract, and the no-egress contract WITHOUT a real inbox. Real email
delivery and the real confirmation/reset clicks cannot be driven headlessly (codex D14). Run these four
checks by hand against the live deploy once, after a Supabase or auth-flow change.

Prereq: the deploy is live (`kipi-web-eta.vercel.app`), and the Supabase project
(`yvermtklysygaeetxcyb`) has **Authentication → Providers → Email → Confirm email = ON**.

1. **Confirmation is required before first login.**
   - Sign up with a real address you control. You should land on "Save your recovery key" + "check your
     inbox", NOT the app home.
   - Before clicking the email link, try to log in with the same email+password. It must be REJECTED with
     "Confirm your email first" — you must not reach the home.
   - Click the confirmation link in the email, then log in. Now it unlocks to the home.

2. **The reset link targets Supabase's hosted page.**
   - Use "Forgot password → Send reset email". The email's link should open Supabase's own
     password-reset page (on `yvermtklysygaeetxcyb.supabase.co`), where you set the new password — NOT a
     kipi page that reads a token.

3. **No token is left in the visible URL/history after the reset.**
   - After completing the Supabase reset and being returned to kipi, check the address bar and browser
     history: there must be NO `access_token=` / `refresh_token=` / `type=recovery` fragment left in the
     URL (the app strips it via `history.replaceState` on load — D1).

4. **Local re-key: old password rejected, new accepted.**
   - After the reset, on kipi's "Reset your password" screen enter your recovery key + the NEW password,
     click "Recover my cases". It should unlock.
   - Lock, then try to log in with the OLD password — it must be rejected. Log in with the NEW password —
     it must work. (This proves the vault was actually re-keyed to the new password, in sync with
     Supabase — D4.)

If any of these fails, do NOT ship the auth change — the identity↔vault binding or the token-hygiene
contract is broken.
