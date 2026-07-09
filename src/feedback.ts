// rel-feedback (docs/17 §5.3): the ONLY founder-bound channel, and it carries ZERO case data.
// A user-authored, pre-filled GitHub issue the user reviews + submits THEMSELVES — the founder's infra
// never receives it programmatically. This module is a pure URL builder: it takes NO arguments, so no
// case/vault content can ever be interpolated into the link. The UI opens it as a target=_blank anchor
// (not a fetch — github.com is NOT in connect-src; nothing is sent until the user clicks "Submit" on
// GitHub's own page).

const REPO = "https://github.com/assafkip/kipi";
const TITLE = "kipi-web feedback";

// A static prompt template. NOTHING here is interpolated from the app — it is the same text for everyone.
const BODY_TEMPLATE = [
  "<!-- We never see your cases. Only the text you type below is sent, and only when YOU submit this issue. -->",
  "**What happened:**",
  "",
  "",
  "**What I expected:**",
  "",
  "",
  "**Browser / OS (optional):**",
  "",
].join("\n");

/** The fixed GitHub new-issue URL with the static feedback template. No parameters → no case data. */
export function buildFeedbackUrl(): string {
  const u = new URL(`${REPO}/issues/new`);
  u.searchParams.set("title", TITLE);
  u.searchParams.set("body", BODY_TEMPLATE);
  return u.toString();
}

/** The plain-language disclosure shown next to the feedback control. */
export const FEEDBACK_DISCLOSURE =
  "We never see your cases. This opens a GitHub issue with only the text you type.";

// rel-bug: the "Report a bug" channel — an email to the founder. Same zero-case-data model as the
// GitHub feedback link above: this builds a `mailto:` the user's OWN mail client opens; nothing is
// sent programmatically and the app interpolates NO case/vault content (the builder takes no args, so
// there is nothing to leak). mailto is a navigation, not a fetch, so it needs no connect-src origin.
const BUG_EMAIL = "assaf@ktlystlabs.com";
const BUG_SUBJECT = "kipi bug report";

// A static template. Identical for everyone — no app state is ever interpolated in.
const BUG_BODY_TEMPLATE = [
  "We never see your cases. Only the text you type below is sent, and only when YOU send this email.",
  "",
  "What happened:",
  "",
  "",
  "What I expected:",
  "",
  "",
  "Steps to reproduce:",
  "",
  "",
  "Browser / OS (optional):",
  "",
].join("\n");

/** The fixed mailto URL with the static bug-report template. No parameters → no case data. */
export function buildBugReportUrl(): string {
  // Build the query by hand with encodeURIComponent so the body uses %20 (some mail clients render a
  // URLSearchParams "+" as a literal plus sign in the body).
  const query = `subject=${encodeURIComponent(BUG_SUBJECT)}&body=${encodeURIComponent(BUG_BODY_TEMPLATE)}`;
  return `mailto:${BUG_EMAIL}?${query}`;
}

/** The plain-language disclosure shown on the bug-report control. */
export const BUG_DISCLOSURE =
  "We never see your cases. This opens an email with only the text you type.";
