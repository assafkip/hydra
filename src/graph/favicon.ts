// Domain-node favicons (founder decision 2026-06-24, node-graph-prd-audit). A domain/url node renders
// the site's favicon as its face so an analyst recognises it at a glance (Google s2 favicon service).
//
// EGRESS NOTE — this is the ONE deliberate exception to the client's zero-egress posture. The browser
// fetches the favicon DIRECTLY from Google's static CDN (t0.gstatic.com faviconV2), so the bare DOMAIN of
// a case entity is exposed to Google (an image GET, no case content, no key, no path/finding). The founder
// weighed this against the recognition value and chose the direct fetch over the privacy-safe Worker-proxy
// tier (2026-06-24). The original Python webapp hid this behind a SERVER-SIDE cache/proxy; the client-side
// app has no server, so the fetch is browser→Google. We hit the gstatic faviconV2 endpoint DIRECTLY (a
// pinned shard) rather than www.google.com/s2/favicons, which 301-redirects to gstatic and would need the
// redirect target allowed too. This is the SOLE module that names the Google host (leakgate
// FAVICON_FETCH_HOSTS is scoped to this file); the CSP img-src allows t0.gstatic.com.
//
// The host rule is a verbatim port of the original webapp's /api/favicon guard (app.py): sanitize to
// [a-z0-9.-], require a dot (no dotless/IDN host), else no favicon.

// gstatic faviconV2 (the endpoint www.google.com/s2/favicons redirects to) — hit directly, no redirect.
const FAVICON_BASE = "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&size=64&url=";

/** The favicon image URL for a domain/url value, or null when the host is unusable (no favicon drawn). */
export function faviconUrl(value: string | undefined): string | null {
  const host = faviconHost(value);
  return host ? FAVICON_BASE + encodeURIComponent("http://" + host) : null;
}

/** Extract the registrable host from a domain/url value (strip scheme/www/path/query), sanitized. null if unusable. */
export function faviconHost(value: string | undefined): string | null {
  let s = String(value ?? "").trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // strip scheme
  // WHATWG URL treats \ as a path separator too — split on it or example.com\secret leaks (codex adv).
  s = s.split("/")[0].split("\\")[0].split("?")[0].split("#")[0]; // host only — drop path/query/fragment
  // Drop userinfo + port BEFORE sanitizing: sanitize-first turned user:secret@example.com into
  // usersecretexample.com, leaking credentials to gstatic (codex 2026-07-03, kweb-favicon-contract).
  const at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);
  s = s.split(":")[0];
  s = s.replace(/^www\./, "");
  s = s.replace(/[^a-z0-9.-]/g, ""); // sanitize (matches the original's [^a-z0-9.\-] guard)
  if (!s || !s.includes(".")) return null; // dotless / empty → no favicon
  return s;
}
