// GitHub star button: fill every .js-gh-stars element with the public repo's live star count. There are
// two of these — one in the top strip (index.html, post-login) and one on the auth screen (pre-login,
// githubStarAnchor below), so social proof shows before AND after login. The buttons are static anchors
// that always link to the repo; this only adds the number. The fetch lives in the bundle because the
// strict CSP forbids inline JS. api.github.com is already CSP-allowed (the github_user OSINT tool uses it).
// Fails SILENTLY — if the count can't load (offline / rate-limited), the ★ placeholder stays and the link
// still works.

export const HYDRA_REPO = "assafkip/hydra";
const HYDRA_REPO_URL = "https://github.com/assafkip/hydra";

// The GitHub mark (octocat) as an inline SVG path — reused by the top strip (index.html) and this anchor.
const OCTOCAT =
  "M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.76-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z";

/** The pre-login star button element (built in TS since the auth screen is rendered by app.ts, not the
 *  static index.html shell). Same repo link + .js-gh-stars count target as the top-strip button. */
export function githubStarAnchor(): HTMLAnchorElement {
  const a = document.createElement("a");
  a.href = HYDRA_REPO_URL;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.title = "Star Hydra on GitHub";
  // Same utility classes as the top-strip button (Tailwind scans src/**/*.ts, so these generate).
  a.className =
    "inline-flex items-center gap-1.5 text-sm bg-bg-soft border border-bg-border px-2.5 py-1.5 rounded hover:border-accent text-ink-muted hover:text-ink no-underline";
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("fill", "currentColor");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", OCTOCAT);
  svg.appendChild(path);
  const label = document.createElement("span");
  label.textContent = "GitHub";
  const count = document.createElement("span");
  count.className = "js-gh-stars font-mono text-xs tabular-nums";
  count.textContent = "★";
  a.append(svg, label, count);
  return a;
}

export async function loadGithubStars(repo: string = HYDRA_REPO, fetchImpl: typeof fetch = fetch): Promise<void> {
  const els = document.querySelectorAll<HTMLElement>(".js-gh-stars");
  if (els.length === 0) return;
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${repo}`, {
      headers: { accept: "application/vnd.github+json" },
    });
    if (!res.ok) return; // 404 (private/not-yet-created) or 403 (rate limit) → keep the placeholder
    const data = (await res.json()) as { stargazers_count?: number };
    if (typeof data.stargazers_count === "number") {
      const label = `★ ${data.stargazers_count.toLocaleString()}`;
      els.forEach((el) => (el.textContent = label));
    }
  } catch {
    /* network error — leave the ★ placeholder; the links still work */
  }
}
