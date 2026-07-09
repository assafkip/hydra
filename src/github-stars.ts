// GitHub star button (top strip): fill #gh-star-count with the public repo's live star count. The button
// itself is a static anchor in index.html that always links to the repo; this only adds the number. The
// fetch lives in the bundle because the strict CSP forbids inline JS. api.github.com is already CSP-allowed
// (the github_user OSINT tool uses it). Fails SILENTLY — if the count can't load (repo not public yet,
// offline, or GitHub rate-limited the keyless call), the button keeps its ★ placeholder and still links out.

export const HYDRA_REPO = "assafkip/hydra";

export async function loadGithubStars(repo: string = HYDRA_REPO, fetchImpl: typeof fetch = fetch): Promise<void> {
  const el = document.getElementById("gh-star-count");
  if (!el) return;
  try {
    const res = await fetchImpl(`https://api.github.com/repos/${repo}`, {
      headers: { accept: "application/vnd.github+json" },
    });
    if (!res.ok) return; // 404 (private/not-yet-created) or 403 (rate limit) → keep the placeholder
    const data = (await res.json()) as { stargazers_count?: number };
    if (typeof data.stargazers_count === "number") {
      el.textContent = `★ ${data.stargazers_count.toLocaleString()}`;
    }
  } catch {
    /* network error — leave the ★ placeholder; the link still works */
  }
}
