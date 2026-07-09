import { describe, it, expect } from "vitest";
import { githubUser } from "../../src/osint/github-user.js";
import { gitlabUser } from "../../src/osint/gitlab-user.js";
import { hackernewsUser } from "../../src/osint/hackernews-user.js";
import { npmUser } from "../../src/osint/npm-user.js";
import type { FetchLike } from "../../src/osint/types.js";

// Shapes captured live 2026-07-09 from each provider's real response.
function fetchJson(payload: unknown, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, json: async () => payload })) as unknown as FetchLike;
}
// Captures the request headers so the BYO-token path can be asserted (and never leaked into an error).
function capturingHeaders(payload: unknown, status = 200): { impl: FetchLike; headers: () => Record<string, string> } {
  let seen: Record<string, string> = {};
  const impl = (async (_url: string, init?: { headers?: Record<string, string> }) => {
    seen = init?.headers ?? {};
    return { ok: status < 400, status, json: async () => payload };
  }) as unknown as FetchLike;
  return { impl, headers: () => seen };
}

describe("githubUser (api.github.com) — typed identity pivots, T3", () => {
  it("emits account/person/org/url/email pivots, not summary text (finding-5)", async () => {
    const impl = fetchJson({
      login: "octocat",
      name: "The Octocat",
      company: "@github",
      blog: "https://github.blog",
      email: "octo@github.com",
      twitter_username: "github",
      location: "San Francisco",
      html_url: "https://github.com/octocat",
      public_repos: 8,
      followers: 100,
    });
    const r = await githubUser("octocat", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("github");
    expect(r.tier).toBe("T3"); // identity is a lead, never infra
    const keyed = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(keyed).toContain("account:https://github.com/octocat");
    expect(keyed).toContain("person:The Octocat");
    expect(keyed).toContain("org:github"); // leading @ stripped
    expect(keyed).toContain("url:https://github.blog/");
    expect(keyed).toContain("email:octo@github.com");
    expect(keyed).toContain("account:https://twitter.com/github");
    expect(r.summary).toContain("100 followers");
  });
  it("sends the BYO token in the Authorization header and never in the error", async () => {
    const cap = capturingHeaders(null, 401);
    let msg = "";
    await githubUser("octocat", { fetchImpl: cap.impl, retries: 0 }, "ghp_SECRETTOKEN").catch((e) => (msg = String(e)));
    // token path: header set on the successful call shape too — assert via a 200 capture
    const ok = capturingHeaders({ login: "octocat" });
    await githubUser("octocat", { fetchImpl: ok.impl, retries: 0 }, "ghp_SECRETTOKEN");
    expect(ok.headers().authorization).toBe("Bearer ghp_SECRETTOKEN");
    expect(msg).toContain("401");
    expect(msg).not.toContain("ghp_SECRETTOKEN"); // key hygiene through the error path
  });
  it("throws on a 404 (never a fake profile)", async () => {
    await expect(githubUser("nobody", { fetchImpl: fetchJson({}, 404), retries: 0 })).rejects.toThrow(/not found/);
  });
  it("rejects a login-mismatched response (account substitution, finding-1)", async () => {
    const impl = fetchJson({ login: "someone-else", html_url: "https://github.com/someone-else" });
    await expect(githubUser("octocat", { fetchImpl: impl, retries: 0 })).rejects.toThrow(/login does not match/);
  });
  it("drops a hostile twitter_username that is not a real handle (finding-2)", async () => {
    const impl = fetchJson({ login: "octocat", twitter_username: "evil/../path?x=1" });
    const r = await githubUser("octocat", { fetchImpl: impl, retries: 0 });
    expect(r.entities.some((e) => e.value.includes("twitter.com"))).toBe(false);
  });
  it("rejects a pasted non-handle before fetching (finding-6)", async () => {
    let fetched = false;
    const impl = (async () => { fetched = true; return { ok: true, status: 200, json: async () => ({}) }; }) as unknown as FetchLike;
    await expect(githubUser("a whole pasted bio with spaces", { fetchImpl: impl, retries: 0 })).rejects.toThrow(/not a valid username/);
    expect(fetched).toBe(false);
  });
});

describe("gitlabUser (gitlab.com) — array endpoint, T3", () => {
  it("emits account/person/email from the first public match", async () => {
    const impl = fetchJson([{ id: 1, username: "gitlab-bot", name: "GitLab Bot", state: "active", public_email: "bot@gitlab.com", web_url: "https://gitlab.com/gitlab-bot" }]);
    const r = await gitlabUser("gitlab-bot", { fetchImpl: impl, retries: 0 });
    expect(r.tier).toBe("T3");
    const keyed = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(keyed).toContain("account:https://gitlab.com/gitlab-bot");
    expect(keyed).toContain("person:GitLab Bot");
    expect(keyed).toContain("email:bot@gitlab.com");
  });
  it("throws when the array is empty (no public user)", async () => {
    await expect(gitlabUser("nobody", { fetchImpl: fetchJson([]), retries: 0 })).rejects.toThrow(/no public user/);
  });
  it("sends the BYO token in the PRIVATE-TOKEN header", async () => {
    const ok = capturingHeaders([{ username: "gitlab-bot", web_url: "https://gitlab.com/gitlab-bot" }]);
    await gitlabUser("gitlab-bot", { fetchImpl: ok.impl, retries: 0 }, "glpat_SECRET");
    expect(ok.headers()["private-token"]).toBe("glpat_SECRET");
  });
  it("rejects a username-mismatched match — no first-object substitution (finding-3)", async () => {
    const impl = fetchJson([{ username: "someone-else", web_url: "https://gitlab.com/someone-else" }]);
    await expect(gitlabUser("gitlab-bot", { fetchImpl: impl, retries: 0 })).rejects.toThrow(/no public user matching/);
  });
  it("drops a non-http web_url (finding-3)", async () => {
    const impl = fetchJson([{ username: "gitlab-bot", web_url: "javascript:alert(1)" }]);
    const r = await gitlabUser("gitlab-bot", { fetchImpl: impl, retries: 0 });
    expect(r.entities.some((e) => e.type === "account")).toBe(false);
  });
});

describe("hackernewsUser (firebase) — bio parse, T3", () => {
  it("emits the account + any site/email in the about bio", async () => {
    const impl = fetchJson({ id: "pg", about: "Bug fixer. https://paulgraham.com contact pg@ycombinator.com", karma: 157316, created: 1160418092, submitted: [1, 2, 3] });
    const r = await hackernewsUser("pg", { fetchImpl: impl, retries: 0 });
    expect(r.tier).toBe("T3");
    const keyed = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(keyed).toContain("account:https://news.ycombinator.com/user?id=pg");
    expect(keyed).toContain("url:https://paulgraham.com/"); // URL.href normalizes with a trailing slash
    expect(keyed).toContain("email:pg@ycombinator.com");
    expect(r.summary).toContain("157316 karma");
  });
  it("throws when the API returns null (no such user)", async () => {
    await expect(hackernewsUser("nobody", { fetchImpl: fetchJson(null), retries: 0 })).rejects.toThrow(/no such user/);
  });
});

describe("npmUser (registry search) — maintainer→packages, T3", () => {
  it("emits package account + repo url + publisher email for the queried maintainer", async () => {
    const impl = fetchJson({
      total: 1,
      objects: [
        {
          package: {
            name: "left-pad",
            links: { repository: "git+https://github.com/stevemao/left-pad.git" },
            publisher: { email: "steve@example.com", username: "substack" },
          },
        },
      ],
    });
    const r = await npmUser("substack", { fetchImpl: impl, retries: 0 });
    expect(r.tier).toBe("T3");
    const keyed = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(keyed).toContain("account:https://www.npmjs.com/package/left-pad");
    expect(keyed).toContain("url:https://github.com/stevemao/left-pad"); // git+ and .git stripped
    expect(keyed).toContain("email:steve@example.com");
  });
  it("does NOT attribute a co-maintainer's publisher email to the queried username", async () => {
    const impl = fetchJson({ objects: [{ package: { name: "x", publisher: { email: "other@x.com", username: "someone-else" } } }] });
    const r = await npmUser("substack", { fetchImpl: impl, retries: 0 });
    expect(r.entities.some((e) => e.type === "email")).toBe(false);
  });
  it("caps a huge objects list and throws on an unexpected shape", async () => {
    const objects = Array.from({ length: 300 }, (_, i) => ({ package: { name: `p${i}` } }));
    const r = await npmUser("prolific", { fetchImpl: fetchJson({ objects }), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(100);
    await expect(npmUser("x", { fetchImpl: fetchJson({ nope: true }), retries: 0 })).rejects.toThrow(/unexpected response shape/);
  });
  it("drops a hostile package name (path/query injection) — no junk account pivot (finding-4)", async () => {
    const impl = fetchJson({ objects: [{ package: { name: "../../evil?x=1", publisher: { username: "substack" } } }] });
    const r = await npmUser("substack", { fetchImpl: impl, retries: 0 });
    expect(r.entities.some((e) => e.value.includes("evil"))).toBe(false);
  });
});

describe("hostile HN bio hardening (finding-5)", () => {
  it("caps an unbounded flood of URLs/emails in the about bio", async () => {
    const about = Array.from({ length: 400 }, (_, i) => `https://h${i}.example.com`).join(" ");
    const r = await hackernewsUser("pg", { fetchImpl: fetchJson({ id: "pg", about }), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(101); // the account node + up to MAX_ENRICH_RESULTS bio links
  });
});
