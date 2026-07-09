import { describe, it, expect, afterEach } from "vitest";
import { loadGithubStars } from "../src/github-stars.js";

// vitest runs in node (no jsdom), so stub the one DOM call the module makes.
function stubDoc(el: { textContent: string } | null): void {
  (globalThis as unknown as { document: unknown }).document = {
    getElementById: (id: string) => (id === "gh-star-count" ? el : null),
  };
}
afterEach(() => {
  delete (globalThis as unknown as { document?: unknown }).document;
});

const okFetch = (payload: unknown) =>
  (async () => ({ ok: true, json: async () => payload })) as unknown as typeof fetch;

describe("loadGithubStars (top-strip GitHub button)", () => {
  it("fills the count from the repo's stargazers_count", async () => {
    const el = { textContent: "★" };
    stubDoc(el);
    await loadGithubStars("assafkip/hydra", okFetch({ stargazers_count: 91 }));
    expect(el.textContent).toBe("★ 91");
  });

  it("keeps the ★ placeholder on a failed fetch (silent, link still works)", async () => {
    const el = { textContent: "★" };
    stubDoc(el);
    const failFetch = (async () => ({ ok: false, json: async () => ({}) })) as unknown as typeof fetch;
    await loadGithubStars("assafkip/hydra", failFetch);
    expect(el.textContent).toBe("★");
  });

  it("does not throw when a network error is thrown", async () => {
    stubDoc({ textContent: "★" });
    const boom = (async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    await expect(loadGithubStars("assafkip/hydra", boom)).resolves.toBeUndefined();
  });

  it("does nothing (no throw) when the element is absent", async () => {
    stubDoc(null);
    await expect(loadGithubStars("x/y", okFetch({ stargazers_count: 1 }))).resolves.toBeUndefined();
  });
});
