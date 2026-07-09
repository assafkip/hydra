import { describe, it, expect, afterEach } from "vitest";
import { loadGithubStars } from "../src/github-stars.js";

// vitest runs in node (no jsdom), so stub the DOM call the module makes. loadGithubStars fills EVERY
// .js-gh-stars element (both the top-strip and the pre-login button), so the stub returns a NodeList-like.
function stubDoc(els: { textContent: string }[]): void {
  (globalThis as unknown as { document: unknown }).document = {
    querySelectorAll: (sel: string) => (sel === ".js-gh-stars" ? els : []),
  };
}
afterEach(() => {
  delete (globalThis as unknown as { document?: unknown }).document;
});

const okFetch = (payload: unknown) =>
  (async () => ({ ok: true, json: async () => payload })) as unknown as typeof fetch;

describe("loadGithubStars (top-strip GitHub button)", () => {
  it("fills the count on EVERY star element (top strip + pre-login button)", async () => {
    const els = [{ textContent: "★" }, { textContent: "★" }];
    stubDoc(els);
    await loadGithubStars("assafkip/hydra", okFetch({ stargazers_count: 91 }));
    expect(els.map((e) => e.textContent)).toEqual(["★ 91", "★ 91"]);
  });

  it("keeps the ★ placeholder on a failed fetch (silent, link still works)", async () => {
    const el = { textContent: "★" };
    stubDoc([el]);
    const failFetch = (async () => ({ ok: false, json: async () => ({}) })) as unknown as typeof fetch;
    await loadGithubStars("assafkip/hydra", failFetch);
    expect(el.textContent).toBe("★");
  });

  it("does not throw when a network error is thrown", async () => {
    stubDoc([{ textContent: "★" }]);
    const boom = (async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    await expect(loadGithubStars("assafkip/hydra", boom)).resolves.toBeUndefined();
  });

  it("does nothing (no throw) when no star element is present", async () => {
    stubDoc([]);
    await expect(loadGithubStars("x/y", okFetch({ stargazers_count: 1 }))).resolves.toBeUndefined();
  });
});
