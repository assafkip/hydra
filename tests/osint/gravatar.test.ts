import { describe, it, expect } from "vitest";
import { gravatarLookup } from "../../src/osint/gravatar.js";
import { runTool } from "../../src/agent/tools.js";
import type { FetchLike } from "../../src/osint/types.js";

// a56ffd8e: Gravatar email→profile over the CORS-open gravatar.com profile JSON. node-safe via an injected
// fetchImpl (no network); SHA-256 hashing uses node's global crypto.subtle (same API as the browser).
function fetchJson(payload: unknown, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, json: async () => payload })) as unknown as FetchLike;
}

const PROFILE = {
  entry: [{
    displayName: "Beau Lebens",
    preferredUsername: "beau",
    profileUrl: "https://gravatar.com/beau",
    currentLocation: "Golden, CO",
    company: "Automattic",
    job_title: "Lead, WooCommerce",
    accounts: [
      { url: "https://x.com/beaulebens", shortname: "twitter", verified: true },
      { url: "https://www.linkedin.com/in/beaulebens", shortname: "linkedin", verified: true },
    ],
  }],
};

describe("a56ffd8e gravatar — email→profile pivot (keyless, T3 leads)", () => {
  it("surfaces the profile + linked-account URLs as leads and the identity as summary", async () => {
    const res = await gravatarLookup("beau@automattic.com", { fetchImpl: fetchJson(PROFILE) });
    expect(res.tier).toBe("T3");
    expect(res.entities.map((e) => e.value)).toEqual([
      "https://gravatar.com/beau",
      "https://x.com/beaulebens",
      "https://www.linkedin.com/in/beaulebens",
    ]);
    expect(res.entities.every((e) => e.type === "url")).toBe(true);
    expect(res.summary).toContain("Beau Lebens");
    expect(res.summary).toContain("Lead, WooCommerce at Automattic");
    expect(res.summary).toContain("x.com/beaulebens");
  });

  it("reports an honest miss when no profile is registered (404)", async () => {
    const res = await gravatarLookup("nobody@nowhere.example", { fetchImpl: fetchJson({}, 404) });
    expect(res.entities).toEqual([]);
    expect(res.summary).toContain("No Gravatar profile");
  });

  it("is dispatchable as the gravatar agent tool", async () => {
    const out = await runTool("gravatar", { email: "beau@automattic.com" }, { fetchImpl: fetchJson(PROFILE) });
    expect(out.is_error).toBe(false);
    expect(out.content).toContain("https://x.com/beaulebens");
  });
});
