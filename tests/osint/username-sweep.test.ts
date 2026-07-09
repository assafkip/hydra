import { describe, it, expect } from "vitest";
import { usernameSweep } from "../../src/osint/username-sweep.js";

// restore-tool-belt (2026-06-24): keyless username presence sweep (GitHub + Keybase). The live CORS proof
// is the deploy gate; this proves the result logic against mocked fetches.

function mockFetch(routes: Record<string, { ok?: boolean; body?: unknown; throws?: boolean }>): typeof fetch {
  return (async (url: string) => {
    const key = Object.keys(routes).find((k) => String(url).includes(k));
    const r = key ? routes[key] : { ok: false };
    if (r.throws) throw new Error("network down");
    return { ok: r.ok, json: async () => r.body ?? {} } as Response;
  }) as unknown as typeof fetch;
}

describe("usernameSweep", () => {
  it("returns a profile URL for each platform the handle exists on", async () => {
    const res = await usernameSweep("torvalds", {
      fetchImpl: mockFetch({
        "api.github.com": { ok: true, body: { html_url: "https://github.com/torvalds" } },
        "keybase.io": { ok: true, body: { status: { code: 0 }, them: [{ id: "x" }] } },
      }),
    });
    expect(res.tier).toBe("T3"); // a social presence is a lead, never proof
    expect(res.entities.map((e) => e.value).sort()).toEqual(["https://github.com/torvalds", "https://keybase.io/torvalds"]);
    expect(res.entities.every((e) => e.type === "url")).toBe(true);
  });

  it("strips a leading @ and omits platforms where the handle is absent (404 / empty)", async () => {
    const res = await usernameSweep("@ghost", {
      fetchImpl: mockFetch({
        "api.github.com": { ok: false }, // 404 absent
        "keybase.io": { ok: true, body: { status: { code: 0 }, them: [] } }, // found-but-empty
      }),
    });
    expect(res.query).toBe("ghost");
    expect(res.entities).toEqual([]);
  });

  it("NEGATIVE: one platform throwing never sinks the sweep (allSettled)", async () => {
    const res = await usernameSweep("torvalds", {
      fetchImpl: mockFetch({
        "api.github.com": { throws: true }, // GitHub down
        "keybase.io": { ok: true, body: { status: { code: 0 }, them: [{ id: "x" }] } },
      }),
    });
    expect(res.entities.map((e) => e.value)).toEqual(["https://keybase.io/torvalds"]); // keybase still reported
  });
});
