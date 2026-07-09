import { describe, it, expect } from "vitest";
import { jinaRead } from "../../src/osint/jina.js";
import { tavilySearch } from "../../src/osint/tavily.js";
import type { FetchLike } from "../../src/osint/types.js";

// restore-tool-belt (2026-06-24): Jina reader is the keyed CORS-open tool that survived live verification
// (its REAL GET response reflects ACAO). hydra-osint-provider-inputs (2026-07-08): Tavily, once rejected to
// the proxy tier, was RE-TESTED live (Origin hydra) and its ACTUAL POST response now carries ACAO — they
// fixed their CORS, so it is CORS-open/direct now (the scar discipline held: decided off the real response).

const KEY = "jina_SECRET-do-not-leak";

function fetchText(text: string, capture?: (req: { url: string; init?: RequestInit }) => void): FetchLike {
  return (async (url: string, init?: RequestInit) => {
    capture?.({ url, init });
    return { ok: true, status: 200, text: async () => text };
  }) as unknown as FetchLike;
}

function fetchJson(json: unknown, capture?: (req: { url: string; init?: RequestInit }) => void): FetchLike {
  return (async (url: string, init?: RequestInit) => {
    capture?.({ url, init });
    return { ok: true, status: 200, json: async () => json };
  }) as unknown as FetchLike;
}

describe("jina reader", () => {
  it("reads page text into summary + extracts leads, key in the Authorization header, URL appended raw", async () => {
    let seen: { url: string; init?: RequestInit } | undefined;
    const fetchImpl = fetchText("# Page\nContact us at https://payout.example and 198.51.100.9", (r) => (seen = r));
    const out = await jinaRead("https://scam.test/claim", KEY, { fetchImpl, retries: 0 });
    expect(out.provider).toBe("jina");
    expect(out.tier).toBe("T2");
    expect(out.summary).toContain("Contact us");
    expect(out.entities.find((e) => e.type === "url" && e.value === "https://payout.example")).toBeTruthy();
    expect(out.entities.find((e) => e.type === "ip" && e.value === "198.51.100.9")).toBeTruthy();
    expect(seen?.url).toBe("https://r.jina.ai/https://scam.test/claim");
    expect((seen?.init?.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
  });

  it("throws Jina HTTP <status> on 401 without leaking the key", async () => {
    const fetchImpl = (async () => ({ ok: false, status: 401, text: async () => "" })) as unknown as FetchLike;
    await expect(jinaRead("https://x.test", KEY, { fetchImpl, retries: 0 })).rejects.toThrow(/Jina HTTP 401/);
    await jinaRead("https://x.test", KEY, { fetchImpl, retries: 0 }).catch((e) => expect(String(e)).not.toContain(KEY));
  });
});

describe("tavily search (hydra-osint-provider-inputs 2026-07-08 — direct, CORS-open)", () => {
  it("POSTs to api.tavily.com with the key in the Authorization header, parses answer+results into T3 leads", async () => {
    let seen: { url: string; init?: RequestInit } | undefined;
    const fetchImpl = fetchJson(
      { answer: "See https://payout.example and 198.51.100.9", results: [{ url: "https://scam.test/a", content: "kit at cdn.badkit.io" }] },
      (r) => (seen = r),
    );
    const out = await tavilySearch("who is behind scam.test", KEY, { fetchImpl, retries: 0 });
    expect(out.provider).toBe("tavily");
    expect(out.tier).toBe("T3"); // a search summary is never citable — lead-grade
    expect(seen?.url).toBe("https://api.tavily.com/search");
    expect((seen?.init?.headers as Record<string, string>).authorization).toBe(`Bearer ${KEY}`);
    expect((seen?.init?.method as string)).toBe("POST");
    expect(out.entities.find((e) => e.type === "url" && e.value === "https://payout.example")).toBeTruthy();
    expect(out.entities.find((e) => e.type === "ip" && e.value === "198.51.100.9")).toBeTruthy();
    expect(out.entities.find((e) => e.type === "domain" && e.value === "cdn.badkit.io")).toBeTruthy();
  });

  it("throws Tavily HTTP <status> on 401 without leaking the key", async () => {
    const fetchImpl = (async () => ({ ok: false, status: 401, json: async () => ({}) })) as unknown as FetchLike;
    await expect(tavilySearch("x", KEY, { fetchImpl, retries: 0 })).rejects.toThrow(/Tavily HTTP 401/);
    await tavilySearch("x", KEY, { fetchImpl, retries: 0 }).catch((e) => expect(String(e)).not.toContain(KEY));
  });
});
