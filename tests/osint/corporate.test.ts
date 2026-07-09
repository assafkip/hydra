import { describe, it, expect } from "vitest";
import { gleifLei } from "../../src/osint/gleif.js";
import { wikidataEntity } from "../../src/osint/wikidata.js";
import type { FetchLike } from "../../src/osint/types.js";

// Shapes captured live 2026-07-09 from each provider's real response.
function fetchJson(payload: unknown, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, json: async () => payload })) as unknown as FetchLike;
}
// Route Wikidata's two calls (search then getentities) by the `action` query param.
function fetchByAction(map: Record<string, unknown>): FetchLike {
  return (async (url: string) => {
    const action = new URL(url).searchParams.get("action")!;
    return { ok: true, status: 200, json: async () => map[action] };
  }) as unknown as FetchLike;
}

describe("gleifLei (api.gleif.org) — T1 registry, typed org pivots", () => {
  it("emits the legal name + trade names as org pivots with LEI/jurisdiction/status in the note", async () => {
    const impl = fetchJson({
      data: [
        {
          attributes: {
            lei: "HWUPKR0MPOU8FGXBT394",
            entity: {
              legalName: { name: "Apple Inc." },
              otherNames: [{ name: "Apple Computer, Inc." }],
              legalAddress: { city: "Glendale", country: "US" },
              jurisdiction: "US-CA",
              status: "ACTIVE",
            },
            registration: { status: "ISSUED" },
          },
          relationships: { "direct-parent": {}, "direct-children": {} },
        },
      ],
    });
    const r = await gleifLei("Apple Inc.", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("gleif");
    expect(r.tier).toBe("T1");
    const keyed = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(keyed).toContain("org:Apple Inc.");
    expect(keyed).toContain("org:Apple Computer, Inc.");
    expect(r.entities[0].note).toContain("LEI HWUPKR0MPOU8FGXBT394");
    expect(r.entities[0].note).toContain("has parent / has children");
  });
  it("returns an empty (no-match) result, not an error, for an unknown name", async () => {
    const r = await gleifLei("Nonexistent Co", { fetchImpl: fetchJson({ data: [] }), retries: 0 });
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("no LEI registry record");
  });
  it("DROPS a record whose legal name is unrelated to the query (substitution guard, finding-1)", async () => {
    const impl = fetchJson({ data: [{ attributes: { lei: "X", entity: { legalName: { name: "Totally Unrelated Holdings GmbH" } } } }] });
    const r = await gleifLei("Apple Inc.", { fetchImpl: impl, retries: 0 });
    expect(r.entities).toHaveLength(0); // unrelated record dropped, never a T1 pivot
  });
  it("throws on an unexpected (non-data-array) shape and caps + length-bounds a hostile response", async () => {
    await expect(gleifLei("x", { fetchImpl: fetchJson({ nope: 1 }), retries: 0 })).rejects.toThrow(/unexpected response shape/);
    const data = Array.from({ length: 300 }, () => ({ attributes: { lei: "L", entity: { legalName: { name: "N".repeat(5000) } } } }));
    const r = await gleifLei("x", { fetchImpl: fetchJson({ data }), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(100); // count cap
    expect(Math.max(...r.entities.map((e) => e.value.length))).toBeLessThanOrEqual(201); // length cap
  });
});

describe("wikidataEntity (www.wikidata.org, origin=*) — T3 lead, typed pivots", () => {
  it("emits label + aliases (org) + official website (url); handles ride the summary", async () => {
    const impl = fetchByAction({
      wbsearchentities: { search: [{ id: "Q21708200", label: "OpenAI", description: "AI research org" }] },
      wbgetentities: {
        entities: {
          Q21708200: {
            aliases: { en: [{ value: "openai.com" }, { value: "Open AI" }] },
            claims: {
              P856: [{ mainsnak: { datavalue: { value: "https://openai.com/" } } }],
              P2002: [{ mainsnak: { datavalue: { value: "OpenAI" } } }],
              P2037: [{ mainsnak: { datavalue: { value: "openai" } } }],
            },
          },
        },
      },
    });
    const r = await wikidataEntity("OpenAI", { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("wikidata");
    expect(r.tier).toBe("T3");
    const keyed = r.entities.map((e) => `${e.type}:${e.value}`);
    expect(keyed).toContain("org:OpenAI");
    expect(keyed).toContain("org:Open AI");
    expect(keyed).toContain("url:https://openai.com/");
    expect(r.summary).toContain("Twitter @OpenAI");
    expect(r.summary).toContain("GitHub openai");
  });
  it("appends origin=* to every request (the MediaWiki CORS grant)", async () => {
    const urls: string[] = [];
    const impl = (async (url: string) => {
      urls.push(url);
      const action = new URL(url).searchParams.get("action");
      return { ok: true, status: 200, json: async () => (action === "wbsearchentities" ? { search: [{ id: "Q1", label: "x" }] } : { entities: { Q1: {} } }) };
    }) as unknown as FetchLike;
    await wikidataEntity("x", { fetchImpl: impl, retries: 0 });
    expect(urls.length).toBe(2);
    expect(urls.every((u) => new URL(u).searchParams.get("origin") === "*")).toBe(true);
  });
  it("returns an empty result for a name with no Wikidata item", async () => {
    const r = await wikidataEntity("zzznope", { fetchImpl: fetchJson({ search: [] }), retries: 0 });
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("no Wikidata item");
  });
  it("DROPS an unrelated top hit — no substitution into the pivot graph (finding-2)", async () => {
    const impl = fetchByAction({
      wbsearchentities: { search: [{ id: "Q999", label: "Some Unrelated Band", description: "a music group" }] },
      wbgetentities: { entities: { Q999: { aliases: { en: [{ value: "The Unrelated" }] }, claims: { P856: [{ mainsnak: { datavalue: { value: "https://evil.example/" } } }] } } } },
    });
    const r = await wikidataEntity("Apple Inc.", { fetchImpl: impl, retries: 0 });
    expect(r.entities).toHaveLength(0);
    expect(r.summary).toContain("did not match");
  });
});
