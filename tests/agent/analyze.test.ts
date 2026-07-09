import { describe, it, expect } from "vitest";
import {
  gateAttribution,
  salvageAnalyzeJson,
  mapAnalyzeToCanonKeys,
  buildAnalyzePrompt,
  ANALYZE_MAX_TOKENS,
  ANALYZE_MAX_RELATIONSHIPS,
  type PresentedEntity,
} from "../../src/agent/analyze.js";
import { canonKey } from "../../src/entity/db.js";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, analyzeCase } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// PRD-B (RCA discipline-evaporation): the depth-restoration — the token/rel caps are back at the
// original floors, and the analyze prompt feeds RETAINED per-entity evidence text (a `dossier`), not
// just id/label/type/role. Each assertion carries its NEGATIVE proof (the floor would fail thinned;
// the evidence is absent for an entity without a claim).
describe("analyze depth restoration (PRD-B)", () => {
  it("caps are restored to the original floors (analyze-max-tokens / analyze-max-rels)", () => {
    expect(ANALYZE_MAX_TOKENS).toBeGreaterThanOrEqual(16384); // negative: 4096 (the thinned value) fails this
    expect(ANALYZE_MAX_RELATIONSHIPS).toBeGreaterThanOrEqual(150); // negative: 80 fails this
  });

  it("feeds per-entity evidence text when a dossier is present; omits it when absent", () => {
    const withEvidence: PresentedEntity[] = [
      { id: "e0", canonKey: "k0", label: "scam.example", type: "domain", role: "operator", dossier: "drains to wallet W; hosts the ColorDSGN kit" },
    ];
    const withoutEvidence: PresentedEntity[] = [
      { id: "e1", canonKey: "k1", label: "noise.example", type: "domain", role: "infra" },
    ];
    const promptWith = buildAnalyzePrompt(withEvidence, null);
    const promptWithout = buildAnalyzePrompt(withoutEvidence, null);
    // the evidence text reaches the prompt under an `evidence:` line
    expect(promptWith).toContain("evidence: drains to wallet W; hosts the ColorDSGN kit");
    // NEGATIVE proof: an entity with no dossier emits NO evidence line (not the literal "undefined")
    expect(promptWithout).not.toContain("evidence:");
    expect(promptWithout).not.toContain("undefined");
  });

  it("the prompt still bounds typed_relationships by the restored cap", () => {
    const p = buildAnalyzePrompt([{ id: "e0", canonKey: "k0", label: "x", type: "domain", role: "infra" }], null);
    expect(p).toContain(`Emit AT MOST ${ANALYZE_MAX_RELATIONSHIPS} typed_relationships`);
  });
});

// kweb-analyze-uncap-entities (sp-bc070b51): analyzeCase must feed EVERY entity into the one analyze call —
// analyze clusters across the whole set, so the old presentedFor 80-slice silently dropped every cluster/edge
// touching an entity past index 80. Each assertion carries its NEGATIVE proof: under the 80-slice, an id past
// e79 never reaches the prompt AND mapAnalyzeToCanonKeys drops it from the response (id outside presented set).
describe("analyzeCase feeds every entity past the 80-cap (uncap)", () => {
  async function vaultWithEntities(n: number): Promise<Vault> {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, "sk-ant-analyze");
    // One run holding n distinct, admitted domain entities (real .com TLD so the admission gate keeps them).
    const promoted = Array.from({ length: n }, (_, i) => ({
      entity: `d${String(i).padStart(3, "0")}.example.com`,
      entity_type: "domain",
      grade: "A",
      infra_source_count: 2,
      source_count: 2,
    }));
    await vault.put("run:dense", { objective: "dense", steps: [], promoted, leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn" });
    return vault;
  }

  // Stub: capture the prompt body, find the LARGEST e<index> id present, and echo a cluster referencing
  // e0 + that max id. Returns the captured prompt + the max index so the test can assert on both.
  function analyzeFetch(): { impl: FetchLike; lastBody: () => string; maxId: () => string; maxIdx: () => number } {
    let body = "";
    let maxId = "e0";
    let maxIdx = 0;
    const impl = (async (_url: string, init: RequestInit) => {
      body = String(init.body);
      // each prompt entity line is `eN: <label> …` (newlines are escaped in the JSON body, so no \b).
      const ids = [...body.matchAll(/e(\d+):/g)].map((m) => ({ id: `e${m[1]}`, idx: Number(m[1]) }));
      const top = ids.reduce((a, b) => (b.idx > a.idx ? b : a), { id: "e0", idx: 0 });
      maxId = top.id;
      maxIdx = top.idx;
      const out = JSON.stringify({
        clusters: [{ name: "Ring", kind: "network", member_ids: ["e0", maxId], description: "x" }],
        typed_relationships: [{ src_id: "e0", dst_id: maxId, rel_type: "shares_infra", confidence: "high", evidence: "y" }],
      });
      return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: out }], stop_reason: "end_turn", usage: {} }) };
    }) as unknown as FetchLike;
    return { impl, lastBody: () => body, maxId: () => maxId, maxIdx: () => maxIdx };
  }

  it("a >80-entity case puts ids past e79 in the prompt AND a cluster/edge lands on one", async () => {
    const vault = await vaultWithEntities(120);
    const { impl, lastBody, maxIdx } = analyzeFetch();
    const { clusters, relationships } = await analyzeCase(vault, { fetchImpl: impl });

    // NEGATIVE proof #1: under the 80-slice the prompt holds only e0..e79, so an id past e79 is absent.
    expect(maxIdx()).toBeGreaterThanOrEqual(80);
    expect(lastBody()).toMatch(/e8\d:/); // at least one e8x id reached the prompt (newlines escaped → no \b)
    // NEGATIVE proof #2: the echoed cluster references e0 + an id past e79. With the slice that id is outside
    // the presented set, so mapAnalyzeToCanonKeys drops it → memberKeys would be length 1, not 2.
    expect(clusters).toHaveLength(1);
    expect(clusters[0].memberKeys).toHaveLength(2);
    // the relationship's dst also resolved (would be dropped entirely under the slice → relationships empty).
    expect(relationships).toHaveLength(1);
  });

  it("high-count (~200 entities) still returns clusters — clusters-first survives the uncapped list (codex finding-1)", async () => {
    const vault = await vaultWithEntities(200);
    const { impl, maxIdx } = analyzeFetch();
    const { clusters } = await analyzeCase(vault, { fetchImpl: impl });
    expect(maxIdx()).toBeGreaterThanOrEqual(150); // the full set reached the prompt, not a cap
    expect(clusters.length).toBeGreaterThan(0); // no token guard re-introduced a cap that zeroed clusters
  });
});

// ca-analyze (INC-3): the PURE analyze helpers — port of analyze.py. gate_attribution must clamp
// evidence-free strong attribution; the salvage parse must recover a truncated big-case response;
// the opaque-id → canonKey mapping must never invent an entity (drop ids outside the presented set).

describe("gateAttribution (port of analyze.py gate_attribution)", () => {
  it("strong attribution: low → drop, medium → co_listed, high → kept", () => {
    expect(gateAttribution("same_operator", "low")).toBeNull();
    expect(gateAttribution("same_operator", "medium")).toBe("co_listed");
    expect(gateAttribution("same_operator", "high")).toBe("same_operator");
  });
  it("missing confidence defaults to medium (demote)", () => {
    expect(gateAttribution("same_owner", null)).toBe("co_listed");
    expect(gateAttribution("same_owner", undefined)).toBe("co_listed");
  });
  it("non-attribution rel_types pass through unchanged at any confidence", () => {
    expect(gateAttribution("shills", "low")).toBe("shills");
    expect(gateAttribution("hosted_on", "high")).toBe("hosted_on");
  });
});

describe("salvageAnalyzeJson (port of _salvage_json + _extract_objects)", () => {
  it("parses clean JSON", () => {
    const r = salvageAnalyzeJson('{"clusters":[{"name":"Ring A","member_ids":["e0"]}],"typed_relationships":[]}');
    expect(r.clusters).toHaveLength(1);
    expect(r.typed_relationships).toHaveLength(0);
  });
  it("strips a ```json fence", () => {
    const r = salvageAnalyzeJson('```json\n{"clusters":[{"name":"X","member_ids":["e1"]}],"typed_relationships":[]}\n```');
    expect((r.clusters[0] as { name: string }).name).toBe("X");
  });
  it("recovers the COMPLETE objects from a truncated response (the last object is cut off)", () => {
    // The 2nd cluster object is truncated mid-string — _extract_objects keeps the 1st, drops the broken tail.
    const truncated = '{"clusters":[{"name":"Ring A","member_ids":["e0","e1"]},{"name":"Ring B incomp';
    const r = salvageAnalyzeJson(truncated);
    expect(r.clusters).toHaveLength(1);
    expect((r.clusters[0] as { name: string }).name).toBe("Ring A");
  });
  it("unparseable garbage → empty arrays, never throws", () => {
    const r = salvageAnalyzeJson("not json at all");
    expect(r.clusters).toEqual([]);
    expect(r.typed_relationships).toEqual([]);
  });
});

describe("mapAnalyzeToCanonKeys (opaque eN → canonKey, gate_attribution, no invented entity)", () => {
  const presented: PresentedEntity[] = [
    { id: "e0", canonKey: canonKey("person", "alice"), label: "Alice", type: "person", role: "operator" },
    { id: "e1", canonKey: canonKey("domain", "evil.com"), label: "evil.com", type: "domain", role: "infra" },
  ];

  it("maps cluster member_ids + relationship src/dst ids to canonKeys", () => {
    const raw = {
      clusters: [{ name: "Ring A", kind: "ring", member_ids: ["e0", "e1"], description: "the crew" }],
      typed_relationships: [{ src_id: "e0", dst_id: "e1", rel_type: "hosted_on", confidence: "high", evidence: "x" }],
    };
    const { clusters, relationships } = mapAnalyzeToCanonKeys(raw, presented);
    expect(clusters[0].memberKeys).toEqual([canonKey("person", "alice"), canonKey("domain", "evil.com")]);
    expect(relationships[0]).toMatchObject({
      srcKey: canonKey("person", "alice"),
      dstKey: canonKey("domain", "evil.com"),
      relType: "hosted_on",
    });
  });

  it("DROPS ids outside the presented set (never invents an entity — consolidate D1)", () => {
    const raw = {
      clusters: [{ name: "Ghost", member_ids: ["e9", "e0"] }], // e9 is not presented
      typed_relationships: [{ src_id: "e0", dst_id: "e9", rel_type: "shills", confidence: "high" }],
    };
    const { clusters, relationships } = mapAnalyzeToCanonKeys(raw, presented);
    expect(clusters[0].memberKeys).toEqual([canonKey("person", "alice")]); // e9 dropped
    expect(relationships).toEqual([]); // dst e9 unknown → relationship dropped
  });

  it("drops a cluster with zero known members + applies gate_attribution (low same_operator → drop)", () => {
    const raw = {
      clusters: [{ name: "Empty", member_ids: ["e7", "e8"] }],
      typed_relationships: [{ src_id: "e0", dst_id: "e1", rel_type: "same_operator", confidence: "low" }],
    };
    const { clusters, relationships } = mapAnalyzeToCanonKeys(raw, presented);
    expect(clusters).toEqual([]); // no known members
    expect(relationships).toEqual([]); // low strong-attribution dropped
  });

  it("self-loop relationship is dropped", () => {
    const raw = {
      clusters: [],
      typed_relationships: [{ src_id: "e0", dst_id: "e0", rel_type: "shills", confidence: "high" }],
    };
    expect(mapAnalyzeToCanonKeys(raw, presented).relationships).toEqual([]);
  });
});
