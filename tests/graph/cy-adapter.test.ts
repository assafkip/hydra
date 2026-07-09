import { describe, it, expect } from "vitest";
import { modelToElements, shortLabel, edgeId, clusterHsl } from "../../src/graph/cy-adapter.js";
import type { GraphModel } from "../../src/graph/model.js";

// PRD cytoscape-graph cyg-adapter: the pure model -> Cytoscape-element mapping in graph.html's
// data vocabulary. These prove the role/shape/origin/score mapping, the deterministic stable edge
// id, the alias canonicalization, the F3 no-thumbnail rule, and the degenerate cases.

function node(over: Partial<GraphModel["nodes"][number]> & { id: string; label: string; kind: any }) {
  return { promoted: false, ...over } as GraphModel["nodes"][number];
}

const SEED = node({ id: "objective", label: "Investigate example.com", kind: "objective" });

// PRD live-graph-quality (Codex finding-2 area): favicon-by-promoted. Only a CONFIRMED (promoted) or
// INTAKE web-host node gets a favicon; an un-confirmed osint-discovered LEAD domain does NOT — so a live
// dig never leaks a transient discovered domain to Google, and osint dead-ends read visually distinct.
describe("modelToElements — favicon-by-promoted (live-graph privacy)", () => {
  const webHost = (over: Partial<GraphModel["nodes"][number]>) =>
    node({ id: "n", label: "discovered.com", kind: "lead", entityType: "domain", ...over });
  const thumbOf = (n: GraphModel["nodes"][number]) =>
    modelToElements({ objective: "o", nodes: [SEED, n], edges: [] }).nodes.find((x) => x.data.id === n.id)!.data.thumbnail;

  it("a PROMOTED domain gets a favicon", () => {
    expect(thumbOf(webHost({ id: "p", kind: "finding", promoted: true }))).toBeTruthy();
  });
  it("an INTAKE domain gets a favicon", () => {
    expect(thumbOf(webHost({ id: "i", promoted: false, origin: "intake" }))).toBeTruthy();
  });
  it("an un-confirmed osint LEAD domain gets NO favicon (no egress for a discovered dead-end)", () => {
    expect(thumbOf(webHost({ id: "l", promoted: false, origin: "osint" }))).toBeFalsy();
  });
  it("a non-web-host node never gets a favicon regardless of promotion", () => {
    expect(thumbOf(webHost({ id: "ip", kind: "finding", promoted: true, entityType: "ip", label: "1.2.3.4" }))).toBeFalsy();
  });
});

describe("modelToElements", () => {
  it("maps the objective to a distinct seed node (round-rectangle, purple, solid, score 100)", () => {
    const { nodes } = modelToElements({ objective: "o", nodes: [SEED], edges: [] });
    expect(nodes).toHaveLength(1);
    const d = nodes[0].data;
    expect(d.kind).toBe("objective");
    expect(d.role).toBe("seed");
    expect(d.shape).toBe("round-rectangle");
    expect(d.clusterColor).toBe("#7E22CE");
    expect(d.color).toBe("#7E22CE");
    expect(d.borderStyle).toBe("solid");
    expect(d.score).toBe(100);
    expect("thumbnail" in d).toBe(false); // F3: no thumbnail field (D12)
  });

  it("maps a promoted finding to its role/shape/color with dashed osint border + grade score", () => {
    const m: GraphModel = {
      objective: "o",
      nodes: [SEED, node({ id: "finding:0:domain:evil.com", label: "https://evil.com/path", kind: "finding", promoted: true, entityType: "domain", grade: "A", sourceCount: 2, infraSourceCount: 2 })],
      edges: [{ from: "objective", to: "finding:0:domain:evil.com", kind: "promoted" }],
    };
    const { nodes, edges } = modelToElements(m);
    const f = nodes.find((n) => n.data.kind === "finding")!.data;
    expect(f.role).toBe("infra");
    expect(f.shape).toBe("rectangle");
    expect(f.color).toBe("#15803D");
    expect(f.clusterColor).toBe("#475569"); // honest slate (no client clusters)
    expect(f.borderStyle).toBe("dashed");
    expect(f.origin).toBe("osint");
    expect(f.type).toBe("domain");
    expect(f.surface_type).toBe("domain");
    expect(f.report_count).toBe(2);
    expect(f.score).toBe(90); // grade A
    expect(f.label).toBe("evil.com/path"); // shortLabel drops scheme
    expect(f.full_name).toBe("https://evil.com/path");
    // promoted edge: high confidence, green, width 2.5, solid, stable id
    expect(edges).toHaveLength(1);
    expect(edges[0].data.id).toBe("e:objective__finding:0:domain:evil.com__promoted");
    expect(edges[0].data.confidence).toBe("high");
    expect(edges[0].data.color).toBe("#15803D");
    expect(edges[0].data.width).toBe(2.5);
    expect(edges[0].data.lineStyle).toBe("solid");
  });

  it("maps entity↔entity network edges (co_occurs dotted, linked solid, no arrow styling kind preserved)", () => {
    const a = node({ id: "finding:0:ip:1.1.1.1", label: "1.1.1.1", kind: "finding", promoted: true, entityType: "ip" });
    const b = node({ id: "finding:1:domain:x.io", label: "x.io", kind: "finding", promoted: true, entityType: "domain" });
    const m: GraphModel = {
      objective: "Case graph",
      nodes: [SEED, a, b],
      edges: [
        { from: a.id, to: b.id, kind: "co_occurs", confidence: "low" },
        { from: a.id, to: b.id, kind: "linked", confidence: "high" },
      ],
    };
    const { edges } = modelToElements(m);
    const co = edges.find((e) => e.data.kind === "co_occurs")!.data;
    const li = edges.find((e) => e.data.kind === "linked")!.data;
    expect(co.lineStyle).toBe("dotted");
    expect(co.color).toBe("#A8A29E");
    expect(li.lineStyle).toBe("solid");
    expect(li.color).toBe("#78716C");
    // distinct stable ids per kind (no collision with the objective spoke edge ids)
    expect(co.id).not.toBe(li.id);
  });

  it("maps a held lead to a low-confidence dotted edge and carries the gate reason", () => {
    const m: GraphModel = {
      objective: "o",
      nodes: [SEED, node({ id: "lead:0:person:Jane", label: "Jane Roe", kind: "lead", promoted: false, entityType: "person", reason: "name-only, no crosslink" })],
      edges: [{ from: "objective", to: "lead:0:person:Jane", kind: "lead" }],
    };
    const { nodes, edges } = modelToElements(m);
    const l = nodes.find((n) => n.data.kind === "lead")!.data;
    expect(l.role).toBe("operator");
    expect(l.shape).toBe("ellipse");
    expect(l.reason).toBe("name-only, no crosslink");
    expect(l.score).toBe(40); // unknown grade -> mid
    expect(edges[0].data.confidence).toBe("low");
    expect(edges[0].data.color).toBe("#8A847D");
    expect(edges[0].data.width).toBe(1);
    expect(edges[0].data.lineStyle).toBe("dotted");
  });

  it("canonicalizes entity-type aliases to the right role/shape (D11)", () => {
    const cases: Array<[string, string, string]> = [
      ["ip_address", "infra", "rectangle"],
      ["crypto_wallet", "ioc", "octagon"],
      ["hash_sha256", "ioc", "octagon"],
      ["telegram_channel", "channel", "diamond"],
      ["username", "operator", "ellipse"],
      ["wallet", "ioc", "octagon"],
      ["something_unknown", "source", "triangle"],
    ];
    for (const [type, role, shape] of cases) {
      const { nodes } = modelToElements({
        objective: "o",
        nodes: [node({ id: `finding:0:${type}:x`, label: "x", kind: "finding", promoted: true, entityType: type })],
        edges: [],
      });
      expect(nodes[0].data.role, type).toBe(role);
      expect(nodes[0].data.shape, type).toBe(shape);
    }
  });

  it("is deterministic — two calls are byte-identical", () => {
    const m: GraphModel = {
      objective: "o",
      nodes: [SEED, node({ id: "finding:0:ip:1.2.3.4", label: "1.2.3.4", kind: "finding", promoted: true, entityType: "ip", grade: "B" })],
      edges: [{ from: "objective", to: "finding:0:ip:1.2.3.4", kind: "promoted" }],
    };
    expect(JSON.stringify(modelToElements(m))).toBe(JSON.stringify(modelToElements(m)));
  });

  it("keeps a hostile entity value as a literal data string (no markup, no escaping)", () => {
    const xss = `<img src=x onerror=alert(1)>`;
    const { nodes } = modelToElements({
      objective: "o",
      nodes: [node({ id: "finding:0:person:x", label: xss, kind: "finding", promoted: true, entityType: "person" })],
      edges: [],
    });
    expect(nodes[0].data.full_name).toBe(xss); // verbatim — the renderer puts it on canvas / via textContent
    expect(typeof nodes[0].data.label).toBe("string");
  });

  it("drops an edge whose endpoint is missing (no dangling edge for cytoscape)", () => {
    const { edges } = modelToElements({
      objective: "o",
      nodes: [SEED],
      edges: [{ from: "objective", to: "ghost", kind: "promoted" }],
    });
    expect(edges).toEqual([]);
  });

  it("degenerate: empty/objective-only models", () => {
    expect(modelToElements(null)).toEqual({ nodes: [], edges: [] });
    expect(modelToElements({ objective: "o", nodes: [], edges: [] })).toEqual({ nodes: [], edges: [] });
    const one = modelToElements({ objective: "o", nodes: [SEED], edges: [] });
    expect(one.nodes).toHaveLength(1);
    expect(one.edges).toHaveLength(0);
  });

  it("shortLabel + edgeId helpers", () => {
    expect(shortLabel("https://a.com/")).toBe("a.com");
    expect(shortLabel("x".repeat(40)).length).toBe(26);
    expect(edgeId({ from: "a", to: "b", kind: "lead" })).toBe("e:a__b__lead");
  });

  it("shortLabel preserves the host and ellipsizes the path (url is never blind-cut)", () => {
    // a long URL (>26 after stripping the query): the host is the identity — keep it, collapse the path.
    expect(shortLabel("https://example.com/very/long/path/segment?q=tracking", "url")).toBe("example.com/…");
    // a short url keeps its path (no truncation needed)
    expect(shortLabel("evil.com/login", "url")).toBe("evil.com/login");
    // www + query/fragment are stripped as noise (the short path survives)
    expect(shortLabel("https://www.example.com/p#frag", "domain")).toBe("example.com/p");
  });

  it("shortLabel middle-ellipsizes an over-long host, keeping the registrable tail", () => {
    const out = shortLabel("really-long-suspicious-subdomain.example.com", "domain");
    expect(out.length).toBe(26);
    expect(out).toContain("…");
    expect(out.endsWith("example.com")).toBe(true); // the registrable tail (identity) survives
  });

  it("shortLabel middle-ellipsizes a wallet/hash (head…tail, the standard crypto display)", () => {
    const wallet = "0x52908400098527886e0f7030069857d2e4169ee7";
    const out = shortLabel(wallet, "wallet");
    expect(out.length).toBe(26);
    expect(out.startsWith("0x5290")).toBe(true);
    expect(out.endsWith("169ee7")).toBe(true); // distinctive tail visible, not chopped off
    expect(out).toContain("…");
  });

  it("shortLabel leaves an email intact when short (the local part matters)", () => {
    expect(shortLabel("abuse@acmecorp.io", "email")).toBe("abuse@acmecorp.io");
  });
});

// clu-graph-node-parity: the border style encodes PROVENANCE like the original graph.html — solid =
// from intake, dashed = osint/detective-investigated, dotted = manual. No longer hardcoded.
describe("node border style reflects origin (clu-graph-node-parity)", () => {
  function n(over: Partial<GraphModel["nodes"][number]> & { id: string; label: string }) {
    return { promoted: true, kind: "finding", ...over } as GraphModel["nodes"][number];
  }
  it("intake → solid, osint → dashed, manual → dotted", () => {
    const model = {
      objective: "o",
      nodes: [
        n({ id: "finding:1:domain:a.io", label: "a.io", entityType: "domain", origin: "intake" }),
        n({ id: "finding:2:ip:1.2.3.4", label: "1.2.3.4", entityType: "ip", origin: "osint" }),
        n({ id: "finding:3:wallet:0xabc", label: "0xabc", entityType: "wallet", origin: "manual" }),
      ],
      edges: [],
    };
    const byLabel = new Map(modelToElements(model).nodes.map((x) => [x.data.label, x.data]));
    expect(byLabel.get("a.io")!.borderStyle).toBe("solid");
    expect(byLabel.get("a.io")!.origin).toBe("intake");
    expect(byLabel.get("1.2.3.4")!.borderStyle).toBe("dashed");
    expect(byLabel.get("0xabc")!.borderStyle).toBe("dotted");
  });
  it("clusterHsl matches the original graph.html sat/lightness (65% 50%)", () => {
    expect(clusterHsl("Drainer Infra")).toMatch(/, 65%, 50%\)$/);
  });
});
