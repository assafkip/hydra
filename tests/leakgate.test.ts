import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
// @ts-expect-error — leakgate.mjs is a plain ESM script with no type declarations.
import { findOffenders, ALLOW, VENDOR_DOC_HOSTS, PIVOT_LINK_HOSTS, PROXY_TARGET_HOSTS, FEEDBACK_NAV_HOSTS, ENRICH_DOC_HOSTS, IDENTITY_LEAD_HOSTS } from "../scripts/leakgate.mjs";

// PRD cytoscape-graph D7 (codex-7): the bundled-vendor doc-URL exemption (VENDOR_DOC_HOSTS)
// must apply ONLY to the dist/ output. First-party src/ stays strict, so a vendor host can
// never silence a real first-party phone-home. These are the negative self-tests that prove
// a green leakgate is not a rubber stamp.

const VENDOR_HOST = [...VENDOR_DOC_HOSTS][0]; // e.g. alpinejs.dev

describe("leakgate findOffenders (dist-scoped vendor exemption)", () => {
  it("flags an off-allowlist origin in a src/ file", () => {
    const o = findOffenders("src/app.ts", `fetch("https://evil.example.com/x")`);
    expect(o.length).toBe(1);
    expect(o[0]).toContain("evil.example.com");
  });

  it("STILL flags a VENDOR_DOC_HOST origin in src/ (src is strict — D7)", () => {
    const o = findOffenders("src/app.ts", `const u = "https://${VENDOR_HOST}/docs"`);
    expect(o.length).toBe(1);
    expect(o[0]).toContain(VENDOR_HOST);
  });

  it("does NOT flag a VENDOR_DOC_HOST origin in dist/ (bundled vendor output is exempt)", () => {
    const o = findOffenders("dist/assets/vendor-abc.js", `link:"https://${VENDOR_HOST}/docs"`);
    expect(o).toEqual([]);
  });

  it("STILL flags a NON-vendor off-allowlist origin in dist/", () => {
    const o = findOffenders("dist/assets/vendor-abc.js", `fetch("https://evil.example.com/y")`);
    expect(o.length).toBe(1);
  });

  it("never flags an allowlisted origin, in src or dist", () => {
    const host = [...ALLOW][0];
    expect(findOffenders("src/llm/client.ts", `"https://${host}/v1/messages"`)).toEqual([]);
    expect(findOffenders("dist/assets/a.js", `"https://${host}/v1/messages"`)).toEqual([]);
  });

  it("never flags the W3C SVG namespace URI (spec identifier, not an origin)", () => {
    expect(findOffenders("src/graph/cy-graph.ts", `createElementNS("http://www.w3.org/2000/svg","g")`)).toEqual([]);
  });

  it("exempts the github.com feedback ANCHOR in src/feedback.ts (a navigation target, not a fetch)", () => {
    expect(findOffenders("src/feedback.ts", `const REPO = "https://github.com/assafkip/kipi"`)).toEqual([]);
    expect(findOffenders("dist/assets/index-abc.js", `"https://github.com/assafkip/kipi/issues/new"`)).toEqual([]);
  });

  it("STILL flags github.com in any OTHER src file (a real phone-home can't hide as 'feedback')", () => {
    const o = findOffenders("src/app.ts", `fetch("https://github.com/assafkip/kipi")`);
    expect(o.length).toBe(1);
  });

  it("exempts the provider docs↗ ANCHOR hosts in src/osint/enrich.ts (navigation, not a fetch)", () => {
    expect(findOffenders("src/osint/enrich.ts", `docsUrl: "https://developer.shodan.io/"`)).toEqual([]);
    expect(findOffenders("src/osint/enrich.ts", `docsUrl: "https://docs.etherscan.io/"`)).toEqual([]);
    expect(findOffenders("dist/assets/index-abc.js", `"https://developer.shodan.io/"`)).toEqual([]);
  });

  it("STILL flags a docs-host in any OTHER src file (a real phone-home can't hide as an enrich doc link)", () => {
    const o = findOffenders("src/app.ts", `fetch("https://developer.shodan.io/x")`);
    expect(o.length).toBe(1);
  });

  it("exempts the OSINT pivot LINK hosts in src/osint/pivots.ts (a clicked <a> href, not a fetch)", () => {
    // sp-f9d3c9ff→goal2 validation 2026-06-23: these are PivotLink.url hrefs the analyst clicks, never
    // browser fetches; the CSP connect-src wall (which lists none of them) blocks any direct request.
    expect(findOffenders("src/osint/pivots.ts", `["Domains on this nameserver", "https://securitytrails.com/list/ns/{value}"]`)).toEqual([]);
    expect(findOffenders("src/osint/pivots.ts", `"https://hackertarget.com/find-dns-records/?q={value}"`)).toEqual([]);
    expect(findOffenders("src/osint/pivots.ts", `"https://publicwww.com/websites/{value}"`)).toEqual([]);
    expect(findOffenders("dist/assets/index-abc.js", `"https://securitytrails.com/list/ns/x"`)).toEqual([]); // its dist bundle passes too
  });

  it("STILL flags a pivot-link host in any OTHER src file (a real phone-home can't hide as a pivot link)", () => {
    const o = findOffenders("src/app.ts", `fetch("https://securitytrails.com/x")`);
    expect(o.length).toBe(1);
  });

  it("every external host in src/osint/pivots.ts is enumerated in PIVOT_LINK_HOSTS (no silent re-RED)", () => {
    // The pivot module's exemption is a host SET (needed to attribute hosts in the minified dist bundle).
    // This guards the maintenance hazard: a new pivot whose host is not listed fails HERE with a clear
    // message, instead of silently re-REDding the leakgate later. Drift-proof, like the CSP parity test.
    const src = readFileSync(new URL("../src/osint/pivots.ts", import.meta.url), "utf8");
    const hosts = new Set([...src.matchAll(/https?:\/\/([a-zA-Z0-9.-]+)/g)].map((m) => m[1].toLowerCase().replace(/\.$/, "")));
    const allowed = new Set([...PIVOT_LINK_HOSTS, ...ALLOW]); // a host already in the CSP allowlist (urlscan.io, search.censys.io) is fine
    const missing = [...hosts].filter((h) => !allowed.has(h));
    expect(missing).toEqual([]);
  });

  it("strips a FULL-LINE // comment URL but NEVER hides a real fetch behind an inline // (codex)", () => {
    // a full-line comment example URL is not egress -> exempt:
    expect(findOffenders("src/ingest/record.ts", `  // rejects 'https://x.com"' fragments, matching URL_RE`)).toEqual([]);
    // an inline // (e.g. inside a string) must NOT strip the rest of the line and hide a real origin:
    const o = findOffenders("src/x.ts", `const marker = "//"; fetch("https://evil.example.com/x")`);
    expect(o.length).toBe(1);
    expect(o[0]).toContain("evil.example.com");
    // a trailing inline comment also must not hide a real fetch on the same line:
    const o2 = findOffenders("src/y.ts", `fetch("https://evil2.example.com/x"); // note`);
    expect(o2.length).toBe(1);
  });

  it("src/osint/pivots.ts performs NO fetch/XHR/WebSocket (the invariant that makes its hosts pure links)", () => {
    // The blanket pivot exemption is only safe because the module never egresses — it builds hrefs. If a
    // real fetch is ever added here, this fails (move the egress out of pivots.ts or allowlist it properly).
    const src = readFileSync(new URL("../src/osint/pivots.ts", import.meta.url), "utf8");
    expect(src).not.toMatch(/\bfetch\s*\(|XMLHttpRequest|new\s+WebSocket|sendBeacon/);
  });
});

// sp-c5e2dbc1: the four host exemptions are bundle-WIDE in dist (the `isModule || vendor` pattern), so the
// dist scan would not flag a bundled fetch to an exempted host. That is mitigated at two stronger layers —
// the src scan stays STRICT (catches every first-party fetch) and the CSP connect-src wall blocks at runtime
// any host not in ALLOW — so no leak path exists (codex finding-2, low-pri, CSP-mitigated, no such fetch
// today). The REALISTIC residual is a future dev SILENTLY WIDENING an exemption set with a dangerous host.
// These two guards make widening a deliberate, reviewed act and pin the exact property that keeps the
// dist-wide exemption safe.
describe("leakgate exemption-set hardening (sp-c5e2dbc1)", () => {
  // Frozen membership. Any add/remove to an exemption set forces a deliberate edit HERE (reviewed), so a
  // host can never be quietly added to an egress-gate exemption. Sorted for a stable diff.
  const snapshot = (s: Set<string>) => [...s].sort();
  it("VENDOR_DOC_HOSTS membership is frozen", () => {
    expect(snapshot(VENDOR_DOC_HOSTS)).toEqual([
      "alpinejs.dev", "cdn.jsdelivr.net", "en.wikipedia.org", "engelschall.com", "github.com",
      "jquery.org", "opensource.org", "purl.oclc.org", "purl.org", "schemas.microsoft.com",
      "schemas.openxmlformats.org", "sheetjs.com", "sheetjs.openxmlformats.org", "tldrlegal.com",
      "www.ibm.com", "www.inkscape.org", "www.npmjs.com", "www.w3.org",
    ]);
  });
  it("PROXY_TARGET_HOSTS membership is frozen", () => {
    expect(snapshot(PROXY_TARGET_HOSTS)).toEqual([
      "api.abuseipdb.com", "api.exa.ai", "api.greynoise.io", "api.hunter.io", "api.securitytrails.com",
      "example.com", "pulsedive.com", "www.virustotal.com",
    ]);
  });
  it("FEEDBACK_NAV_HOSTS membership is frozen", () => {
    expect(snapshot(FEEDBACK_NAV_HOSTS)).toEqual(["github.com"]);
  });
  it("ENRICH_DOC_HOSTS membership is frozen", () => {
    expect(snapshot(ENRICH_DOC_HOSTS)).toEqual([
      // founder 2026-07-09: + the five KEY_GUIDANCE token-creation hosts (account.shodan.io, app.tavily.com,
      // etherscan.io, github.com, www.perplexity.ai) — nav anchors, not fetch targets.
      "account.shodan.io", "app.tavily.com", "developer.shodan.io", "docs.etherscan.io", "docs.github.com",
      "docs.gitlab.com", "docs.perplexity.ai", "docs.tavily.com", "etherscan.io", "github.com", "jina.ai",
      "www.perplexity.ai",
    ]);
  });
  it("IDENTITY_LEAD_HOSTS membership is frozen", () => {
    expect(snapshot(IDENTITY_LEAD_HOSTS)).toEqual(["news.ycombinator.com", "twitter.com", "www.npmjs.com"]);
  });
  it("PIVOT_LINK_HOSTS membership is frozen", () => {
    expect(snapshot(PIVOT_LINK_HOSTS)).toEqual([
      "blockchair.com", "builtwith.com", "cloud.walletconnect.com", "dnsdumpster.com", "dnslytics.com",
      "etherscan.io", "hackertarget.com", "haveibeenpwned.com", "hunter.io", "lookup.icann.org",
      "platform.arkhamintelligence.com", "publicwww.com", "securitytrails.com", "t.me", "tgstat.com",
      "www.abuseipdb.com", "www.chainabuse.com", "www.google.com", "www.shodan.io", "www.truecaller.com",
      "www.virustotal.com", "x.com",
    ]);
  });

  // The safety dichotomy codex's finding-2 turns on: the dist-wide exemption can only leak if an exempted
  // host is ALSO reachable via CSP connect-src (i.e. in ALLOW). Today every exempted host is DISJOINT from
  // ALLOW, so CSP blocks any direct fetch to it at runtime — the exemption is safe by construction. If a host
  // ever lands in BOTH an exemption set and ALLOW, that overlap must be a DELIBERATELY acknowledged intended
  // provider (added below with a reason), not a silent one. Empty today.
  it("no exempted host is CSP-connect-src reachable except deliberately-acknowledged provider overlaps", () => {
    const KNOWN_PROVIDER_OVERLAP = new Set<string>([
      // finding-3 (2026-07-09): haveibeenpwned.com is a pivots.ts PIVOT_LINK_HOSTS nav link AND, as of the
      // free email/breach providers, a REAL fetch origin (src/osint/hibp-catalog.ts fetches the keyless
      // domain breach catalog). It is deliberately in the CSP connect-src ALLOW as a first-party provider;
      // the pivots.ts nav-link exemption for the same host is the acknowledged overlap. Safe: the fetch is a
      // real, intended provider call, not a hidden phone-home.
      "haveibeenpwned.com",
    ]); // a host that is both a link/doc exemption AND a real fetch provider; document the reason when adding
    // CSP connect-src reachability must match the wall's real semantics, which include the `*.workers.dev`
    // WILDCARD entry — an exact `ALLOW.has(h)` would false-green on a `foo.workers.dev` exempted host that
    // IS reachable (codex). Mirror the wildcard: a `*.suffix` ALLOW entry matches any same-suffix host.
    const isCspReachable = (host: string): boolean => {
      for (const entry of ALLOW as Set<string>) {
        if (entry === host) return true;
        if (entry.startsWith("*.") && host.endsWith(entry.slice(1)) && host.length > entry.length - 1) return true;
      }
      return false;
    };
    // self-check the matcher so the guard itself can't silently rot: exact, wildcard, and a miss.
    expect(isCspReachable("api.anthropic.com")).toBe(true); // exact ALLOW entry
    expect(isCspReachable("foo.workers.dev")).toBe(true); // matched by the *.workers.dev wildcard
    expect(isCspReachable("workers.dev")).toBe(false); // the bare apex is NOT covered by *.workers.dev
    expect(isCspReachable("not-an-allowed-host.example")).toBe(false); // a real miss
    const exempted = new Set<string>([
      ...VENDOR_DOC_HOSTS, ...PROXY_TARGET_HOSTS, ...FEEDBACK_NAV_HOSTS, ...ENRICH_DOC_HOSTS, ...PIVOT_LINK_HOSTS,
    ]);
    const undocumentedOverlap = [...exempted].filter(
      (h) => isCspReachable(h) && !KNOWN_PROVIDER_OVERLAP.has(h),
    );
    expect(undocumentedOverlap).toEqual([]);
  });
});
