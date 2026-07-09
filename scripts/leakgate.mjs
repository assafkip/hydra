#!/usr/bin/env node
// Leak gate (audit findings F1/F2/F4, finding-12). Parses EVERY https?:// origin
// out of src/ and dist/ and fails if any origin is not in the enumerated CSP
// allowlist. This is a general external-origin audit, not a fixed CDN string set:
// a CDN script, a hotlinked font, or any phone-home origin trips it.
// Scar: the Python webapp shipped 8 CDN <script> tags + Google Fonts + a
// favicon-to-Google fetch (docs/17 section 1.3). The CDNs/fonts stay banned —
// enforced. The favicon-to-Google fetch was REINSTATED by founder decision
// 2026-06-24 as the ONE deliberate img-src egress (FAVICON_FETCH_HOSTS, scoped
// to src/graph/favicon.ts); every OTHER off-allowlist origin still trips.
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";

export const ALLOW = new Set([
  "api.anthropic.com",
  "dns.google",
  "cloudflare-dns.com",
  "rdap.org",
  "rdap.verisign.com",
  "crt.sh",
  "mempool.space",
  // PRD-onchain: the four keyless cross-chain RPCs, called DIRECT from the browser (no key, no proxy;
  // verified live 2026-06-18: each returns 200 + access-control-allow-origin:*). FIXED origins like
  // mempool.space — keyless infra, NOT founder infra. Byte-identical with the connect-src in
  // index.html + vercel.json + _headers (tests/csp.test.ts asserts parity).
  "api.trongrid.io",
  "solana-rpc.publicnode.com",
  // restore-tool-belt (2026-06-24): keyless Ethereum RPC for the OFAC wallet sanctions oracle (eth_call to
  // the Chainalysis isSanctioned contract). CORS-open (ACAO:*, verified live 2026-06-24). FIXED keyless
  // origin — not founder infra. Byte-identical with the connect-src in index.html + vercel.json + _headers.
  "ethereum-rpc.publicnode.com",
  "toncenter.com",
  "api.ensideas.com",
  // Chunk-5 enrich: the six CORS-open keyed OSINT providers, called DIRECT from the browser with
  // the user's key (verified live preflight 2026-06-17: query-param providers return ACAO *;
  // Censys/OTX/urlscan echo their custom auth header in access-control-allow-headers). FIXED origins
  // (like api.anthropic.com) — NO per-user/dynamic/wildcard/founder origin. Must stay byte-identical
  // with the connect-src in index.html + vercel.json + _headers (tests/csp.test.ts asserts parity).
  "api.shodan.io",
  "search.censys.io",
  "otx.alienvault.com",
  "api.etherscan.io",
  "urlscan.io",
  "ipinfo.io",
  // A6: Perplexity web-search (the user's Bearer key) — CORS-open, called DIRECT from the browser. A
  // FIXED origin like the others; NOT founder infra. Byte-identical with the connect-src in index.html +
  // vercel.json + _headers (tests/csp.test.ts asserts parity).
  "api.perplexity.ai",
  // restore-tool-belt (2026-06-24): Jina reader — keyed, called DIRECT from the browser with the user's
  // Bearer key. The ACTUAL GET response reflects ACAO (verified live in-browser 2026-06-24), so it is
  // genuinely CORS-open. FIXED origin, not founder infra. Byte-identical with the connect-src in
  // index.html + vercel.json + _headers (tests/csp.test.ts asserts parity).
  "r.jina.ai",
  // hydra-osint-provider-inputs (2026-07-08): Tavily search — keyed, called DIRECT from the browser with
  // the user's Bearer key. Re-tested LIVE 2026-07-08 (Origin hydra): the ACTUAL POST response returns ACAO
  // (they fixed the CORS that once made it proxy-tier), so it is genuinely CORS-open now. FIXED origin, not
  // founder infra. Byte-identical with the connect-src in index.html + vercel.json + _headers.
  "api.tavily.com",
  // Chunk-6 auth: the founder's Supabase project — the ONLY founder-OWNED origin, IDENTITY-ONLY
  // (email + password hash + login metadata; never case data, never the data key). Browser-callable
  // (CORS * + apikey/authorization headers, verified 2026-06-18). Byte-identical with the connect-src
  // in index.html + vercel.json + _headers (tests/csp.test.ts asserts parity).
  "yvermtklysygaeetxcyb.supabase.co",
  // restore-tool-belt (2026-06-24): keyless username_sweep calls these DIRECT from the browser (both
  // verified ACAO:* live, 2026-06-24). FIXED keyless origins — not founder infra, no key. Byte-identical
  // with the connect-src in index.html + vercel.json + _headers (tests/csp.test.ts asserts parity).
  "api.github.com",
  "keybase.io",
  // a56ffd8e (founder 2026-06-25): keyless Gravatar email→profile pivot. The gravatar.com profile JSON is
  // CORS-open — the ACTUAL GET reflects ACAO:* (verified live 2026-06-25), browser-direct, no key. FIXED
  // keyless origin, not founder infra. Byte-identical with the connect-src in index.html + vercel.json +
  // _headers (tests/csp.test.ts asserts parity). Only the profile JSON is fetched; the linked-account URLs
  // it returns are DATA (leads), never fetched here, so no x.com/linkedin/etc. origin is added.
  "gravatar.com",
  // PRD prd-hydra-free-osint-providers finding-1 (2026-07-09): keyless browser-direct infra/IP providers,
  // all re-probed live from the hydra origin 2026-07-09 (ACAO:* on the real GET). FIXED keyless origins,
  // not founder infra. Byte-identical with the connect-src in index.html + vercel.json + _headers
  // (tests/csp.test.ts asserts parity). The routing/scan four are T1; stopforumspam + isc.sans.edu are
  // T3 reputation leads (their adapters register infra:false, so the gate is unaffected).
  "internetdb.shodan.io",
  "stat.ripe.net",
  "ip.guide",
  "ipwho.is",
  "api.stopforumspam.org",
  "isc.sans.edu",
  // PRD prd-hydra-free-osint-providers finding-2 (2026-07-09): keyless cert + on-chain providers, all
  // re-probed live from the hydra origin 2026-07-09 (ACAO:* on the real GET). FIXED keyless origins, not
  // founder infra. Byte-identical with the connect-src in index.html + vercel.json + _headers. certspotter
  // is a 2nd CT source; blockstream.info + api.blockcypher.com are 2nd/3rd BTC sources; eth.blockscout.com
  // is keyless ETH address labels. All T1 (a CT/on-chain record is non-fakeable).
  "api.certspotter.com",
  "blockstream.info",
  "api.blockcypher.com",
  "eth.blockscout.com",
  // PRD prd-hydra-free-osint-providers finding-5 (2026-07-09): keyless identity providers, re-probed live
  // from the hydra origin 2026-07-09. api.github.com is already allowed (username_sweep). These are fixed
  // keyless API origins, not founder infra. Byte-identical with the connect-src in index.html + vercel.json
  // + _headers. T3 identity leads (their adapters register infra:false, so the gate is unaffected).
  "gitlab.com",
  "hacker-news.firebaseio.com",
  "registry.npmjs.org",
  // PRD prd-hydra-free-osint-providers finding-3 (2026-07-09): keyless email/breach providers, re-probed live
  // from the hydra origin 2026-07-09. Fixed keyless API origins, not founder infra. Byte-identical with the
  // connect-src in index.html + vercel.json + _headers. All T3 leads (adapters register infra:false).
  "api.xposedornot.com",
  "haveibeenpwned.com",
  "disposable.debounce.io",
  "open.kickbox.com",
  // PRD prd-hydra-free-osint-providers finding-5 (2026-07-09): keyless corporate + entity-resolution, live-
  // re-probed from the hydra origin 2026-07-09 (Wikidata via the MediaWiki origin=* anonymous-CORS grant).
  // Fixed keyless API origins, not founder infra. Byte-identical with the connect-src in the three CSP files.
  // gleif is T1 registry; wikidata is a T3 lead (infra:false).
  "api.gleif.org",
  "www.wikidata.org",
  // hydra-reverse-ip (founder 2026-07-09): keyless reverse-IP → co-hosted domains, live-probed CORS `*` from
  // the hydra origin 2026-07-09. Fixed keyless API origin, not founder infra. Byte-identical with the
  // connect-src in the three CSP files (tests/csp.test.ts asserts parity). T2 lead (adapter infra:false).
  "api.hackertarget.com",
  // PRD-5b user-proxy: the USER's OWN Cloudflare Worker (their key, their logs-off) — the ONLY new origin
  // this tier adds. A wildcard for the user's platform (each user deploys their own <name>.workers.dev);
  // it is NOT a founder origin, so the nothing-to-the-founder guarantee holds. Byte-identical with the connect-src in
  // index.html + vercel.json + _headers (tests/csp.test.ts asserts parity). The blocked-provider hosts the
  // worker forwards to are NOT here (they are never browser connect-src targets — see PROXY_TARGET_HOSTS).
  "*.workers.dev",
]);

const ROOTS = ["src", "dist"];
const ORIGIN_RE = /https?:\/\/([a-zA-Z0-9.-]+)/g;

// W3C XML namespace URIs are SPEC IDENTIFIERS, not egress origins: document.createElementNS
// requires the literal "http://www.w3.org/2000/svg" to build SVG, and the browser never
// fetches it. They are NOT added to the CSP allowlist (they are not connect-src targets) —
// they are exempted here so the egress audit does not false-positive on the mandatory SVG
// namespace (PRD-7 graph renderer). Any OTHER www.w3.org URL still trips the gate.
const NAMESPACE_URIS = [
  "http://www.w3.org/2000/svg",
  "http://www.w3.org/1999/xhtml",
  "http://www.w3.org/1999/xlink",
  "http://www.w3.org/2000/xmlns/",
];

// Doc-URL string literals baked into BUNDLED vendor code (e.g. Alpine's console-warning
// link; Cytoscape's homepage/error links). They are NOT fetch targets — and even if some
// code tried, the CSP connect-src wall (which does NOT list these) blocks the request at
// runtime, which is the real guarantee. This exemption only suppresses the static
// source-scan false-positive; the egress wall is unchanged. Add a host here only for a
// vendored doc/marketing URL, never for a real origin the app fetches (that belongs in the
// CSP allowlist + ALLOW).
//
// SCOPE (PRD cytoscape-graph D7, codex-7): this exemption applies ONLY to the bundled
// vendor output (the dist/ tree). First-party src/ stays STRICT — a src/ file that names
// one of these hosts still trips the gate, so the exemption can never silence a real
// first-party phone-home just because a vendor happens to mention the same host. The
// dist/-only scoping is proven by tests/leakgate.test.ts.
export const VENDOR_DOC_HOSTS = new Set([
  "alpinejs.dev", // Alpine 3 CSP-warning link string in the bundled runtime
  // The four below are license/attribution/algorithm-reference URL STRINGS baked into the
  // bundled Cytoscape + dagre/graphlib stack (verified via `npm run leakgate` over dist). None
  // is a fetch target; the CSP connect-src wall (which lists none of them) blocks any real
  // request at runtime. dist-only (D7) — a src/ file naming these still trips the gate.
  "engelschall.com", // dagre/graphlib author attribution (Ralf S. Engelschall)
  "jquery.org", // jquery foundation license URL in a transitive dep
  "tldrlegal.com", // MIT-license summary link in a bundled dep
  "en.wikipedia.org", // dagre algorithm reference links (layout citations)
  "opensource.org", // OSI license URL strings in bundled vendor code
  "github.com", // vendor source-repo links baked into bundles
  // mupdf-swap (2026-06-22): pdf.js removed → its XFA/XMP/license string exemptions are gone with it.
  // MuPDF.js is a PARSER + WASM that never fetches; the compiled mupdf-wasm.wasm embeds XML-namespace
  // + color-profile / SVG identifier STRINGS (spec identifiers, exactly like the SVG namespace — MuPDF
  // never fetches them; the CSP connect-src wall, which lists none of them, blocks any runtime request).
  // Enumerated from `npm run leakgate` over dist after the swap. dist-only — a src/ file naming these trips.
  "www.w3.org", // XML/RDF/SVG namespace identifiers baked into the mupdf WASM (NOT the SVG-only src exemption)
  "www.ibm.com", // ICC color-profile vendor string in the mupdf WASM (not a fetch)
  "www.inkscape.org", // SVG metadata namespace identifier in the mupdf WASM (not a fetch)
  "sheetjs.com", // SheetJS (xlsx) author/license attribution string in the bundle (not a fetch)
  "schemas.openxmlformats.org", // OOXML (xlsx) XML namespace identifier in the SheetJS bundle (not a fetch)
  "schemas.microsoft.com", // OOXML/VML XML namespace identifier in the SheetJS bundle (not a fetch)
  "purl.org", // Dublin Core XML namespace identifier in the SheetJS metadata bundle (not a fetch)
  "purl.oclc.org", // OCLC purl XML namespace identifier in the SheetJS bundle (not a fetch)
  "sheetjs.openxmlformats.org", // SheetJS OOXML default-namespace literal (not a fetch)
  // ocr-assets (codex B2/D2): the bundled tesseract.js worker + main JS hard-code this as the DEFAULT
  // core/lang base. It is a DEAD default — src/ingest/ocr.ts OCR_OPTIONS overrides workerPath/corePath/
  // langPath to the same-origin /tesseract/* + workerBlobURL:false, so the runtime NEVER hits it; the
  // live tests/smoke/ocr.spec.ts asserts ZERO request to jsdelivr (the real guarantee). dist-only — a
  // src/ file naming jsdelivr still trips the gate (so a real first-party CDN use can't hide here).
  "cdn.jsdelivr.net", // tesseract.js default core/lang base (overridden + proven unused by ocr-smoke)
  // argon2id (item 5): hash-wasm minifies its license/attribution banner `/*! hash-wasm
  // (https://www.npmjs.com/package/hash-wasm) */` into the bundle. It is a doc-URL STRING, never a fetch
  // target; the CSP connect-src wall (which doesn't list www.npmjs.com) blocks any runtime request. dist-only
  // — a src/ file naming npmjs still trips the gate.
  "www.npmjs.com",
]);

// A path is "vendor scope" (dist output) when it lives under the dist/ tree. Relative ROOT
// paths from walk() keep the "dist/" prefix; the split guards against a "distillery"-style
// false prefix match.
function isVendorScope(file) {
  return file === "dist" || file.startsWith("dist/") || file.split(/[\\/]/).includes("dist");
}

// pb-proxy (PRD-5b): the six CORS-blocked provider hosts named in src/osint/proxy.ts's PROXIED_PROVIDERS
// registry are NOT browser connect-src targets — they are the `?u=` targets the USER's Cloudflare Worker
// fetches (the browser only connects to *.workers.dev). They are NOT in the CSP connect-src; the wall (which
// lists none of them) blocks any direct browser fetch at runtime, which is the real guarantee. This
// exemption is SCOPED to src/osint/proxy.ts ONLY — any OTHER src file naming these hosts still trips the
// gate (so a real first-party phone-home to a provider can never hide here). Proven by tests/leakgate.test.ts.
export const PROXY_TARGET_HOSTS = new Set([
  "www.virustotal.com",
  "api.greynoise.io",
  "api.securitytrails.com",
  "api.abuseipdb.com",
  "pulsedive.com",
  "api.hunter.io",
  // hydra-osint-provider-inputs (2026-07-08): Exa — a POST+JSON worker-fetched ?u= target, NOT a browser
  // connect-src origin (the browser only connects to *.workers.dev). Same guarantee as the six above.
  "api.exa.ai",
  // hydra-see-sites (2026-07-08): the benign target probeWorker asks the user's Worker /render to fetch
  // (Test connection). Reached by the WORKER, never the browser directly — same category as the providers.
  "example.com",
]);
function isProxyRegistry(file) {
  return file.split(/[\\/]/).slice(-2).join("/") === "osint/proxy.ts";
}

// rel-feedback: the user-authored feedback control is an ANCHOR to a github.com new-issue URL — a
// NAVIGATION target the user clicks + reviews + submits THEMSELVES, NOT a browser fetch. github.com is
// NOT in the CSP connect-src, so the wall blocks any direct fetch at runtime (the real guarantee). This
// exemption is SCOPED to src/feedback.ts ONLY (+ its dist bundle); any OTHER src file naming github.com
// still trips the gate (a real phone-home can't hide here). Proven by tests/leakgate.test.ts.
export const FEEDBACK_NAV_HOSTS = new Set(["github.com"]);
function isFeedbackModule(file) {
  return file.split(/[\\/]/).slice(-1)[0] === "feedback.ts";
}

// en-enrich (sf-enrich build): the provider cards render a "docs ↗" ANCHOR per provider to that
// provider's API-docs page — a NAVIGATION target the user clicks, NOT a browser fetch. Most provider
// doc hosts coincide with their already-allowlisted API origin; the two below (Shodan's developer
// portal + Etherscan's docs subdomain) do NOT, so they are exempted here exactly like the feedback
// github.com anchor. They are NOT in the CSP connect-src, so the wall blocks any direct fetch at
// runtime (the real guarantee). SCOPED to src/osint/enrich.ts ONLY (+ its dist bundle); any OTHER src
// file naming these still trips the gate. Proven by tests/leakgate.test.ts.
export const ENRICH_DOC_HOSTS = new Set([
  "developer.shodan.io", "docs.etherscan.io", "docs.perplexity.ai", "jina.ai", "docs.tavily.com",
  // founder 2026-07-09: the KEY_GUIDANCE "Get a key ↗" token-CREATION pages (enrich.ts). Navigation
  // anchors the user opens themselves, NOT browser fetches — not in the CSP connect-src, so the wall
  // blocks any runtime request. Hosts whose API origin is already allowlisted (censys/otx/gitlab/urlscan/
  // ipinfo) need no entry; these five are the token pages that live on a different host.
  "account.shodan.io", "etherscan.io", "github.com", "www.perplexity.ai", "app.tavily.com",
  // finding-5: the github/gitlab identity providers' docs↗ anchor hosts (their API docs live on a docs.*
  // subdomain, not the allowlisted api.github.com / gitlab.com fetch origin). Navigation, not a fetch.
  "docs.github.com", "docs.gitlab.com",
]);
function isEnrichRegistry(file) {
  return file.split(/[\\/]/).slice(-2).join("/") === "osint/enrich.ts";
}

// finding-5 (identity providers): the keyless identity adapters emit `account`/`url` entity VALUES that are
// navigation LEADS the analyst clicks (a linked Twitter, the HN profile URL, an npm package page), NOT
// browser fetches. Each adapter fetches ONLY its allowlisted API origin (api.github.com / gitlab.com /
// hacker-news.firebaseio.com / registry.npmjs.org); these lead hosts are NOT in the CSP connect-src, so the
// wall blocks any direct fetch at runtime (the real guarantee). SCOPED to the identity adapter files ONLY
// (+ their dist bundle); any OTHER src file naming these still trips the gate. Same category as the
// pivots.ts PIVOT_LINK_HOSTS / feedback.ts github.com anchor.
export const IDENTITY_LEAD_HOSTS = new Set(["twitter.com", "news.ycombinator.com", "www.npmjs.com"]);
function isIdentityModule(file) {
  const base = file.split(/[\\/]/).slice(-1)[0];
  return base === "github-user.ts" || base === "hackernews-user.ts" || base === "npm-user.ts";
}

// pivot-links (sp-f9d3c9ff→goal2 leakgate validation 2026-06-23): src/osint/pivots.ts renders OSINT
// pivot LINKS — `<a>`/new-tab URLs the analyst CLICKS to run a manual lookup, NOT browser fetches (the
// file builds `PivotLink.url` hrefs; a grep over src/ finds zero `fetch(...securitytrails|hackertarget|
// icann)`). The three below are pivot-link hosts that are NOT the provider's already-allowlisted API
// origin (the bare site `securitytrails.com`, not the proxied `api.securitytrails.com`; hackertarget.com;
// lookup.icann.org). They are NOT in the CSP connect-src, so the wall blocks any direct browser fetch at
// runtime (the real guarantee — zero user data egresses to them). SCOPED to src/osint/pivots.ts ONLY (+ its
// dist bundle); any OTHER src file naming these still trips the gate. Proven by tests/leakgate.test.ts.
// The full host inventory of src/osint/pivots.ts (a verbatim port of analyze.py PIVOT_TEMPLATES). Its
// file header is explicit: "these are LINKS the analyst opens in a new tab, not fetches" — and the
// module contains ZERO fetch/XHR/WebSocket (asserted by tests/leakgate.test.ts). The hosts here are NOT
// the provider's already-allowlisted API origin (bare `etherscan.io`/`www.shodan.io`/`www.virustotal.com`
// — the human-facing site, not the `api.*` the enrich adapters fetch). Adding a pivot without listing its
// host here fails the leakgate test (NOT silently the gate) — tests/leakgate.test.ts asserts every external
// host in pivots.ts is in this set. SCOPED to src/osint/pivots.ts (+ its dist bundle); any OTHER src file
// naming these still trips.
export const PIVOT_LINK_HOSTS = new Set([
  "www.shodan.io", "www.virustotal.com", "www.abuseipdb.com", "securitytrails.com", "hackertarget.com",
  "dnsdumpster.com", "dnslytics.com", "lookup.icann.org", "builtwith.com", "publicwww.com",
  "etherscan.io", "blockchair.com", "platform.arkhamintelligence.com", "www.chainabuse.com",
  "cloud.walletconnect.com", "t.me", "tgstat.com", "x.com", "www.google.com", "haveibeenpwned.com",
  "hunter.io", "www.truecaller.com",
]);
function isPivotModule(file) {
  return file.split(/[\\/]/).slice(-2).join("/") === "osint/pivots.ts";
}

// favicon (founder decision 2026-06-24, reversing the F3/D12 drop): src/graph/favicon.ts builds the Google
// s2 favicon URL for a domain-node face. UNLIKE the navigation/proxy exemptions above, this IS a REAL
// browser→Google img-src egress (the founder chose direct fetch over the Worker-proxy tier, knowing the
// case domain is exposed to Google for the icon — no case content/key/finding leaves). It is therefore in
// the CSP IMG-SRC allow (t0.gstatic.com, Google's static CDN — the faviconV2 host, hit directly to avoid the
// www.google.com/s2 301-redirect), NOT connect-src — so the csp.test connect-src===ALLOW parity is unaffected.
// SCOPED to src/graph/favicon.ts ONLY (+ its dist bundle); any OTHER src file naming this host still trips
// the gate (a real connect-src phone-home to Google can't hide here). Proven by tests/leakgate.test.ts.
export const FAVICON_FETCH_HOSTS = new Set(["t0.gstatic.com"]);
function isFaviconModule(file) {
  return file.split(/[\\/]/).slice(-2).join("/") === "graph/favicon.ts";
}

// Pure, testable: every off-allowlist external origin in `text` for `file`, applying the
// namespace and (dist-scoped) vendor-doc exemptions. Used by both the CLI and the
// negative self-test in tests/leakgate.test.ts.
export function findOffenders(file, text) {
  const offenders = [];
  const vendor = isVendorScope(file);
  // A URL inside a FULL-LINE `//` comment is never an egress (a comment doesn't run) — strip lines that
  // START with `//` (after indentation) for SRC files, so a commented example URL (e.g. record.ts's
  // `'https://x.com"'` URL_RE example) is not a false positive. ONLY full-line comments: an inline `//`
  // (e.g. `const m = "//"; fetch("https://evil.com")`) must NOT strip the rest of the line and hide a real
  // origin (codex). NOT for dist: the minified bundle can carry `//` inside a string literal. A real fetch
  // is never on a `//`-starting line, so the src scan still catches it.
  const scanned = vendor ? text : text.replace(/^[ \t]*\/\/[^\n]*/gm, "");
  const re = new RegExp(ORIGIN_RE.source, "g");
  let m;
  while ((m = re.exec(scanned)) !== null) {
    const host = m[1].toLowerCase().replace(/\.$/, "");
    if (host === "www.w3.org" && NAMESPACE_URIS.some((ns) => scanned.startsWith(ns, m.index))) continue;
    if (vendor && VENDOR_DOC_HOSTS.has(host)) continue; // dist-only benign vendored doc-URL (D7)
    if ((isProxyRegistry(file) || vendor) && PROXY_TARGET_HOSTS.has(host)) continue; // pb-proxy: worker-fetched ?u= target, not connect-src (proxy.ts src + its dist bundle; any OTHER src file naming them still trips)
    if ((isFeedbackModule(file) || vendor) && FEEDBACK_NAV_HOSTS.has(host)) continue; // rel-feedback: a github.com anchor (navigation), not a fetch origin (feedback.ts src + its dist bundle; any OTHER src file naming it still trips)
    if ((isEnrichRegistry(file) || vendor) && ENRICH_DOC_HOSTS.has(host)) continue; // en-enrich: a provider docs↗ anchor (navigation), not a fetch origin (enrich.ts src + its dist bundle; any OTHER src file naming it still trips)
    if ((isPivotModule(file) || vendor) && PIVOT_LINK_HOSTS.has(host)) continue; // pivot-links: an osint pivot <a> href (navigation), not a fetch origin (pivots.ts src + its dist bundle; any OTHER src file naming them still trips)
    if ((isFaviconModule(file) || vendor) && FAVICON_FETCH_HOSTS.has(host)) continue; // favicon: a REAL img-src egress to Google (founder decision 2026-06-24), in CSP img-src not connect-src (favicon.ts src + its dist bundle; any OTHER src file naming it still trips)
    if ((isIdentityModule(file) || vendor) && IDENTITY_LEAD_HOSTS.has(host)) continue; // finding-5: an identity lead value (linked Twitter / HN profile / npm package href — navigation), not a fetch origin (identity adapter src + their dist bundle; any OTHER src file naming them still trips)
    if (!ALLOW.has(host)) offenders.push(`${file}: ${m[0]}`);
  }
  return offenders;
}

function walk(dir, out) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, out);
    else scan(p, out);
  }
}

function scan(file, out) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return; // binary / unreadable asset: no text origins to leak
  }
  for (const o of findOffenders(file, text)) out.push(o);
}

// CLI entry: only when run directly (not when imported by the test).
if (import.meta.url === `file://${process.argv[1]}`) {
  const offenders = [];
  for (const root of ROOTS) {
    if (existsSync(root)) walk(root, offenders);
  }
  if (offenders.length > 0) {
    console.error("LEAK GATE FAILED: external origin(s) not in the CSP allowlist:");
    for (const o of offenders) console.error("  " + o);
    console.error(`\nAllowlist: ${[...ALLOW].join(", ")}`);
    process.exit(1);
  }
  console.log(`leak gate OK: scanned ${ROOTS.filter(existsSync).join(", ")}, no off-allowlist origin.`);
}
