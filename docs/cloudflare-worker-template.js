/**
 * kipi-web — user-owned OSINT proxy (PRD-5b, docs/17 §3.2)
 * =========================================================
 *
 * The SIX keyed OSINT providers below have NO browser CORS, so the 100%-client kipi-web app cannot call
 * them directly. This ~100-line Cloudflare Worker is the bridge: YOU deploy it to YOUR Cloudflare account,
 * it holds YOUR provider keys as Worker secrets (never in the browser), it forwards a request to the
 * provider, and it returns the response with CORS so your browser can read it. The founder is NEVER in the
 * path — the proxy is entirely yours, with logging OFF.
 *
 * ── HOW TO DEPLOY (the one human step) ─────────────────────────────────────────────────────────────────
 * 1. Cloudflare dashboard → Workers & Pages → Create → Worker. Name it anything (e.g. "kipi-proxy").
 * 2. Paste THIS file as the Worker code. Deploy. Your URL is https://<name>.<subdomain>.workers.dev .
 * 3. Settings → Variables and Secrets → add ONLY the secrets for the providers you have keys for:
 *      VT_KEY (VirusTotal) · GREYNOISE_KEY · SECURITYTRAILS_KEY · ABUSEIPDB_KEY · PULSEDIVE_KEY · HUNTER_KEY
 *      · EXA_KEY (Exa — a POST+JSON search provider; the Worker forwards the body)
 *    (A provider with no secret here simply stays unavailable — nothing breaks.)
 * 4. In kipi-web → Enrich → "User proxy", paste your https://<name>.workers.dev URL and Save.
 *
 * ── WHY IT IS SAFE ─────────────────────────────────────────────────────────────────────────────────────
 * - It is NOT an open proxy: it forwards ONLY to the fixed PROVIDERS allowlist below (a `?u=` to any other
 *   host is rejected 403). No SSRF to internal/arbitrary targets.
 * - Your provider keys live ONLY in this Worker's secrets — they are added server-side and NEVER returned
 *   to the browser.
 * - CORS is opened only so your kipi-web tab can read the result; no logging is emitted.
 */

// host → how to attach YOUR key (from the Worker's env secrets). A provider whose secret is unset is skipped.
const PROVIDERS = {
  "www.virustotal.com": { secret: "VT_KEY", header: "x-apikey" },
  "api.greynoise.io": { secret: "GREYNOISE_KEY", header: "key" },
  "api.securitytrails.com": { secret: "SECURITYTRAILS_KEY", header: "APIKEY" },
  "api.abuseipdb.com": { secret: "ABUSEIPDB_KEY", header: "Key" },
  "pulsedive.com": { secret: "PULSEDIVE_KEY", query: "key" },
  "api.hunter.io": { secret: "HUNTER_KEY", query: "api_key" },
  // Exa is a POST+JSON search API: `post:true` tells the forwarder to pass the request body through.
  "api.exa.ai": { secret: "EXA_KEY", header: "x-api-key", post: true },
};

// hydra-see-sites (2026-07-08): KEYLESS page-fetch allowlist for the /page endpoint. These are pages hydra's
// link-resolver reads server-side to pull a destination link the browser can't fetch directly (the source
// sets no CORS). NO key is attached — it is a plain GET. Closed allowlist = never an open proxy. Add a host
// here to let hydra resolve links on it (a bare hostname; www. and other subdomains are matched by suffix).
const PAGE_HOSTS = ["pinterest.com", "www.pinterest.com"];
function isAllowedPageHost(hostname) {
  const h = (hostname || "").toLowerCase();
  return PAGE_HOSTS.some((p) => h === p || h.endsWith(`.${p}`));
}

function cors(resp) {
  const h = new Headers(resp.headers);
  h.set("access-control-allow-origin", "*");
  h.set("access-control-allow-headers", "*");
  h.delete("set-cookie");
  return new Response(resp.body, { status: resp.status, headers: h });
}

// ── /render — headless page forensics (PRD-B agent-browser-forensics) ─────────────────────────────────
// EXTRA DEPLOY STEP (only if you want the agent's browser tools): enable Cloudflare Browser Rendering and
// add a browser binding to the Worker. In the dashboard: Workers → your worker → Settings → Bindings →
// add a "Browser Rendering" binding named BROWSER. (Or in wrangler.toml: `browser = { binding = "BROWSER" }`
// and `compatibility_flags = ["nodejs_compat"]`, then `npm i @cloudflare/puppeteer`.) With no BROWSER
// binding this endpoint returns 501 and the client's browser tools simply stay unavailable — nothing else
// breaks. Like the rest of the proxy, the founder is NEVER in the path; this runs on YOUR account.
// SSRF guard: /render must NOT be a window into the user's private network or the cloud metadata endpoint.
// Block loopback / private / link-local / CGNAT / multicast / reserved hosts — on the INITIAL url, on every
// sub-request the page makes, and on the final (post-redirect) url (codex issue-5 C3).
function isBlockedHost(hostname) {
  const h = (hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!h || h === "localhost" || h.endsWith(".localhost") || h.endsWith(".internal") || h.endsWith(".local")) return true;
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0 || a >= 224) return true; // loopback / private / "this host" / multicast+reserved
    if (a === 169 && b === 254) return true; // link-local + cloud metadata 169.254.169.254
    if (a === 192 && b === 168) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  if (h === "::1" || h.startsWith("fe80:") || h.startsWith("fc") || h.startsWith("fd")) return true; // IPv6 loopback/link-local/ULA
  return false;
}

async function renderPage(request, env) {
  const reqUrl = new URL(request.url);
  // OPTIONAL hardening: if you set a RENDER_TOKEN secret on the Worker, /render requires ?t=<token> — so a
  // leaked Worker URL alone cannot drive your browser. With no RENDER_TOKEN set this check is skipped.
  if (env.RENDER_TOKEN && reqUrl.searchParams.get("t") !== env.RENDER_TOKEN) {
    return new Response(JSON.stringify({ error: "render token required" }), { status: 401 });
  }
  const u = reqUrl.searchParams.get("u");
  if (!u) return new Response(JSON.stringify({ error: "missing ?u=<page url>" }), { status: 400 });
  let target;
  try {
    target = new URL(u);
  } catch {
    return new Response(JSON.stringify({ error: "bad target url" }), { status: 400 });
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    return new Response(JSON.stringify({ error: "only http(s) targets" }), { status: 400 });
  }
  if (isBlockedHost(target.hostname)) {
    return new Response(JSON.stringify({ error: "target host is not permitted (private/reserved)" }), { status: 403 });
  }
  if (!env.BROWSER) {
    return new Response(JSON.stringify({ error: "Browser Rendering not enabled — add a BROWSER binding to use /render" }), { status: 501 });
  }
  // Lazy import so the Worker still deploys (for the provider proxy) without @cloudflare/puppeteer installed.
  const puppeteer = (await import("@cloudflare/puppeteer")).default;
  let browser;
  try {
    browser = await puppeteer.launch(env.BROWSER);
    const page = await browser.newPage();
    const networkRequests = [];
    // intercept every sub-request: record it, but ABORT any that targets a private/internal host (SSRF guard).
    await page.setRequestInterception(true);
    page.on("request", (req) => {
      let host = "";
      try {
        host = new URL(req.url()).hostname;
      } catch {
        /* malformed */
      }
      networkRequests.push(req.url());
      if (isBlockedHost(host)) req.abort();
      else req.continue();
    });
    const resp = await page.goto(target.toString(), { waitUntil: "networkidle0", timeout: 30000 });
    // a redirect could land on an internal host — reject the result if the final URL is blocked.
    try {
      if (isBlockedHost(new URL(page.url()).hostname)) {
        return new Response(JSON.stringify({ error: "redirected to a non-permitted host" }), { status: 403 });
      }
    } catch {
      /* keep going on an unparseable final url */
    }
    const html = await page.content();
    const text = await page.evaluate(() => document.body ? document.body.innerText : "");
    const finalUrl = page.url();
    const status = resp ? resp.status() : 0;
    return new Response(
      JSON.stringify({
        status,
        finalUrl,
        html: html.slice(0, 200000), // bound the payload
        text: text.slice(0, 100000),
        networkRequests: networkRequests.slice(0, 500),
      }),
      { headers: { "content-type": "application/json" } },
    );
  } catch (e) {
    return new Response(JSON.stringify({ error: `render failed: ${String(e).slice(0, 200)}` }), { status: 502 });
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        /* best effort */
      }
    }
  }
}

// ── /page — keyless server-side page fetch (hydra-see-sites) ──────────────────────────────────────────
// Plain-GET an ALLOWLISTED page (PAGE_HOSTS) and return its server HTML, so hydra's link-resolver can read a
// destination link that lives in the initial HTML (a Pinterest pin's "link" field) but is CORS-walled from the
// browser. No key, no Browser Rendering — just a fetch. Closed allowlist + the same private/reserved-host
// SSRF guard /render uses (defense-in-depth against a redirect to an internal host).
async function fetchPage(request) {
  const u = new URL(request.url).searchParams.get("u");
  if (!u) return new Response(JSON.stringify({ error: "missing ?u=<page url>" }), { status: 400 });
  let target;
  try {
    target = new URL(u);
  } catch {
    return new Response(JSON.stringify({ error: "bad target url" }), { status: 400 });
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    return new Response(JSON.stringify({ error: "only http(s) targets" }), { status: 400 });
  }
  if (!isAllowedPageHost(target.hostname) || isBlockedHost(target.hostname)) {
    return new Response(JSON.stringify({ error: "target host is not on the page allowlist" }), { status: 403 });
  }
  let resp;
  try {
    resp = await fetch(target.toString(), {
      headers: { "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36", accept: "text/html" },
      redirect: "follow",
      cf: { cacheTtl: 0 },
    });
  } catch {
    return new Response(JSON.stringify({ error: "upstream fetch failed" }), { status: 502 });
  }
  // a redirect could land on an internal host — reject if the final URL is blocked.
  try {
    if (isBlockedHost(new URL(resp.url || target.toString()).hostname)) {
      return new Response(JSON.stringify({ error: "redirected to a non-permitted host" }), { status: 403 });
    }
  } catch {
    /* keep going on an unparseable final url */
  }
  const text = (await resp.text()).slice(0, 1500000); // bound the payload
  return new Response(JSON.stringify({ status: resp.status, finalUrl: resp.url || target.toString(), text }), {
    headers: { "content-type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
    // GET reaches the six original providers + /render; POST reaches the POST+JSON providers (Exa).
    if (request.method !== "GET" && request.method !== "POST") return new Response("method not allowed", { status: 405 });

    // PRD-B agent-browser-forensics: the /render endpoint. kipi-web's browser tools (page_navigate /
    // network_requests / evaluate_script) call this to reach a JS scam page's payout wallet / script.js /
    // kit fingerprint — impossible from a 100%-client app (no headless browser in the browser). It uses
    // Cloudflare BROWSER RENDERING (the user adds a `browser` binding — see the deploy note below).
    if (new URL(request.url).pathname === "/render") return cors(await renderPage(request, env));

    // hydra-see-sites: keyless server-side page fetch (GET only) for the link-resolver — no key, no render.
    if (new URL(request.url).pathname === "/page") {
      if (request.method !== "GET") return new Response("method not allowed", { status: 405 });
      return cors(await fetchPage(request));
    }

    const u = new URL(request.url).searchParams.get("u");
    if (!u) return new Response("missing ?u=<provider api url>", { status: 400 });

    let target;
    try {
      target = new URL(u);
    } catch {
      return new Response("bad target url", { status: 400 });
    }
    // closed allowlist — never an open proxy (SSRF guard)
    if (target.protocol !== "https:" || !Object.prototype.hasOwnProperty.call(PROVIDERS, target.hostname)) {
      return new Response("target host not allowed", { status: 403 });
    }

    const spec = PROVIDERS[target.hostname];
    // A POST provider must be reached with POST (and vice-versa) — never let a GET drive a POST endpoint or leak a body path.
    const wantsPost = !!spec.post;
    if (wantsPost !== (request.method === "POST")) return new Response("method not allowed for this provider", { status: 405 });

    const key = env[spec.secret];
    if (!key) return new Response(`no key configured for ${target.hostname}`, { status: 502 });

    const headers = new Headers({ accept: "application/json" });
    if (spec.header) headers.set(spec.header, key); // header-auth providers
    if (spec.query) target.searchParams.set(spec.query, key); // query-auth providers

    const init = { headers, cf: { cacheTtl: 0 } };
    if (wantsPost) {
      // Forward the client's JSON body to the provider (the query/params are in the body, not the URL).
      headers.set("content-type", "application/json");
      init.method = "POST";
      init.body = await request.text();
    }

    let upstream;
    try {
      upstream = await fetch(target.toString(), init);
    } catch {
      return new Response("upstream fetch failed", { status: 502 });
    }
    return cors(upstream);
  },
};
