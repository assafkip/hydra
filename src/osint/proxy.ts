// pb-proxy (docs/17 Tier-2): the USER-owned Cloudflare-Worker proxy for the CORS-blocked providers. The
// user deploys their OWN worker (docs/cloudflare-worker-template.js) that holds THEIR provider keys as
// worker secrets and forwards the request. The client stores ONLY the worker URL + sends NO provider key
// (codex D3). The founder is NEVER in the path; *.workers.dev is the user's own platform (codex D7).
import { type OsintEntity, type OsintOpts, type OsintResult, MAX_ENRICH_RESULTS, uniqueBy, withRetry } from "./types.js";
import type { TargetKind } from "./enrich.js";
import { validateTarget } from "../agent/tools.js";

/**
 * Accept ONLY a https://<sub>.workers.dev URL at the root (no query/hash/credentials/path) — codex D1.
 * Rejects a suffix attack (x.workers.dev.evil.com), non-https, javascript:, and a path/query-injected URL.
 */
export function isValidWorkerUrl(url: string): boolean {
  let u: URL;
  try {
    u = new URL((url ?? "").trim());
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  if (u.username || u.password) return false; // no userinfo
  if (u.search || u.hash) return false; // no query/hash injection
  if (u.pathname !== "/" && u.pathname !== "") return false; // root only
  const h = u.hostname;
  if (h === "workers.dev") return false; // a subdomain is required
  return /^[a-z0-9-]+(\.[a-z0-9-]+)*\.workers\.dev$/.test(h);
}

/** Call the user's worker with the provider target encoded in ?u= — the worker adds its env key + forwards.
 *  The client request carries NO provider key (codex D3). The target is a FIXED registry URL (not user
 *  input), so the worker is never an open proxy (codex D2). */
export async function proxyFetch(workerUrl: string, targetUrl: string, opts: OsintOpts = {}): Promise<unknown> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${workerUrl}?u=${encodeURIComponent(targetUrl)}`;
  return withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`Proxy HTTP ${res.status}`); // NEVER echo the worker url / a key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

/** POST variant (hydra-osint-provider-inputs 2026-07-08): some blocked providers (Exa) are POST+JSON search
 *  APIs, so the worker must forward a BODY. Same contract as proxyFetch — target in ?u= (a FIXED registry
 *  URL, never an open proxy), NO provider key in the client request (the worker attaches its env key), the
 *  worker url / key are never echoed in an error. The worker's POST branch forwards this JSON body upstream. */
export async function proxyPost(workerUrl: string, targetUrl: string, body: unknown, opts: OsintOpts = {}): Promise<unknown> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${workerUrl}?u=${encodeURIComponent(targetUrl)}`;
  return withRetry(
    async () => {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify(body ?? {}),
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`Proxy HTTP ${res.status}`); // NEVER echo the worker url / a key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

/** PRD-B agent-browser-forensics: the EVALUATED page a Worker render returned — the JS-rendered DOM text +
 *  the network requests the page made. The only way to reach a JS scam page's payout wallet / script.js /
 *  kit fingerprint from a 100%-client app (no headless browser in the browser). */
export interface RenderedPage {
  url: string;
  status: number;
  finalUrl: string;
  text: string; // the evaluated visible text (DOM after JS)
  html: string; // the evaluated DOM html
  networkRequests: string[]; // the URLs the page requested (network forensics)
}

/** Render a JS page through the user's Worker (Cloudflare Browser Rendering). The Worker navigates the URL
 *  headlessly and returns the evaluated DOM + the network requests — see docs/cloudflare-worker-template.js
 *  `/render`. The client sends NO key; the Worker is the user's own (founder decision 2026-06-23). The
 *  target is a real http(s) URL (the SSRF guard lives in the Worker's allowlist + the user owns it). */
export async function renderViaProxy(workerUrl: string, targetUrl: string, opts: OsintOpts = {}): Promise<RenderedPage> {
  if (!isValidWorkerUrl(workerUrl)) throw new Error("invalid worker url");
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    throw new Error("bad target url");
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("only http(s) targets render");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = workerUrl.replace(/\/+$/, "");
  const url = `${base}/render?u=${encodeURIComponent(target.toString())}`;
  return withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`Render HTTP ${res.status}`); // NEVER echo the worker url
      const j = (await res.json()) as Record<string, unknown>;
      return {
        url: targetUrl,
        status: typeof j.status === "number" ? j.status : 0,
        finalUrl: typeof j.finalUrl === "string" ? j.finalUrl : targetUrl,
        text: typeof j.text === "string" ? j.text : "",
        html: typeof j.html === "string" ? j.html : "",
        networkRequests: Array.isArray(j.networkRequests) ? j.networkRequests.filter((u): u is string => typeof u === "string") : [],
      };
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

/** hydra-see-sites (2026-07-08): a Worker connectivity probe for the "Test connection" button.
 *  - "unset": no valid workers.dev URL saved.
 *  - "unreachable": the URL is set but the Worker didn't answer (not deployed / wrong name / network).
 *  - "proxy-only": the Worker answered but Browser Rendering is OFF (a /render probe returns 501). The keyed
 *    providers + the keyless /page link-resolver work; page_navigate/network_requests/evaluate_script do not.
 *  - "render-ready": /render rendered — the full browser-forensics toolkit works. */
export type WorkerProbe = "unset" | "unreachable" | "proxy-only" | "render-ready";

/** Probe the user's Worker by asking /render to fetch a benign URL. 501 = reachable but Browser Rendering
 *  off (proxy-only); a render = render-ready; a thrown/failed connection = unreachable. The worker url is
 *  never echoed. A "render-ready" result costs ONE tiny render on the user's own account (a deliberate test). */
export async function probeWorker(workerUrl: string, opts: OsintOpts = {}): Promise<WorkerProbe> {
  if (!isValidWorkerUrl(workerUrl)) return "unset";
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = workerUrl.replace(/\/+$/, "");
  try {
    const res = await fetchImpl(`${base}/render?u=${encodeURIComponent("https://example.com/")}`, { headers: { accept: "application/json" }, signal: opts.signal });
    if (res.status === 501) return "proxy-only"; // Worker answered; Browser Rendering not enabled
    if (res.ok) return "render-ready"; // /render returned a rendered page
    return "proxy-only"; // any other status still means the Worker answered (reachable)
  } catch {
    return "unreachable"; // no answer — not deployed, wrong URL, or blocked
  }
}

/** hydra-see-sites (2026-07-08): a page a Worker plain-GET returned (no headless render, no JS). Enough to
 *  read a destination link that lives in the initial server HTML (a Pinterest pin's `"link"` field), which a
 *  100%-client app can't fetch directly because the source (pinterest.com) sets no CORS. Lighter than
 *  renderViaProxy — the Worker's keyless /page branch needs NO Browser Rendering binding. */
export interface FetchedPage {
  url: string;
  status: number;
  finalUrl: string;
  text: string; // the raw response text (server HTML), bounded by the Worker
}

/** Plain-GET a page through the user's Worker /page endpoint (a keyless, allowlisted host — see the Worker
 *  template's PAGE_HOSTS). Returns the server HTML text; the client parses it (linkresolve). The client sends
 *  NO key; the Worker is the user's own. The target is a real http(s) URL; the SSRF allowlist lives in the
 *  Worker (PAGE_HOSTS) and the user owns it. The worker url is never echoed in an error. */
export async function resolvePageViaProxy(workerUrl: string, targetUrl: string, opts: OsintOpts = {}): Promise<FetchedPage> {
  if (!isValidWorkerUrl(workerUrl)) throw new Error("invalid worker url");
  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    throw new Error("bad target url");
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("only http(s) targets");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const base = workerUrl.replace(/\/+$/, "");
  const url = `${base}/page?u=${encodeURIComponent(target.toString())}`;
  return withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`Page fetch HTTP ${res.status}`); // NEVER echo the worker url
      const j = (await res.json()) as Record<string, unknown>;
      return {
        url: targetUrl,
        status: typeof j.status === "number" ? j.status : 0,
        finalUrl: typeof j.finalUrl === "string" ? j.finalUrl : targetUrl,
        text: typeof j.text === "string" ? j.text : "",
      };
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

export interface ProxiedProvider {
  id: string;
  label: string;
  targets: TargetKind[];
  apiUrl(target: string): string;
  parse(json: unknown, query: string): OsintEntity[]; // query = the looked-up target (SecurityTrails needs it to qualify labels)
  /** HTTP method the worker uses to reach the provider. Omitted = "GET" (the six original providers).
   *  "POST" providers (Exa) also supply body() — the JSON payload the worker forwards upstream. */
  method?: "GET" | "POST";
  /** The JSON request body for a POST provider (the search query etc.). Ignored for GET providers. */
  body?(target: string): unknown;
}

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" ? (v as Record<string, unknown>) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** The six CORS-blocked providers, reachable ONLY through the user's worker. VirusTotal is fully wired +
 *  tested; the others carry a real request URL + a defensive parse (refined as users exercise them). */
export const PROXIED_PROVIDERS: ProxiedProvider[] = [
  {
    id: "virustotal",
    label: "VirusTotal",
    targets: ["domain", "ip"],
    apiUrl: (t) => `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(t)}`,
    parse: (json) => {
      const recs = arr(obj(obj(obj(json).data).attributes).last_dns_records);
      const out: OsintEntity[] = [];
      for (const r of recs.slice(0, MAX_ENRICH_RESULTS)) {
        const rr = obj(r);
        const value = str(rr.value);
        if (str(rr.type) === "A" && IPV4_RE.test(value)) out.push({ type: "ip", value, note: "VirusTotal passive DNS" });
      }
      return out;
    },
  },
  {
    id: "greynoise",
    label: "GreyNoise",
    targets: ["ip"],
    apiUrl: (t) => `https://api.greynoise.io/v3/community/${encodeURIComponent(t)}`,
    parse: (json) => {
      const ip = str(obj(json).ip);
      return IPV4_RE.test(ip) ? [{ type: "ip", value: ip, note: `GreyNoise: ${str(obj(json).classification) || "seen"}` }] : [];
    },
  },
  {
    id: "securitytrails",
    label: "SecurityTrails",
    targets: ["domain"],
    apiUrl: (t) => `https://api.securitytrails.com/v1/domain/${encodeURIComponent(t)}/subdomains`,
    parse: (json, query) => {
      // SecurityTrails returns bare LABELS ("api", "www") to PREPEND to the queried domain — codex issue-5 C4:
      // emit the FULL subdomain (api.example.com), not the dangling label.
      const base = (query || "").trim().toLowerCase();
      const subs = arr(obj(json).subdomains);
      return subs
        .slice(0, MAX_ENRICH_RESULTS)
        .map((s) => str(s).trim().toLowerCase())
        .filter(Boolean)
        .map((label) => (base && !label.endsWith(base) ? `${label}.${base}` : label))
        .map((value) => ({ type: "subdomain" as const, value, note: "SecurityTrails subdomain" }));
    },
  },
  {
    id: "abuseipdb",
    label: "AbuseIPDB",
    targets: ["ip"],
    apiUrl: (t) => `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(t)}`,
    parse: (json) => {
      const ip = str(obj(obj(json).data).ipAddress);
      return IPV4_RE.test(ip) ? [{ type: "ip", value: ip, note: "AbuseIPDB report" }] : [];
    },
  },
  {
    id: "pulsedive",
    label: "Pulsedive",
    targets: ["ip", "domain"],
    apiUrl: (t) => `https://pulsedive.com/api/info.php?indicator=${encodeURIComponent(t)}`,
    parse: (json) => {
      const indicator = str(obj(json).indicator);
      const type = str(obj(json).type);
      if (!indicator) return [];
      if (type === "ip" && IPV4_RE.test(indicator)) return [{ type: "ip", value: indicator, note: "Pulsedive" }];
      if (type === "domain") return [{ type: "domain", value: indicator.toLowerCase(), note: "Pulsedive" }];
      return [];
    },
  },
  {
    id: "hunter",
    label: "Hunter.io",
    targets: ["domain"],
    apiUrl: (t) => `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(t)}`,
    // Hunter returns EMAILS, which are not yet a first-class OsintEntity type (EntityType has no 'email';
    // widening it is a separate types.ts change). The provider is WIRED end-to-end (request goes through
    // the worker); the email -> entity mapping lands when EntityType gains 'email'. Documented stub.
    parse: () => [],
  },
  {
    // hydra-osint-provider-inputs (2026-07-08): Exa neural/semantic search. CORS-BLOCKED (live-verified — its
    // preflight returns NO access-control-allow-origin), so it routes through the user's worker like the six
    // above. UNLIKE them it is POST+JSON, so it carries method:"POST" + body() — the worker's POST branch
    // forwards the body. The target is a free-text QUERY; a search summary is T2-lead-grade (the domains/URLs
    // it names are LEADS a T1 infra tool must confirm), matching the direct search adapters' discipline.
    id: "exa",
    label: "Exa",
    targets: ["query"],
    method: "POST",
    apiUrl: () => "https://api.exa.ai/search",
    body: (t) => ({ query: t, numResults: 10, type: "auto" }),
    parse: (json) => {
      const results = arr(obj(json).results);
      const out: OsintEntity[] = [];
      const seen = new Set<string>();
      for (const r of results.slice(0, MAX_ENRICH_RESULTS)) {
        const u = str(obj(r).url);
        if (!u) continue;
        let host = "";
        try {
          host = new URL(u).hostname.toLowerCase().replace(/^www\./, "");
        } catch {
          continue;
        }
        const k = `domain:${host}`;
        if (host && !seen.has(k)) { seen.add(k); out.push({ type: "domain", value: host, note: "Exa search (lead — confirm with an infra tool)" }); }
      }
      return out;
    },
  },
];

export function proxiedProvider(id: string): ProxiedProvider | undefined {
  return PROXIED_PROVIDERS.find((p) => p.id === id);
}

/** Run ONE proxied provider: validate the target kind (codex D5), proxy the FIXED provider URL through
 *  the worker, parse -> typed entities (tier T2). Throws on an unknown provider / invalid worker / wrong
 *  target. The caller (enrichViaProxy) gates the entities exactly like a direct enrich. */
export async function runProxiedProvider(id: string, target: string, workerUrl: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const p = proxiedProvider(id);
  if (!p) throw new Error(`unknown proxied provider "${id}"`);
  if (!isValidWorkerUrl(workerUrl)) throw new Error("invalid worker url");
  const t = target.trim();
  if (!p.targets.some((k) => validateTarget(k, t))) throw new Error(`"${t}" is not a valid ${p.targets.join("/")} for ${p.label}`); // D5
  // GET providers pass the target in ?u=; POST providers (Exa) additionally forward a JSON body via the worker.
  const json = p.method === "POST" ? await proxyPost(workerUrl, p.apiUrl(t), p.body ? p.body(t) : {}, opts) : await proxyFetch(workerUrl, p.apiUrl(t), opts);
  return { provider: id, query: t, tier: "T2", entities: uniqueBy(p.parse(json, t), (e) => `${e.type}:${e.value}`) };
}
