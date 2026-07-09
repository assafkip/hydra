// Tavily search (hydra-osint-provider-inputs 2026-07-08). Agent web-search + page extract, keyed.
// CORS-OPEN with the user's Bearer key — verified LIVE 2026-07-08 (Origin: https://hydra.ktlystlabs.com):
// the POST /search preflight returns 200 with ACAO=hydra + allows authorization,content-type,POST, and the
// actual POST response carries `access-control-allow-origin: *`. This SUPERSEDES the stale enrich.ts scar
// that once put Tavily in the proxy tier (Tavily fixed their CORS since 2026-06-24). So it is called DIRECT
// from the browser; the key rides the Authorization: Bearer header, never the URL, never echoed in an error.
//
// EVIDENCE TIER: a search-API summary is T3 (q-investigation rule: "automated tool output only … a
// search-API summary … hypothesis queue only, NOT citable"). So this adapter is T3 and its provider is
// infra:false — the domains/IPs/URLs it names land as LEADS a T1 infra tool (dns/rdap/crt.sh) must confirm,
// exactly like Perplexity/Jina. The answer + result snippets ride the result `query`/`summary` for the agent.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.tavily.com/search";
const MAX_TEXT = 3000; // bound the text carried back (the agent gets the gist, not a wall)

const DOMAIN_RE = /\b(?!www\.)(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"')\\]+/gi;

interface TavilyResult {
  url?: unknown;
  title?: unknown;
  content?: unknown;
}
interface TavilyResponse {
  answer?: unknown;
  results?: unknown;
}

function leadsFromText(text: string): OsintEntity[] {
  const out: OsintEntity[] = [];
  const seen = new Set<string>();
  const push = (type: OsintEntity["type"], value: string): void => {
    const v = value.toLowerCase().replace(/[.,;:)]+$/, "");
    const k = `${type}:${v}`;
    if (v && !seen.has(k)) { seen.add(k); out.push({ type, value: v, note: "Tavily search (T3 lead — confirm with an infra tool)" }); }
  };
  for (const m of text.matchAll(URL_RE)) push("url", m[0]);
  for (const m of text.matchAll(IPV4_RE)) push("ip", m[0]);
  for (const m of text.matchAll(DOMAIN_RE)) push("domain", m[0]);
  return out.slice(0, 30); // bound the surfaced lead set
}

/**
 * Run one Tavily web search for `query` with the user's key. Returns the answer + result snippets (bounded,
 * in `summary`) + the domains/IPs/URLs they named as T3 LEAD entities (the gate keeps them off the graph
 * until an infra tool confirms them). Throws a sanitized `Tavily HTTP <status>` on a bad key / empty query /
 * unexpected shape — the key is never in the message.
 */
export async function tavilySearch(query: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const q = query.trim();
  if (!q) throw new Error("Tavily: empty query");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify({ query: q, max_results: 10, include_answer: true }),
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`Tavily HTTP ${res.status}`); // 401 bad key — NEVER echo the key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const resp = json as TavilyResponse;
  const answer = typeof resp?.answer === "string" ? resp.answer : "";
  const results = Array.isArray(resp?.results) ? (resp.results as TavilyResult[]) : [];
  const snippets = results
    .map((r) => `${typeof r?.url === "string" ? r.url : ""} ${typeof r?.content === "string" ? r.content : ""}`)
    .join("\n");
  const text = `${answer}\n${snippets}`.trim();
  if (!text) throw new Error("Tavily: empty result");
  const bounded = text.slice(0, MAX_TEXT); // extract from the BOUNDED text, not a huge payload
  return {
    provider: "tavily",
    query: `${q} → ${answer.slice(0, 200)}`,
    tier: "T3", // a search summary is never citable — hypothesis/lead only (q-investigation tiers)
    entities: leadsFromText(bounded),
    summary: bounded,
  };
}
