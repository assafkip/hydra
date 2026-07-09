// A6 Perplexity: keyed, browser-native web-search + reasoning, ported from the Python osint_mcp
// perplexity tool (case-031 D2 — the attribution-research escalation). Perplexity's API is CORS-open
// with the user's Bearer key (memory enrich-most-providers-are-cors-open), so it is called DIRECT from
// the browser; the key rides the Authorization header, never the URL, and is never echoed in an error.
//
// EVIDENCE TIER: a search-API summary is T3 (q-investigation rule: "automated tool output only … a
// search-API summary … hypothesis queue only, NOT citable"). So this adapter is T3 and its provider is
// infra:false — the entities it surfaces (domains/IPs the answer names) land as LEADS, never auto-graphed
// findings. That is the case-031 D2 pattern: Perplexity surfaces CANDIDATES, the T1 infra tools (dns/rdap/
// crt.sh) then confirm them. The answer text rides the result `query` so the agent reads the reasoning.
//
// Reasoning-mode escalation: `sonar` is the fast search model; `sonar-reasoning` is the deeper model the
// Python escalates to for a hard attribution question. The adapter picks `sonar-reasoning` when the query
// reads like a reasoning task (who/why/connect/attribute…), else `sonar` — one call, one enrich-budget slot.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.perplexity.ai/chat/completions";
const MAX_ANSWER = 1200; // bound the answer text we carry back (the agent gets the gist, not a wall)

// Entity shapes worth surfacing from the answer prose. Conservative (admission re-gates downstream): a
// domain (not an email/file), an IPv4, a full URL. The gate's isAdmissible drops noise/boilerplate.
const DOMAIN_RE = /\b(?!www\.)(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"')\\]+/gi;
const REASONING_HINT = /\b(who|why|connect|link|attribut|relationship|behind|owner|operate|same)\b/i;

interface PplxResponse {
  choices?: { message?: { content?: unknown } }[];
  citations?: unknown;
}

function extractEntities(answer: string): OsintEntity[] {
  const out: OsintEntity[] = [];
  const seen = new Set<string>();
  const push = (type: OsintEntity["type"], value: string): void => {
    const v = value.toLowerCase().replace(/[.,;:)]+$/, "");
    const k = `${type}:${v}`;
    if (v && !seen.has(k)) { seen.add(k); out.push({ type, value: v, note: "Perplexity search (T3 lead — confirm with an infra tool)" }); }
  };
  for (const m of answer.matchAll(URL_RE)) push("url", m[0]);
  for (const m of answer.matchAll(IPV4_RE)) push("ip", m[0]);
  for (const m of answer.matchAll(DOMAIN_RE)) push("domain", m[0]);
  return out.slice(0, 30); // bound the surfaced lead set
}

/**
 * Run one Perplexity web search for `query` with the user's key. Returns the answer text (in `query`,
 * bounded) + the domains/IPs/URLs it named as T3 LEAD entities (the gate keeps them off the graph until
 * an infra tool confirms them). Throws a sanitized error on a bad key / empty query / unexpected shape —
 * the key is never in the message.
 */
export async function perplexitySearch(query: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const q = query.trim();
  if (!q) throw new Error("Perplexity: empty query");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const model = REASONING_HINT.test(q) ? "sonar-reasoning" : "sonar"; // reasoning-mode escalation
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify({
          model,
          messages: [
            { role: "system", content: "You are an OSINT research assistant. Answer concisely with concrete entities (domains, IPs, names, wallets) and cite sources." },
            { role: "user", content: q },
          ],
        }),
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`Perplexity HTTP ${res.status}`); // 401 bad key — NEVER echo the key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const content = (json as PplxResponse)?.choices?.[0]?.message?.content;
  const answer = typeof content === "string" ? content.trim() : "";
  if (!answer) throw new Error("Perplexity: empty answer");
  const bounded = answer.slice(0, MAX_ANSWER); // extract from the BOUNDED text (codex), not a huge answer
  return {
    provider: "perplexity",
    query: `${q} → [${model}] ${bounded}`,
    tier: "T3", // a search summary is never citable — hypothesis/lead only (q-investigation tiers)
    entities: extractEntities(bounded),
  };
}
