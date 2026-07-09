// Jina Reader (restore-osint-tool-belt 2026-06-24, port of investigations/enrich/jina.py read mode).
// Reads a URL into clean text/markdown — the keyed alternative to the browser-forensic render when you need
// what a (often JS-built) page actually says. CORS-open with the user's key (r.jina.ai reflects ACAO + allows
// the authorization header — verified live OPTIONS preflight 2026-06-24), so it is called DIRECT from the
// browser. The key rides the Authorization: Bearer header (never the URL, never echoed in an error).
//
// EVIDENCE TIER: a fetched page read is T2 (an independently fetched live page) but NOT a non-fakeable infra
// record, so infra:false — the domains/IPs/URLs in the page text are LEADS for a T1 infra tool to confirm.
import { type OsintEntity, type OsintOpts, type OsintResult, withRetry } from "./types.js";

const READER_BASE = "https://r.jina.ai/";
const MAX_TEXT = 3000; // bound the page text carried back (the agent gets the gist, not the whole page)

const DOMAIN_RE = /\b(?!www\.)(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\b/g;
const URL_RE = /\bhttps?:\/\/[^\s<>"')\\]+/gi;

function leadsFromText(text: string): OsintEntity[] {
  const out: OsintEntity[] = [];
  const seen = new Set<string>();
  const push = (type: OsintEntity["type"], value: string): void => {
    const v = value.toLowerCase().replace(/[.,;:)]+$/, "");
    const k = `${type}:${v}`;
    if (v && !seen.has(k)) { seen.add(k); out.push({ type, value: v, note: "Jina reader (T2 lead — confirm with an infra tool)" }); }
  };
  for (const m of text.matchAll(URL_RE)) push("url", m[0]);
  for (const m of text.matchAll(IPV4_RE)) push("ip", m[0]);
  for (const m of text.matchAll(DOMAIN_RE)) push("domain", m[0]);
  return out.slice(0, 30);
}

/** Read `url` via Jina Reader with the user's key. Returns the page text (bounded, in `summary`) + the
 *  domains/IPs/URLs it named as T2 LEAD entities. Throws a sanitized `Jina HTTP <status>` on a bad key /
 *  blocked URL — the key is never in the message. The reader URL appends the target raw (Jina's design). */
export async function jinaRead(url: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const target = url.trim();
  if (!target) throw new Error("Jina: empty URL");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const text = await withRetry(
    async () => {
      // Only the Authorization header is sent (the live-confirmed CORS-allowed header); r.jina.ai returns
      // markdown by default, so no custom X-Return-Format header is needed (which would widen the preflight).
      const res = await fetchImpl(READER_BASE + target, {
        headers: { authorization: `Bearer ${key}` },
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`Jina HTTP ${res.status}`); // 401 bad key / 4xx blocked — NEVER echo the key
      return (await res.text()).slice(0, MAX_TEXT);
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  return {
    provider: "jina",
    query: `${target} → ${text.slice(0, 200)}`,
    tier: "T2", // an independently fetched live page (lead-grade; confirm named entities with an infra tool)
    entities: leadsFromText(text),
    summary: text,
  };
}
