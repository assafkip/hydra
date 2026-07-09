// Link resolver (hydra-see-sites 2026-07-08). Reads a page's SERVER HTML (via the user's Worker /page
// endpoint) and pulls the OUTBOUND destination link a link-aggregator page points to — the pivot a static
// fetch or Jina misses because the source (e.g. pinterest.com) is CORS-walled and JS-heavy.
//
// KEY RECON (verified live 2026-07-08): a Pinterest pin's destination is in the INITIAL server HTML as a
// `"link":"<url>"` field (pin 661677370297740779 → an Etsy listing). So NO headless render / JS execution is
// needed — a plain Worker GET + this parser gets it. The Worker is required only because the browser can't
// read pinterest.com's HTML directly (no CORS); it is the LIGHT /page path, not /render.
//
// EVIDENCE TIER: an independently fetched live page is T2, and the named destination is a LEAD a T1 infra
// tool (dns/rdap/crt.sh) must confirm — infra:false. Same discipline as the Jina/Perplexity adapters.
import type { OsintEntity, OsintOpts, OsintResult } from "./types.js";
import { resolvePageViaProxy } from "./proxy.js";

const MAX_LEADS = 20;

// Bare hosts to treat as "self / not a destination" (the source platform + its CDN). Kept as BARE strings
// (no https:// literal) so the leakgate egress scanner never mistakes them for a fetch origin — the client
// never fetches these; the Worker does. endsWith-matched so subdomains (i.pinimg.com) are covered.
const SELF_HOSTS = ["pinterest.com", "pinimg.com"];

function isSelfHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^www\./, "");
  return SELF_HOSTS.some((s) => h === s || h.endsWith(`.${s}`));
}

/** Parse the outbound destination(s) from a page's HTML. Returns the destination first (noted distinctly),
 *  then any other external domains as leads. `sourceUrl` is the page we fetched (its own host is filtered out
 *  so a self-link never reads as the destination). */
export function extractDestination(html: string, sourceUrl: string): OsintEntity[] {
  let sourceHost = "";
  try {
    sourceHost = new URL(sourceUrl).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    /* sourceUrl may be a bare string in a test — no source-host filter then */
  }

  const out: OsintEntity[] = [];
  const seenDomains = new Set<string>();

  const consider = (rawUrl: string, note: string): void => {
    // JSON often escapes the slashes ("https:\/\/…"); unescape before parsing.
    const clean = rawUrl.replace(/\\\//g, "/").trim();
    let u: URL;
    try {
      u = new URL(clean);
    } catch {
      return;
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") return;
    const host = u.hostname.toLowerCase().replace(/^www\./, "");
    if (!host || isSelfHost(host) || host === sourceHost) return;
    if (seenDomains.has(host)) return;
    seenDomains.add(host);
    out.push({ type: "url", value: clean, note });
    out.push({ type: "domain", value: host, note });
  };

  // 1) The high-value destination fields a link-aggregator embeds (Pinterest `"link"`, generic `"clickthrough"`).
  const LINK_FIELD = /"(?:link|clickthrough_url|destination_url)":"((?:https?:|https?:\\\/\\\/)[^"]+)"/gi;
  for (const m of html.matchAll(LINK_FIELD)) consider(m[1], "outbound destination link (T2 lead — confirm with an infra tool)");

  // 2) Fallback leads: any other external URL named in the page (bounded).
  const URL_RE = /(?:https?:\/\/|https?:\\\/\\\/)[^\s"'<>\\)]+/gi;
  for (const m of html.matchAll(URL_RE)) {
    if (out.length >= MAX_LEADS * 2) break; // out holds url+domain pairs
    consider(m[0], "external link on the page (T2 lead — confirm with an infra tool)");
  }

  return out.slice(0, MAX_LEADS * 2);
}

/** Resolve a page's outbound destination via the user's Worker. Fetches the server HTML (keyless /page),
 *  parses the destination + external leads. Returns tier T2 with the destination surfaced first; the entities
 *  are LEADS (infra:false) a T1 tool must confirm. Throws a sanitized error (no worker url) on a bad worker /
 *  blocked host / non-200. */
export async function resolveLink(url: string, workerUrl: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const target = url.trim();
  if (!target) throw new Error("resolveLink: empty URL");
  const page = await resolvePageViaProxy(workerUrl, target, opts);
  const entities = extractDestination(page.text, page.finalUrl || target);
  const dest = entities.find((e) => e.type === "url");
  let sourceHost = "page";
  try {
    sourceHost = new URL(target).hostname;
  } catch {
    /* keep the fallback label */
  }
  return {
    provider: `resolve:${sourceHost}`,
    query: dest ? `${target} → ${dest.value}` : target,
    tier: "T2", // an independently fetched live page; the destination is a lead an infra tool confirms
    entities,
  };
}
