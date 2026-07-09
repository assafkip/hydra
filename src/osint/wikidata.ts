// wikidata — keyless entity-resolution via the Wikidata (MediaWiki) API (www.wikidata.org, CORS via the
// MediaWiki `origin=*` anonymous-CORS param — re-probed live from the hydra origin 2026-07-09). PRD
// prd-hydra-free-osint-providers finding-5. A Wikidata name-match is a T3 LEAD (a crowd-maintained
// knowledge graph — a label collision or an editorial error can mislead), so infra:false and every hit is a
// corroborate-first lead, never promotable attribution on its own.
//
// Two bounded calls: wbsearchentities (name → the top item Q-id) then wbgetentities (aliases + claims). It
// emits the label + aliases as TYPED org pivots (finding-5) and the official website (P856) as a url pivot;
// social handles (Twitter P2002, GitHub P2037) ride the summary as leads (no literal-host URL is built in
// source, so the leakgate egress scan is unaffected). Every request appends &origin=* for the CORS grant.
import { capString, httpUrlOrNull, isNameRelated, MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const API = "https://www.wikidata.org/w/api.php";

interface SearchResponse {
  search?: { id?: string; label?: string; description?: string }[];
}
interface Claim {
  mainsnak?: { datavalue?: { value?: unknown } };
}
interface Entity {
  aliases?: Record<string, { value?: string }[]>;
  claims?: Record<string, Claim[]>;
}

async function getJson<T>(fetchImpl: typeof fetch, url: string, opts: OsintOpts): Promise<T> {
  return withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`Wikidata HTTP ${res.status}`);
      return (await res.json()) as T;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

/** Pull the FIRST string claim value for a property (P-id), or "" — Wikidata string-datatype claims (Twitter/
 *  GitHub handles, ORCID, etc.) carry a plain string in mainsnak.datavalue.value. */
function stringClaim(claims: Record<string, Claim[]> | undefined, pid: string): string {
  const v = claims?.[pid]?.[0]?.mainsnak?.datavalue?.value;
  return typeof v === "string" ? v : "";
}

/** company/entity name → its Wikidata label + aliases (typed org pivots) + official website (url) + social
 *  handles (summary leads). Keyless T3 lead. */
export async function wikidataEntity(company: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const name = company.trim();
  const searchUrl = `${API}?action=wbsearchentities&search=${encodeURIComponent(name)}&language=en&format=json&type=item&limit=1&origin=*`;
  const search = await getJson<SearchResponse>(fetchImpl, searchUrl, opts);
  const top = Array.isArray(search.search) ? search.search[0] : undefined;
  if (!top?.id || !/^Q\d+$/.test(top.id)) {
    return { provider: "wikidata", query: name, tier: "T3", entities: [], summary: `no Wikidata item for "${name}"` };
  }

  const getUrl = `${API}?action=wbgetentities&ids=${encodeURIComponent(top.id)}&props=aliases%7Cclaims&languages=en&format=json&origin=*`;
  const got = await getJson<{ entities?: Record<string, Entity> }>(fetchImpl, getUrl, opts);
  const entity = got.entities?.[top.id];

  const entities: OsintEntity[] = [];
  const label = capString(top.label, 200);
  // Relatedness guard (codex adversarial): a hostile Wikidata response must not attribute an UNRELATED item
  // to the query. Require the label OR one of the aliases to relate to the queried name; else return no-match
  // (never inject the unrelated item's org/url/handles as leads).
  const aliasValues = (entity?.aliases?.en ?? []).map((a) => capString(a?.value, 200)).filter(Boolean);
  if (!isNameRelated(name, label) && !aliasValues.some((a) => isNameRelated(name, a))) {
    return { provider: "wikidata", query: name, tier: "T3", entities: [], summary: `no related Wikidata item for "${name}" (top hit ${top.id} did not match)` };
  }
  if (label) entities.push({ type: "org", value: label, note: `Wikidata ${top.id}${top.description ? ` — ${capString(top.description, 120)}` : ""}` });
  // aliases → typed org pivots (capped + length-bounded).
  for (const a of (entity?.aliases?.en ?? []).slice(0, MAX_ENRICH_RESULTS)) {
    const alias = capString(a?.value, 200);
    if (alias && alias !== label) entities.push({ type: "org", value: alias, note: `Wikidata alias of ${label || top.id}` });
  }
  // official website (P856) → a typed url pivot (runtime value, scheme-checked).
  const website = httpUrlOrNull(stringClaim(entity?.claims, "P856"));
  if (website) entities.push({ type: "url", value: website, note: `Wikidata official website of ${label || top.id}` });

  // social handles → SUMMARY leads (no literal-host URL built in source — leakgate egress scan unaffected).
  const twitter = capString(stringClaim(entity?.claims, "P2002"), 40);
  const github = capString(stringClaim(entity?.claims, "P2037"), 60);
  const handleParts = [twitter ? `Twitter @${twitter}` : "", github ? `GitHub ${github}` : ""].filter(Boolean);
  const summary = [`Wikidata ${top.id}`, handleParts.length ? `handles (leads): ${handleParts.join(", ")}` : ""].filter(Boolean).join(" · ");
  return {
    provider: "wikidata",
    query: name,
    tier: "T3",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value.toLowerCase()}`).slice(0, MAX_ENRICH_RESULTS),
    summary,
  };
}
