// gleif — keyless company registry lookup via the GLEIF LEI API (api.gleif.org, CORS `*`, re-probed live
// from the hydra origin 2026-07-09). PRD prd-hydra-free-osint-providers finding-5/6. An LEI record is a
// non-fakeable T1 registry record (the global Legal Entity Identifier system, ISO 17442): a legal name,
// jurisdiction, registered address, and issuance status maintained by an accredited LOU.
//
// finding-6 divergence from investigations/agent/osint_mcp.py opencorporates: OpenCorporates is freemium +
// CORS-blocked (needs a key/proxy), so it can't run browser-direct. This DIVERGES to GLEIF — the free,
// keyless, CORS-open global LEI registry — for the same T1 shell-company-attribution role. GLEIF gives the
// LEI + legal name + jurisdiction + status + ownership-relationship presence (parent/children); it does not
// list officers (that is OpenCorporates' keyed value). Emits the org as a TYPED pivot (finding-5).
import { capString, isNameRelated, MAX_ENRICH_RESULTS, type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://api.gleif.org/api/v1/lei-records";

interface LeiRecord {
  attributes?: {
    lei?: string;
    entity?: {
      legalName?: { name?: string };
      otherNames?: { name?: string }[];
      legalAddress?: { city?: string; country?: string };
      jurisdiction?: string;
      status?: string;
    };
    registration?: { status?: string };
  };
  relationships?: Record<string, unknown>;
}

/** company name → its LEI registry record(s): the legal name as a typed org pivot + LEI/jurisdiction/status
 *  in the note. Keyless, T1 registry. */
export async function gleifLei(company: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const name = company.trim();
  const url = `${ENDPOINT}?filter%5Bentity.legalName%5D=${encodeURIComponent(name)}&page%5Bsize%5D=5`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/vnd.api+json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`GLEIF HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  if (!json || typeof json !== "object" || !Array.isArray((json as { data?: unknown }).data)) {
    throw new Error("GLEIF: unexpected response shape");
  }
  const records = ((json as { data: LeiRecord[] }).data).slice(0, MAX_ENRICH_RESULTS); // cap before materializing
  const entities: OsintEntity[] = [];
  const summaries: string[] = [];
  for (const rec of records) {
    const e = rec.attributes?.entity;
    const legalName = capString(e?.legalName?.name, 200);
    if (!legalName) continue;
    // Relatedness guard (codex adversarial): a hostile GLEIF response must not attribute an UNRELATED entity
    // to the query. Keep the record only if the legal name OR one of its other/trade names relates to the
    // queried name; otherwise drop it (never emit it as a T1 org pivot).
    const otherNameValues = (e?.otherNames ?? []).map((on) => capString(on?.name, 200)).filter(Boolean);
    if (!isNameRelated(name, legalName) && !otherNameValues.some((on) => isNameRelated(name, on))) continue;
    const lei = capString(rec.attributes?.lei, 40);
    const addr = [capString(e?.legalAddress?.city, 80), capString(e?.legalAddress?.country, 8)].filter(Boolean).join(", ");
    const rel = rec.relationships ?? {};
    const ownership = [rel["direct-parent"] ? "has parent" : "", rel["direct-children"] ? "has children" : ""].filter(Boolean).join(" / ");
    const note = [
      lei ? `LEI ${lei}` : "",
      capString(e?.jurisdiction, 16) ? `jurisdiction ${capString(e?.jurisdiction, 16)}` : "",
      addr,
      capString(e?.status, 24) ? `entity ${capString(e?.status, 24)}` : "",
      capString(rec.attributes?.registration?.status, 24) ? `registration ${capString(rec.attributes?.registration?.status, 24)}` : "",
      ownership,
    ].filter(Boolean).join(" · ");
    entities.push({ type: "org", value: legalName, note: `GLEIF LEI registry record — ${note}` });
    // otherNames (trade names / transliterations) are org aliases — capped, typed.
    for (const on of (e?.otherNames ?? []).slice(0, 10)) {
      const alias = capString(on?.name, 200);
      if (alias && alias !== legalName) entities.push({ type: "org", value: alias, note: `GLEIF other/trade name of ${legalName}` });
    }
    if (lei) summaries.push(`${legalName} (${lei})`);
  }
  if (!entities.length) {
    return { provider: "gleif", query: name, tier: "T1", entities: [], summary: `no LEI registry record for "${name}"` };
  }
  return {
    provider: "gleif",
    query: name,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value.toLowerCase()}`).slice(0, MAX_ENRICH_RESULTS),
    summary: `${entities.length} registry match(es): ${summaries.slice(0, 10).join("; ")}`,
  };
}
