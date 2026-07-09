// Chunk-5 enrich: keyed, browser-native AlienVault OTX lookup (otx.alienvault.com, CORS-open: the
// OPTIONS preflight echoes the X-OTX-API-KEY header, verified 2026-06-17). The target may be a domain
// OR an IPv4; the key rides the header, never the URL, and is never echoed in a thrown error.
//
// A6 (parity otx.py): the first web port did passive_dns ONLY. The original ALSO surfaces the threat
// CONTEXT — the OTX `general` endpoint's pulse_info: the named campaigns / threat-actor pulses, their
// malware-family tags, and the related indicators those pulses bundle. That context is what turns a
// passive-DNS hit into "this IP is in the <X> campaign". This adapter now fetches BOTH (one tool call,
// one enrich-budget slot): passive DNS (T2 crosslinks) PLUS the pulse campaign/malware context.
import {
  type OsintEntity,
  type OsintOpts,
  type OsintResult,
  MAX_ENRICH_RESULTS,
  uniqueBy,
  withRetry,
} from "./types.js";

const BASE = "https://otx.alienvault.com/api/v1/indicators";
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

interface OtxPassiveDns {
  passive_dns?: { hostname?: string; address?: string; record_type?: string }[];
}

interface OtxPulse {
  name?: string;
  malware_families?: ({ display_name?: string } | string)[];
  tags?: string[];
  indicators?: { type?: string; indicator?: string }[];
}
interface OtxGeneral {
  pulse_info?: { count?: number; pulses?: OtxPulse[] };
}

async function otxFetch(url: string, key: string, opts: OsintOpts): Promise<unknown> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  return withRetry(
    async () => {
      const res = await fetchImpl(url, {
        headers: { accept: "application/json", "x-otx-api-key": key },
        signal: opts.signal,
      });
      if (!res.ok) throw new Error(`OTX HTTP ${res.status}`); // 403 bad key — NEVER echo the key
      return (await res.json()) as unknown;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
}

/** The pulse_info CONTEXT (otx.py): named campaigns + malware families + the indicators those pulses
 *  bundle. Returns (entities, contextNote). Pulse indicators (domain/IP only — the gate's infra types)
 *  ride as entities tagged with their campaign; the campaign + malware names ride in the note. */
function parseGeneral(general: OtxGeneral, target: string): { entities: OsintEntity[]; note: string } {
  const info = general.pulse_info;
  const pulses = Array.isArray(info?.pulses) ? info!.pulses!.slice(0, 10) : [];
  if (!pulses.length) return { entities: [], note: "" };
  const entities: OsintEntity[] = [];
  const campaigns: string[] = [];
  const malware = new Set<string>();
  for (const p of pulses) {
    const name = typeof p.name === "string" ? p.name.slice(0, 80) : "";
    if (name) campaigns.push(name);
    for (const mf of p.malware_families ?? []) {
      const dn = typeof mf === "string" ? mf : mf?.display_name;
      if (dn) malware.add(dn);
    }
    for (const ind of (p.indicators ?? []).slice(0, MAX_ENRICH_RESULTS)) {
      const v = typeof ind.indicator === "string" ? ind.indicator.toLowerCase().replace(/\.$/, "") : "";
      const t = (ind.type ?? "").toLowerCase();
      if (!v) continue;
      if ((t === "domain" || t === "hostname") && v.includes(".")) {
        entities.push({ type: "domain", value: v, note: `OTX pulse "${name}"` });
      } else if ((t === "ipv4" || t === "ip") && IPV4_RE.test(v)) {
        entities.push({ type: "ip", value: v, note: `OTX pulse "${name}"` });
      }
    }
  }
  const parts = [`${pulses.length} OTX pulse(s) for ${target}`];
  if (campaigns.length) parts.push(`campaigns: ${campaigns.slice(0, 6).join("; ")}`);
  if (malware.size) parts.push(`malware: ${[...malware].slice(0, 6).join(", ")}`);
  return { entities, note: parts.join(" — ") };
}

export async function otxPassiveDns(target: string, key: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const isIp = IPV4_RE.test(target.trim());
  const kind = isIp ? "IPv4" : "domain";
  const url = `${BASE}/${kind}/${encodeURIComponent(target)}/passive_dns`;
  const json = await otxFetch(url, key, opts);

  if (!json || typeof json !== "object") throw new Error("OTX: unexpected response shape");
  const rows = Array.isArray((json as OtxPassiveDns).passive_dns) ? (json as OtxPassiveDns).passive_dns! : [];

  const entities: OsintEntity[] = [];
  for (const row of rows.slice(0, MAX_ENRICH_RESULTS)) {
    if (row.hostname && typeof row.hostname === "string") {
      const host = row.hostname.toLowerCase().replace(/\.$/, "");
      if (host) entities.push({ type: "domain", value: host, note: "OTX passive DNS" });
    }
    if (row.address && typeof row.address === "string" && IPV4_RE.test(row.address)) {
      entities.push({ type: "ip", value: row.address, note: "OTX passive DNS" });
    }
  }

  // A6: ALSO fetch the pulse_info campaign/malware context (one tool call, one enrich-budget slot). A
  // failure here must NOT sink the passive-DNS result — campaign context is additive, so it is best-effort.
  let contextNote = "";
  try {
    const general = (await otxFetch(`${BASE}/${kind}/${encodeURIComponent(target)}/general`, key, opts)) as OtxGeneral;
    if (general && typeof general === "object") {
      const ctx = parseGeneral(general, target);
      entities.push(...ctx.entities);
      contextNote = ctx.note;
    }
  } catch (e) {
    // an injected/cross-realm abort may not be a DOMException — match on the name too (codex), so a
    // cancellation is never swallowed as "context unavailable".
    if (e instanceof Error && e.name === "AbortError") throw e; // stop the loop, don't mask it
    // any other failure: keep the passive-DNS result, drop the context (best-effort).
  }

  return {
    provider: "otx",
    query: contextNote ? `${target} — ${contextNote}` : target,
    tier: "T2",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
