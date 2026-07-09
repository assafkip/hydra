// RDAP via rdap.org (CORS-open; 302-redirects to the registry RDAP host, which is
// also CSP-allowlisted). The structured replacement for port-43 whois. T1: a
// domain registry record is non-fakeable.
import { type OsintEntity, type OsintOpts, type OsintResult, uniqueBy, withRetry } from "./types.js";

const ENDPOINT = "https://rdap.org/domain/";

interface RdapVcardEntry {
  0: string;
}
interface RdapEntity {
  roles?: string[];
  handle?: string;
  vcardArray?: [string, RdapVcardEntry[]];
}
interface RdapResponse {
  handle?: string;
  ldhName?: string;
  nameservers?: { ldhName?: string }[];
  entities?: RdapEntity[];
  events?: { eventAction?: string; eventDate?: string }[];
}

function vcardName(entity: RdapEntity): string | undefined {
  const props = entity.vcardArray?.[1] ?? [];
  for (const p of props as unknown as Array<[string, unknown, unknown, string]>) {
    if (p[0] === "fn" && typeof p[3] === "string") return p[3];
  }
  return entity.handle;
}

export async function rdapDomain(domain: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const url = `${ENDPOINT}${encodeURIComponent(domain)}`;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(url, { headers: { accept: "application/rdap+json" }, signal: opts.signal });
      if (!res.ok) throw new Error(`RDAP HTTP ${res.status}`);
      return (await res.json()) as RdapResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );

  const entities: OsintEntity[] = [];
  if (json.ldhName) entities.push({ type: "domain", value: json.ldhName.toLowerCase() });
  for (const ns of json.nameservers ?? []) {
    if (ns.ldhName) entities.push({ type: "nameserver", value: ns.ldhName.toLowerCase() });
  }
  for (const ent of json.entities ?? []) {
    const name = vcardName(ent);
    if (!name) continue;
    if (ent.roles?.includes("registrar")) entities.push({ type: "registrar", value: name });
    else if (ent.roles?.includes("registrant")) entities.push({ type: "registrant", value: name });
  }
  return {
    provider: "rdap.org",
    query: domain,
    tier: "T1",
    entities: uniqueBy(entities, (e) => `${e.type}:${e.value}`),
  };
}
