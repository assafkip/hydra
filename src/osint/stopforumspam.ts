// StopForumSpam — keyless IP abuse-reputation (api.stopforumspam.org, CORS `*`, PRD
// prd-hydra-free-osint-providers finding-1). A crowd-reported spam/abuse score is NOT a non-fakeable infra
// record, so this is a T3 LEAD: the value is the reputation text (summary), it emits no typed entity and
// registers infra:false, so a reputation hit can never inflate the promotion gate's infra count.
import { type OsintOpts, type OsintResult, withRetry } from "./types.js";

const ENDPOINT = "https://api.stopforumspam.org/api";

interface StopForumSpamResponse {
  success?: number;
  ip?: { value?: string; frequency?: number; appears?: number; country?: string };
}

/** IP → its crowd-reported spam/abuse frequency (summary only). Keyless, T3 lead (infra:false). */
export async function stopForumSpamLookup(ip: string, opts: OsintOpts = {}): Promise<OsintResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const json = await withRetry(
    async () => {
      const res = await fetchImpl(`${ENDPOINT}?ip=${encodeURIComponent(ip)}&json`, { signal: opts.signal });
      if (!res.ok) throw new Error(`StopForumSpam HTTP ${res.status}`);
      return (await res.json()) as StopForumSpamResponse;
    },
    opts.retries,
    undefined,
    opts.signal,
  );
  const rec = json.ip;
  const appears = rec?.appears ?? 0;
  const summary = appears
    ? `flagged in ${appears} spam report(s), frequency ${rec?.frequency ?? 0}${rec?.country ? `, country ${rec.country}` : ""}`
    : "no spam reports on record";
  return { provider: "stopforumspam", query: ip, tier: "T3", entities: [], summary };
}
