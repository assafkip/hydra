// Phone parse (restore-osint-tool-belt 2026-06-24, port of investigations/enrich/phone.py).
// Region / country / line-type, fully OFFLINE — libphonenumber-js bundles its metadata; NO network, no key.
// The line-type is the fraud signal the Python adapter highlights (VOIP == common disposable/fraud anchor).
//
// Parity note vs the Python adapter: Google's `phonenumbers` lib also ships geocoder + carrier datasets
// (carrier name, granular geo description). libphonenumber-js does NOT bundle those (they are megabytes of
// data we will not ship to a zero-CDN browser bundle). So this emits region (country name via the built-in
// Intl.DisplayNames), country code, line-type, and validity — carrier is reported as unavailable in-browser
// rather than faked. Per the q-investigation rule, a phone as an IDENTITY anchor still needs a second source.
import { parsePhoneNumberFromString } from "libphonenumber-js";
import type { OsintOpts, OsintResult } from "./types.js";

function regionName(country: string | undefined): string {
  if (!country) return "";
  try {
    return new Intl.DisplayNames(["en"], { type: "region" }).of(country) ?? country;
  } catch {
    return country;
  }
}

/** Parse a phone number offline: E.164, country, region name, line-type, validity. Keyless, deterministic,
 *  no network. T2 — a parsed number is a deterministic record, but as an identity anchor it needs a second
 *  independent source (q-investigation rule), so this asserts NO account attribution on its own. */
export async function phoneParse(number: string, _opts: OsintOpts = {}): Promise<OsintResult> {
  const num = number.trim();
  if (!num) throw new Error("phone_parse: empty number");
  const parsed = parsePhoneNumberFromString(num);
  if (!parsed) {
    throw new Error(`phone_parse: cannot parse '${num}' — use E.164 (+<country code><number>)`);
  }
  if (!parsed.isValid()) {
    return {
      provider: "phone_parse",
      query: num,
      tier: "T2",
      entities: [],
      summary: `phone: ${num} — invalid (not a valid number per libphonenumber metadata).`,
    };
  }
  const e164 = parsed.number; // E.164 form
  const country = parsed.country ?? "";
  const region = regionName(country);
  // getType() can be undefined for ambiguous numbers (no unique type) — surface UNKNOWN, never crash.
  const lineType = (parsed.getType() ?? "UNKNOWN").toString();
  const summary = [
    `E.164: ${e164}`,
    `region: ${region || "(unknown)"}`,
    `country: ${country || "(unknown)"}`,
    `carrier: (unavailable in-browser — carrier metadata not bundled)`,
    `line type: ${lineType}`,
    ...(lineType === "VOIP" ? ["VoIP — a common fraud/disposable signal."] : []),
  ].join("\n");
  // No emittable entity type for a phone number itself (EntityType has no `phone`), so the value rides in
  // the summary; the agent reasons on it and corroborates before any attribution.
  return { provider: "phone_parse", query: num, tier: "T2", entities: [], summary };
}
