// clu-chat-intake: the post-intake COMPLETENESS CHECK. After files/paste are ingested, the conductor
// posts an honest read of what just landed: how many entities, by type, the evidence-tier mix, and the
// explicit gaps. This is the discipline the q-investigation rules demand — never present a single-source
// scrape as if it were corroborated.
//
// TIERING (per .claude/rules/q-investigation.md): document/file-extracted entities are T3 — automated
// extraction output from ONE source, with NO independent corroboration. They are the hypothesis queue,
// not findings. So a fresh intake is all T3 until OSINT/registry/on-chain corroboration adds a T1/T2
// crosslink. We state that plainly instead of implying confidence the evidence doesn't carry.
//
// PURE: no DOM, no vault, no clock. renderCompleteness emits markdown that names only TYPES + counts
// (never the entity VALUES) — so there is no place for a hostile entity string to ride into the chat.

import type { ExtractedEntity } from "../ingest/extract.js";

export interface CompletenessReport {
  totalEntities: number;
  byType: Record<string, number>; // e.g. { domain: 3, wallet: 1 } — counts sum to totalEntities
  tierMix: { T1: number; T2: number; T3: number }; // sums to totalEntities
  gaps: string[]; // explicit, human-readable gaps — always non-empty
}

// On-chain / registry-corroboratable types worth calling out by name in the gap nudges.
const CORROBORATE_HINTS: Record<string, string> = {
  wallet: "wallets on-chain",
  crypto_wallet: "wallets on-chain",
  domain: "domains via whois/DNS",
  ip: "IPs via reverse-DNS/whois",
};

/** Tally extracted entities into a structured completeness report. Fresh document intake is all T3. */
export function intakeCompleteness(entities: ExtractedEntity[]): CompletenessReport {
  const list = Array.isArray(entities) ? entities : [];
  const byType: Record<string, number> = {};
  for (const e of list) {
    const t = (e?.type || "unknown").toLowerCase();
    byType[t] = (byType[t] || 0) + 1;
  }
  const total = list.length;
  // Every freshly-extracted entity is single-source, uncorroborated → T3 (q-investigation evidence tiers).
  const tierMix = { T1: 0, T2: 0, T3: total };

  const gaps: string[] = [];
  if (total === 0) {
    gaps.push("No entities were extracted from this intake — add more evidence, or check the file decoded (a scanned PDF/image OCRs; a binary is skipped).");
    return { totalEntities: 0, byType, tierMix, gaps };
  }
  gaps.push(`All ${total} entit${total === 1 ? "y is" : "ies are"} T3 (single-source, unverified) — none corroborated by an independent T1/T2 source yet.`);
  const corroborate = Object.keys(byType)
    .map((t) => CORROBORATE_HINTS[t])
    .filter((h, i, a): h is string => !!h && a.indexOf(h) === i);
  if (corroborate.length) {
    gaps.push(`To raise the tier, corroborate ${corroborate.join(", ")} — run \`investigate <entity>\` to pivot and crosslink.`);
  } else {
    gaps.push("To raise the tier, run `investigate <entity>` to pivot and crosslink an independent source.");
  }
  return { totalEntities: total, byType, tierMix, gaps };
}

/** Render a completeness report as chat markdown — TYPES + counts only, never entity values (no injection
 *  surface). The conductor posts this after intake. */
export function renderCompleteness(r: CompletenessReport): string {
  const lines: string[] = [];
  lines.push(`**Intake complete — ${r.totalEntities} entit${r.totalEntities === 1 ? "y" : "ies"} extracted.**`);
  const types = Object.keys(r.byType).sort();
  if (types.length) {
    lines.push("");
    lines.push(types.map((t) => `${r.byType[t]} ${t}`).join(" · "));
  }
  lines.push("");
  lines.push(`Evidence tiers: **T1 ${r.tierMix.T1} · T2 ${r.tierMix.T2} · T3 ${r.tierMix.T3}**`);
  lines.push("");
  lines.push("**Gaps:**");
  for (const g of r.gaps) lines.push(`- ${g}`);
  return lines.join("\n");
}
