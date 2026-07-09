// The "what tools does this app ACTUALLY run" inventory (founder 2026-07-09). Unlike catalog.ts (the
// hand-maintained marketing inventory, which lists aspirational backend/Apify capabilities the browser
// can't run), this is DERIVED at build time from the live registries — so it can never claim a tool the
// app doesn't actually wire, and never miss one that's added:
//   - Without a key = OSINT_TOOLS minus the proxied set (keyless, browser-direct).
//   - With your own key = ENRICH_PROVIDERS (the CORS-open keyed providers, key entered in the app).
//   - Pro = BLOCKED_PROVIDERS (CORS-blocked — run through the user's own Worker proxy / the pro tier).
// It is a MANIFEST, not a runner — nothing here fetches. Rendered by renderToolsPage (pages.ts).
import { OSINT_TOOLS, PROXIED_TOOL_NAMES } from "../agent/tools.js";
import { ENRICH_PROVIDERS, BLOCKED_PROVIDERS } from "./enrich.js";

export interface ToolInfo {
  /** The tool / provider name shown on the row. */
  name: string;
  /** One line: what it does. */
  detail: string;
}

export interface ToolInventory {
  keyless: ToolInfo[];
  keyed: ToolInfo[];
  pro: ToolInfo[];
}

/** The first sentence of a prescriptive ToolDef description — the "what it does" one-liner, without the
 *  "Call this when …" trigger prose that follows. Falls back to the whole string if there's no period. */
function firstSentence(description: string): string {
  const m = /^(.*?[.])(?:\s|$)/.exec(description.trim());
  return (m ? m[1] : description).trim();
}

/** Derive the live inventory from the registries. Pure — safe to call at render time. */
export function toolInventory(): ToolInventory {
  const keyless = OSINT_TOOLS.filter((t) => !PROXIED_TOOL_NAMES.has(t.name)).map((t) => ({
    name: t.name,
    detail: firstSentence(t.description),
  }));
  const keyed = ENRICH_PROVIDERS.map((p) => ({
    name: p.label,
    detail: `${p.blurb} — needs your ${p.keyHint}`,
  }));
  const pro = BLOCKED_PROVIDERS.map((b) => ({
    name: b.label,
    detail: "CORS-blocked — runs through your own Worker proxy (the pro tier), not the free browser app",
  }));
  return { keyless, keyed, pro };
}

/** Flat counts for the page header. */
export function toolInventoryCounts(): { total: number; keyless: number; keyed: number; pro: number } {
  const inv = toolInventory();
  return {
    total: inv.keyless.length + inv.keyed.length + inv.pro.length,
    keyless: inv.keyless.length,
    keyed: inv.keyed.length,
    pro: inv.pro.length,
  };
}
