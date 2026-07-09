import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// Pairs with the design-rule-compliance PRD (prd-design-rule-compliance-2026-06-20):
// the deterministic mirror of the ui-ux-pro-max rules that bit kipi-web. Registered as a
// permanent prd-os gate (bypass_check) so these a11y/token/icon rules can never silently
// regress. Read-only: scans the committed source, asserts nothing about runtime.

const css = readFileSync("src/styles/app.css", "utf8");

// LIGHT TABLE redesign (2026-07-06): the token system is now a triplet RGB palette (--c-*) backing the
// semantic vars, with a light :root and a dark :root[data-theme="dark"]. These rules keep their teeth —
// WCAG AA + the ink>muted>faint hierarchy — but now verify BOTH themes, resolving the triplet-backed
// tokens instead of reading a single hard-coded hex.
// Match the selectors WITH their opening brace so a mention of ":root[data-theme=\"dark\"]" in a
// comment doesn't shift the block boundaries.
const DARK_START = css.indexOf(':root[data-theme="dark"] {');
const LIGHT_BLOCK = css.slice(css.indexOf(":root {"), DARK_START);
const DARK_BLOCK = css.slice(DARK_START);

// ---- WCAG 2.1 relative-luminance + contrast (on RGB triplets) ----
function srgbToLin(channel: number): number {
  const s = channel / 255;
  return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
}
function luminance([r, g, b]: [number, number, number]): number {
  return 0.2126 * srgbToLin(r) + 0.7152 * srgbToLin(g) + 0.0722 * srgbToLin(b);
}
function contrast(fg: [number, number, number], bg: [number, number, number]): number {
  const hi = Math.max(luminance(fg), luminance(bg));
  const lo = Math.min(luminance(fg), luminance(bg));
  return (hi + 0.05) / (lo + 0.05);
}
/** The --c-* triplet map declared in a theme block. */
function triplets(block: string): Record<string, [number, number, number]> {
  const map: Record<string, [number, number, number]> = {};
  for (const m of block.matchAll(/--(c-[a-z0-9-]+):\s*(\d+)\s+(\d+)\s+(\d+)\s*;/g)) {
    map[m[1]] = [Number(m[2]), Number(m[3]), Number(m[4])];
  }
  return map;
}
/** Which --c-* triplet backs a semantic token (e.g. --faint -> c-ink-faint). */
function backing(name: string): string {
  const m = new RegExp(`--${name}:\\s*rgb\\(var\\(--(c-[a-z0-9-]+)\\)`).exec(css);
  if (!m) throw new Error(`semantic token --${name} is not triplet-backed in app.css`);
  return m[1];
}
/** Resolve a semantic token to its RGB triplet in a given theme. */
function resolve(name: string, block: string): [number, number, number] {
  const t = triplets(block)[backing(name)];
  if (!t) throw new Error(`--${backing(name)} not defined in the theme block`);
  return t;
}
const THEMES: Array<{ name: string; block: string; bgs: string[] }> = [
  { name: "light", block: LIGHT_BLOCK, bgs: ["bg", "card", "bg-soft"] },
  { name: "dark", block: DARK_BLOCK, bgs: ["bg", "card", "bg-soft"] },
];

describe("design-rule compliance (ui-ux-pro-max)", () => {
  it("--faint passes WCAG AA (>=4.5:1) on every background it sits on — both themes", () => {
    for (const { name, block, bgs } of THEMES) {
      const faint = resolve("faint", block);
      for (const bg of bgs) {
        expect(contrast(faint, resolve(bg, block)), `--faint on --${bg} (${name})`).toBeGreaterThanOrEqual(4.5);
      }
    }
  });

  it("keeps ink>muted>faint (contrast against the theme bg descends) — both themes", () => {
    for (const { name, block } of THEMES) {
      const bg = resolve("bg", block);
      const ink = contrast(resolve("ink", block), bg);
      const muted = contrast(resolve("muted", block), bg);
      const faint = contrast(resolve("faint", block), bg);
      expect(ink, `ink>muted (${name})`).toBeGreaterThan(muted);
      expect(muted, `muted>faint (${name})`).toBeGreaterThan(faint);
    }
  });

  it("honors prefers-reduced-motion", () => {
    expect(css).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/);
  });

  it("no emoji icons remain in the de-emoji'd surfaces", () => {
    const banned = ["⚠", "🔍"]; // warning sign, magnifier
    for (const file of ["src/app.ts", "src/pages.ts", "src/chat/dock.ts", "src/agent/session.ts"]) {
      const src = readFileSync(file, "utf8");
      for (const glyph of banned) {
        expect(src.includes(glyph)).toBe(false);
      }
    }
  });

  it("the icon sites use inline SVG matching the index.html idiom", () => {
    const app = readFileSync("src/app.ts", "utf8");
    const pages = readFileSync("src/pages.ts", "utf8");
    // dock "Investigator" title: search SVG
    expect(app).toContain('<span class="dock-title"><svg');
    // storage conflict banner: alert-triangle SVG injected as trusted markup, conflict branch only
    expect(app).toContain('id="storagebanner"');
    expect(app).toMatch(/backend\.conflict \? '<svg/);
    // stale-brief icon: alert-triangle SVG set via innerHTML on .del-stale-icon
    expect(pages).toContain("del-stale-icon");
    expect(pages).toMatch(/del-stale-icon[\s\S]{0,120}<svg/);
    // NOTE: the "Dig one hop" nc-dig SVG button was retired with the node drawer (ccc-workspace-shell —
    // its content, incl. dig-one-hop, moved off the dock). digNode remains a live dep, just not this button.
  });

  it("role-pill classes reference tokens; the LIGHT role colors are unchanged + a dark palette exists", () => {
    // The redesign keeps the light role colors byte-identical and ADDS a dark variant per role. The pills
    // still reference the semantic tokens (no raw hex in the class), and the light triplet must resolve to
    // the original color so a role never silently re-colors.
    const original: Record<string, [number, number, number]> = {
      operator: [194, 65, 12], // #C2410C
      channel: [126, 34, 206], // #7E22CE
      ioc: [185, 28, 28], // #B91C1C
      infra: [21, 128, 61], // #15803D
      source: [71, 85, 105], // #475569
    };
    const lightT = triplets(LIGHT_BLOCK);
    const darkT = triplets(DARK_BLOCK);
    for (const [role, rgb] of Object.entries(original)) {
      // the class references the tokens (no raw hex)
      expect(css).toMatch(
        new RegExp(`\\.role-${role}\\s*\\{[^}]*var\\(--role-${role}-bg\\)[^}]*var\\(--role-${role}-fg\\)`),
      );
      // the light fg resolves to the original color byte-for-byte (no silent recolor)
      expect(lightT[`c-role-${role}`], `light --c-role-${role}`).toEqual(rgb);
      // a distinct dark variant exists (the bench-at-night palette)
      expect(darkT[`c-role-${role}`], `dark --c-role-${role}`).toBeTruthy();
      expect(darkT[`c-role-${role}`], `dark --c-role-${role} differs from light`).not.toEqual(rgb);
    }
    // the empty .role- still styled, via the shared bg-soft / muted tokens
    expect(css).toMatch(/\.role-\s*\{[^}]*var\(--bg-soft\)[^}]*var\(--muted\)/);
  });
});
