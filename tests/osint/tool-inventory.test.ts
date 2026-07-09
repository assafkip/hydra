import { describe, it, expect } from "vitest";
import { toolInventory, toolInventoryCounts } from "../../src/osint/tool-inventory.js";
import { OSINT_TOOLS, PROXIED_TOOL_NAMES } from "../../src/agent/tools.js";
import { ENRICH_PROVIDERS, BLOCKED_PROVIDERS, KEY_GUIDANCE } from "../../src/osint/enrich.js";

describe("tool inventory (the /tools page — derived, never drifts)", () => {
  const inv = toolInventory();

  it("keyless = every OSINT tool that is NOT proxied (and nothing else)", () => {
    expect(inv.keyless.length).toBe(OSINT_TOOLS.length - PROXIED_TOOL_NAMES.size);
    for (const t of inv.keyless) expect(PROXIED_TOOL_NAMES.has(t.name)).toBe(false);
    // reverse_ip is a keyless tool → it must appear here
    expect(inv.keyless.some((t) => t.name === "reverse_ip")).toBe(true);
  });

  it("keyed = the enrich providers, pro = the blocked providers", () => {
    expect(inv.keyed.length).toBe(ENRICH_PROVIDERS.length);
    expect(inv.pro.length).toBe(BLOCKED_PROVIDERS.length);
  });

  it("the proxied tools are surfaced under Pro, never keyless", () => {
    for (const name of PROXIED_TOOL_NAMES) {
      expect(inv.keyless.some((t) => t.name === name)).toBe(false);
    }
  });

  it("counts add up", () => {
    const c = toolInventoryCounts();
    expect(c.total).toBe(c.keyless + c.keyed + c.pro);
    expect(c.total).toBe(inv.keyless.length + inv.keyed.length + inv.pro.length);
  });

  it("every row has a non-empty name + detail (no blank cells)", () => {
    for (const row of [...inv.keyless, ...inv.keyed, ...inv.pro]) {
      expect(row.name.length).toBeGreaterThan(0);
      expect(row.detail.length).toBeGreaterThan(0);
    }
  });
});

describe("key guidance is complete for every keyed provider (no vague key hints)", () => {
  it("each enrich provider has a token-creation URL + steps", () => {
    for (const p of ENRICH_PROVIDERS) {
      const g = KEY_GUIDANCE[p.id];
      expect(g, `missing KEY_GUIDANCE for ${p.id}`).toBeDefined();
      expect(g.url.startsWith("https://"), `${p.id} key url must be https`).toBe(true);
      expect(g.steps.length, `${p.id} needs steps`).toBeGreaterThan(10);
    }
  });

  it("github + gitlab are optional (they run keyless); the rest require a key", () => {
    expect(KEY_GUIDANCE.github.required).toBe(false);
    expect(KEY_GUIDANCE.gitlab.required).toBe(false);
    for (const p of ENRICH_PROVIDERS) {
      if (p.id === "github" || p.id === "gitlab") continue;
      expect(KEY_GUIDANCE[p.id].required, `${p.id} should require a key`).toBe(true);
    }
  });
});
