import { describe, it, expect } from "vitest";
import {
  OSINT_TOOLS,
  enrichToolDef,
  runEnrichTool,
  validateTarget,
  enrichBudget,
} from "../../src/agent/tools.js";
import { enrichProvider, ENRICH_PROVIDERS } from "../../src/osint/enrich.js";
import type { FetchLike } from "../../src/osint/types.js";

// m3-tools (codex D3/D6/D7/D8): the enrich providers exposed as agent ToolDefs with a closed-allowlist
// router, per-TargetKind validation BEFORE any fetch, a registry-id namespaced source, and a per-run
// budget. None of these symbols existed before this chunk (the negative self-test: it fails to resolve
// the imports / the new behavior until tools.ts is built).

const SHODAN_KEY = "shodanKEY-do-not-leak-123";
const SHODAN_BODY = { ip_str: "8.8.8.8", hostnames: ["dns.google"], domains: ["google.com"], asn: "AS15169", org: "Google LLC", ports: [443] };

function cannedFetch(body: unknown, calls: { n: number }): FetchLike {
  return (async () => {
    calls.n++;
    return { ok: true, status: 200, json: async () => body } as Response;
  }) as unknown as FetchLike;
}
const resolveShodan = (id: string): string | null => (id === "shodan" ? SHODAN_KEY : null);

describe("m3-tools — enrich providers as agent tools", () => {
  it("every provider declares an explicit infra flag", () => {
    for (const p of ENRICH_PROVIDERS) expect(typeof p.infra).toBe("boolean");
  });

  it("enrichToolDef names enrich_<id> with a single target param, no collision with the free tools", () => {
    const shodan = enrichProvider("shodan")!;
    const def = enrichToolDef(shodan);
    expect(def.name).toBe("enrich_shodan");
    expect(def.input_schema.required).toEqual(["target"]);
    expect((def.input_schema.properties as Record<string, unknown>).target).toBeDefined();
    expect(OSINT_TOOLS.some((t) => t.name === def.name)).toBe(false);
  });

  it("validateTarget enforces the kind strictly", () => {
    expect(validateTarget("ip", "8.8.8.8")).toBe(true);
    expect(validateTarget("ip", "999.1.1.1")).toBe(false);
    expect(validateTarget("ip", "example.com")).toBe(false);
    expect(validateTarget("domain", "example.com")).toBe(true);
    expect(validateTarget("domain", "8.8.8.8")).toBe(false);
    expect(validateTarget("wallet", "0x" + "a".repeat(40))).toBe(true);
    expect(validateTarget("wallet", "0x123")).toBe(false);
  });

  it("an unknown / prototype-pollution id routes to an is_error, never a fetch", async () => {
    const calls = { n: 0 };
    const opts = { fetchImpl: cannedFetch(SHODAN_BODY, calls) };
    for (const name of ["enrich_nope", "enrich___proto__", "enrich_", "dns_lookup"]) {
      const out = await runEnrichTool(name, { target: "8.8.8.8" }, resolveShodan, opts);
      expect(out.is_error).toBe(true);
    }
    expect(calls.n).toBe(0); // closed allowlist: never reached an adapter
  });

  it("a wrong-kind target is rejected BEFORE any key lookup or fetch", async () => {
    const calls = { n: 0 };
    const out = await runEnrichTool("enrich_shodan", { target: "example.com" }, resolveShodan, { fetchImpl: cannedFetch(SHODAN_BODY, calls) });
    expect(out.is_error).toBe(true);
    expect(calls.n).toBe(0); // validation runs before the adapter
  });

  it("a missing key is a clean is_error with no fetch", async () => {
    const calls = { n: 0 };
    const out = await runEnrichTool("enrich_shodan", { target: "8.8.8.8" }, () => null, { fetchImpl: cannedFetch(SHODAN_BODY, calls) });
    expect(out.is_error).toBe(true);
    expect(calls.n).toBe(0);
  });

  it("a keyed run returns gated entities, the namespaced source, infra + queryEcho, and never the key", async () => {
    const calls = { n: 0 };
    const out = await runEnrichTool("enrich_shodan", { target: "8.8.8.8" }, resolveShodan, { fetchImpl: cannedFetch(SHODAN_BODY, calls) });
    expect(out.is_error).toBe(false);
    expect(calls.n).toBe(1);
    expect(out.provider).toBe("enrich:shodan"); // registry-id namespaced (D6)
    expect(out.infra).toBe(true);
    expect(out.queryEcho).toBe("8.8.8.8");
    expect(out.entities.some((e) => e.type === "domain" && e.value === "dns.google")).toBe(true);
    expect(out.content).not.toContain(SHODAN_KEY); // the key rode only in the URL, never the content
  });

  it("enrichBudget blocks a repeat (provider,target) and the per-provider cap", () => {
    const b = enrichBudget({ maxTotal: 10, maxPerProvider: 2 });
    expect(b.check("enrich:shodan", "8.8.8.8").ok).toBe(true);
    expect(b.check("enrich:shodan", "8.8.8.8").ok).toBe(false); // repeat
    expect(b.check("enrich:shodan", "1.1.1.1").ok).toBe(true);
    expect(b.check("enrich:shodan", "2.2.2.2").ok).toBe(false); // per-provider cap (2) reached
    expect(b.check("enrich:ipinfo", "2.2.2.2").ok).toBe(true); // a different provider is independent
  });
});
