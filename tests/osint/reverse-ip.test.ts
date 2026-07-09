import { describe, it, expect } from "vitest";
import { reverseIpLookup } from "../../src/osint/reverse-ip.js";
import { runTool } from "../../src/agent/tools.js";
import type { FetchLike } from "../../src/osint/types.js";

const IP = "203.0.113.10";

// HackerTarget reverseiplookup returns PLAINTEXT (one domain per line), not JSON — shape captured live
// 2026-07-09. Every failure is a 200 with an `error …` / `API count exceeded …` body.
function fetchText(body: string, status = 200): FetchLike {
  return (async () => ({ ok: status < 400, status, text: async () => body })) as unknown as FetchLike;
}

describe("reverseIpLookup (api.hackertarget.com)", () => {
  it("parses co-hosted domains into domain pivots (T2 lead, not infra)", async () => {
    const impl = fetchText("alpha.example\nbeta.example\ngamma.example");
    const r = await reverseIpLookup(IP, { fetchImpl: impl, retries: 0 });
    expect(r.provider).toBe("hackertarget");
    expect(r.tier).toBe("T2");
    expect(r.entities.map((e) => e.value)).toEqual(["alpha.example", "beta.example", "gamma.example"]);
    expect(r.entities.every((e) => e.type === "domain")).toBe(true);
    expect(r.summary).toContain("co-hosted");
  });

  it("caps a busy shared host and rejects junk lines (hostile-response hardening)", async () => {
    const lines = ["real.example", "not a domain!!", "javascript:alert(1)", ...Array.from({ length: 300 }, (_, i) => `h${i}.shared.test`)];
    const r = await reverseIpLookup(IP, { fetchImpl: fetchText(lines.join("\n")), retries: 0 });
    expect(r.entities.length).toBeLessThanOrEqual(100); // MAX_ENRICH_RESULTS cap
    expect(r.entities.every((e) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(e.value))).toBe(true); // no junk admitted
    expect(r.summary).toContain("showing"); // truncation is disclosed, never silent
  });

  it("an `error …` body throws → is_error (never an empty-success result)", async () => {
    const out = await runTool("reverse_ip", { ip: IP }, { fetchImpl: fetchText("error check your search parameter"), retries: 0 });
    expect(out.is_error).toBe(true);
    expect(out.entities).toHaveLength(0);
  });

  it("a quota body throws → is_error", async () => {
    const out = await runTool("reverse_ip", { ip: IP }, { fetchImpl: fetchText("API count exceeded - Increase Quota with Membership"), retries: 0 });
    expect(out.is_error).toBe(true);
  });

  // NEGATIVE self-test: a non-IP target is rejected BEFORE any fetch (a domain must never reach the reverse-IP API).
  it("a non-IP target is rejected before any fetch", async () => {
    let fetched = false;
    const spy = (async () => {
      fetched = true;
      return { ok: true, status: 200, text: async () => "should.not.happen" };
    }) as unknown as FetchLike;
    const out = await runTool("reverse_ip", { ip: "example.com" }, { fetchImpl: spy, retries: 0 });
    expect(out.is_error).toBe(true);
    expect(fetched).toBe(false);
    expect(JSON.parse(out.content).error).toContain("IPv4");
  });

  it("is wired into the tool DISPATCH and carries infra:false (a shared-host neighbor is a lead)", async () => {
    const out = await runTool("reverse_ip", { ip: IP }, { fetchImpl: fetchText("one.example\ntwo.example"), retries: 0 });
    expect(out.is_error).toBe(false);
    expect(out.infra).toBe(false); // never inflates the promotion gate's infra_source_count
    expect(out.provider).toBe("hackertarget");
  });
});
