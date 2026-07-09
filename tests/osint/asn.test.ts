import { describe, it, expect } from "vitest";
import { asnLookup } from "../../src/osint/asn.js";
import { runTool } from "../../src/agent/tools.js";
import type { FetchLike } from "../../src/osint/types.js";

// a56ffd8e: Team Cymru IP→ASN over the dns.google DoH. node-safe via an injected fetchImpl (no network).
// DoH TXT answers arrive quoted (type 16); cymru sends "ASN | prefix | CC | registry | date" for the origin
// zone and "ASN | CC | registry | date | NAME, CC" for the AS-name zone.
function txt(data: string): unknown {
  return { Status: 0, Answer: [{ type: 16, data: `"${data}"` }] };
}
function fetchByName(routes: { match: string; payload: unknown }[]): FetchLike {
  return (async (url: string) => {
    const hit = routes.find((r) => String(url).includes(r.match));
    return { ok: true, status: 200, json: async () => hit?.payload ?? { Status: 0, Answer: [] } } as Response;
  }) as unknown as FetchLike;
}

describe("a56ffd8e asn_lookup — Team Cymru IP→ASN (keyless DoH)", () => {
  it("parses the origin record + AS operator name into one asn entity", async () => {
    const res = await asnLookup("1.1.1.1", {
      fetchImpl: fetchByName([
        { match: "1.1.1.1.origin.asn.cymru.com", payload: txt("13335 | 1.1.1.0/24 | US | arin | 2010-07-14") },
        { match: "AS13335.asn.cymru.com", payload: txt("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US") },
      ]),
    });
    expect(res.tier).toBe("T1");
    expect(res.entities).toHaveLength(1);
    expect(res.entities[0]).toMatchObject({ type: "asn", value: "AS13335" });
    expect(res.entities[0].note).toContain("prefix 1.1.1.0/24");
    expect(res.entities[0].note).toContain("CLOUDFLARENET, US");
  });

  it("splits a multi-origin announcement into one entity per ASN", async () => {
    const res = await asnLookup("8.8.8.8", {
      fetchImpl: fetchByName([
        { match: "8.8.8.8.origin.asn.cymru.com", payload: txt("15169 396982 | 8.8.8.0/24 | US | arin | 2000-01-01") },
      ]),
    });
    expect(res.entities.map((e) => e.value).sort()).toEqual(["AS15169", "AS396982"]);
  });

  it("returns no entities for a non-IPv4 target (no fetch attempted)", async () => {
    const res = await asnLookup("not-an-ip", { fetchImpl: fetchByName([]) });
    expect(res.entities).toEqual([]);
  });

  it("is dispatchable as the asn_lookup agent tool", async () => {
    const out = await runTool(
      "asn_lookup",
      { ip: "1.1.1.1" },
      { fetchImpl: fetchByName([{ match: "origin.asn.cymru.com", payload: txt("13335 | 1.1.1.0/24 | US | arin | 2010") }]) },
    );
    expect(out.is_error).toBe(false);
    expect(out.content).toContain("AS13335");
  });
});
