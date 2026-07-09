import { describe, it, expect } from "vitest";
import { dnsLookup } from "../../src/osint/doh";
import { rdapDomain } from "../../src/osint/rdap";
import { crtshSubdomains } from "../../src/osint/crtsh";
import { runPivot } from "../../src/osint/index";
import { withRetry, type FetchLike } from "../../src/osint/types";

function fakeFetch(routes: (url: string) => unknown): FetchLike {
  return (async (url: string) => ({
    ok: true,
    status: 200,
    json: async () => routes(String(url)),
  })) as unknown as FetchLike;
}

const DOH = (url: string) => {
  if (url.includes("type=A&") || url.endsWith("type=A"))
    return { Status: 0, Answer: [{ name: "example.com", type: 1, data: "93.184.216.34" }] };
  if (url.includes("type=NS"))
    return { Status: 0, Answer: [{ name: "example.com", type: 2, data: "a.iana-servers.net." }] };
  if (url.includes("type=MX"))
    return { Status: 0, Answer: [{ name: "example.com", type: 15, data: "10 mail.example.com." }] };
  return { Status: 0, Answer: [] };
};

describe("OSINT adapters parse canned fixtures (no network)", () => {
  it("DoH yields ip + nameserver + mailserver entities", async () => {
    const r = await dnsLookup("example.com", { fetchImpl: fakeFetch(DOH), retries: 0 });
    expect(r.provider).toBe("dns.google");
    expect(r.entities).toContainEqual({ type: "ip", value: "93.184.216.34", note: "A of example.com" });
    expect(r.entities.some((e) => e.type === "nameserver" && e.value === "a.iana-servers.net")).toBe(true);
    expect(r.entities.some((e) => e.type === "mailserver" && e.value === "mail.example.com")).toBe(true);
  });

  it("RDAP yields registrar + nameserver + domain entities", async () => {
    const fixture = {
      ldhName: "EXAMPLE.COM",
      nameservers: [{ ldhName: "A.IANA-SERVERS.NET" }],
      entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "RESERVED-Internet"]]] }],
    };
    const r = await rdapDomain("example.com", { fetchImpl: fakeFetch(() => fixture), retries: 0 });
    expect(r.entities).toContainEqual({ type: "domain", value: "example.com" });
    expect(r.entities).toContainEqual({ type: "registrar", value: "RESERVED-Internet" });
    expect(r.entities.some((e) => e.type === "nameserver")).toBe(true);
  });

  it("crt.sh dedupes subdomains and classifies the apex domain", async () => {
    const rows = [
      { name_value: "example.com\nwww.example.com" },
      { common_name: "*.example.com" },
      { name_value: "api.example.com" },
    ];
    const r = await crtshSubdomains("example.com", { fetchImpl: fakeFetch(() => rows), retries: 0 });
    const values = r.entities.map((e) => e.value).sort();
    expect(values).toEqual(["api.example.com", "example.com", "www.example.com"]);
    expect(r.entities.find((e) => e.value === "example.com")!.type).toBe("domain");
    expect(r.entities.find((e) => e.value === "www.example.com")!.type).toBe("subdomain");
  });

  it("withRetry recovers from a transient failure", async () => {
    let calls = 0;
    const out = await withRetry(async () => {
      calls++;
      if (calls < 2) throw new Error("flaky");
      return "ok";
    }, 2, 1);
    expect(out).toBe("ok");
    expect(calls).toBe(2);
  });

  it("runPivot reports how many of the 3 providers succeeded", async () => {
    const router = (url: string) => {
      if (url.includes("dns.google")) return DOH(url);
      if (url.includes("rdap.org")) return { ldhName: "EXAMPLE.COM", nameservers: [] };
      if (url.includes("crt.sh")) return [{ name_value: "example.com" }];
      return {};
    };
    const r = await runPivot("example.com", { fetchImpl: fakeFetch(router), retries: 0 });
    expect(r.succeeded).toBe(3);
    expect(r.results.map((x) => x.provider).sort()).toEqual(["crt.sh", "dns.google", "rdap.org"]);
  });
});
