import { describe, it, expect } from "vitest";
import { emailTriage, emailHeaders } from "../../src/osint/email-intel.js";
import { phoneParse } from "../../src/osint/phone.js";
import { ofacScreen } from "../../src/osint/ofac.js";
import type { FetchLike } from "../../src/osint/types.js";

// A DoH mock that answers by record type parsed from the request URL (?type=MX / ?type=TXT&name=...).
function dohMock(records: { mx?: string[]; txt?: Record<string, string[]> }): FetchLike {
  return (async (url: string) => {
    const u = new URL(url);
    const type = u.searchParams.get("type");
    const name = u.searchParams.get("name") ?? "";
    let answer: { type: number; data: string }[] = [];
    if (type === "MX") answer = (records.mx ?? []).map((d) => ({ type: 15, data: d }));
    if (type === "TXT") answer = (records.txt?.[name] ?? []).map((d) => ({ type: 16, data: d }));
    return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: answer }) };
  }) as unknown as FetchLike;
}

describe("email_triage", () => {
  it("identifies provider + SPF/DMARC + disposable, emits domain + MX pivots", async () => {
    const fetchImpl = dohMock({
      mx: ["10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."],
      txt: {
        "evil.com": ['"v=spf1 include:_spf.google.com ~all"'],
        "_dmarc.evil.com": ['"v=DMARC1; p=reject; rua=mailto:dmarc@evil.com"'],
      },
    });
    const out = await emailTriage("user@evil.com", { fetchImpl, retries: 0 });
    expect(out.provider).toBe("email_triage");
    expect(out.tier).toBe("T1");
    expect(out.summary).toContain("provider: Google Workspace");
    expect(out.summary).toContain("policy reject");
    expect(out.summary).toContain("disposable: no");
    // domain + the two MX hosts come back as pivot nodes
    expect(out.entities.find((e) => e.type === "domain" && e.value === "evil.com")).toBeTruthy();
    expect(out.entities.filter((e) => e.type === "mailserver").length).toBe(2);
  });

  it("flags a disposable domain", async () => {
    const out = await emailTriage("burner@mailinator.com", { fetchImpl: dohMock({ mx: [] }), retries: 0 });
    expect(out.summary).toContain("disposable: YES");
  });

  it("rejects a non-address", async () => {
    await expect(emailTriage("notanemail", { fetchImpl: dohMock({}), retries: 0 })).rejects.toThrow(/user@domain/);
  });

  it("auto-routes a pasted header block to the header parser", async () => {
    const raw = "Received: from a.example (a.example [203.0.113.9]) by mx.test\nFrom: x@test";
    const out = await emailTriage(raw, { fetchImpl: dohMock({}), retries: 0 });
    expect(out.provider).toBe("email_headers");
  });
});

describe("email_headers", () => {
  it("parses the Received chain and flags the origin IP (no network)", async () => {
    const raw = [
      "Received: from relay.test (relay.test [198.51.100.7]) by mx.final.test; Mon",
      "Received: from origin.test (origin.test [203.0.113.42]) by relay.test; Mon",
      "From: attacker@origin.test",
      "X-Originating-IP: [203.0.113.42]",
    ].join("\n");
    const out = await emailHeaders(raw);
    expect(out.provider).toBe("email_headers");
    expect(out.tier).toBe("T3");
    // bottom-most hop with a public IP is the origin
    expect(out.summary).toContain("origin IP: 203.0.113.42");
    const ips = out.entities.filter((e) => e.type === "ip").map((e) => e.value);
    expect(ips).toContain("203.0.113.42");
    expect(ips).toContain("198.51.100.7");
    expect(out.entities.find((e) => e.value === "203.0.113.42")?.note).toContain("ORIGIN");
  });

  it("skips private IPs (only public source IPs are leads)", async () => {
    const raw = "Received: from internal (internal [10.0.0.5]) by mx (mx [192.168.1.1]); Mon";
    const out = await emailHeaders(raw);
    expect(out.entities.filter((e) => e.type === "ip").length).toBe(0);
  });

  it("rejects text with no Received headers", async () => {
    await expect(emailHeaders("From: x@y.com\nSubject: hi")).rejects.toThrow(/no Received/);
  });
});

describe("phone_parse", () => {
  it("parses a valid US mobile (offline, no network)", async () => {
    const out = await phoneParse("+12025550173");
    expect(out.provider).toBe("phone_parse");
    expect(out.summary).toContain("E.164: +12025550173");
    expect(out.summary).toContain("country: US");
    expect(out.entities).toEqual([]);
  });

  it("reports an invalid number without throwing", async () => {
    const out = await phoneParse("+1234");
    expect(out.summary).toContain("invalid");
  });

  it("throws on unparseable junk", async () => {
    await expect(phoneParse("hello")).rejects.toThrow(/cannot parse/);
  });
});

describe("ofac_screen", () => {
  function rpcMock(result: string): FetchLike {
    return (async () => ({ ok: true, status: 200, json: async () => ({ result }) })) as unknown as FetchLike;
  }

  it("flags a sanctioned wallet (oracle returns non-zero)", async () => {
    const out = await ofacScreen("0x" + "a".repeat(40), { fetchImpl: rpcMock("0x" + "0".repeat(63) + "1"), retries: 0 });
    expect(out.tier).toBe("T1");
    expect(out.summary).toContain("SANCTIONED");
    expect(out.entities.find((e) => e.type === "wallet")).toBeTruthy();
  });

  it("reports a clean wallet (oracle returns zero)", async () => {
    const out = await ofacScreen("0x" + "b".repeat(40), { fetchImpl: rpcMock("0x" + "0".repeat(64)), retries: 0 });
    expect(out.summary).toContain("NOT sanctioned");
    expect(out.entities).toEqual([]);
  });

  it("routes a person/org NAME to the proxy tier (treasury.gov is CORS-blocked)", async () => {
    const out = await ofacScreen("Vladimir Putin");
    expect(out.summary).toContain("Worker-proxy tier");
    expect(out.entities).toEqual([]);
  });
});
