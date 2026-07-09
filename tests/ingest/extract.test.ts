import { describe, it, expect } from "vitest";
import { extractEntities } from "../../src/ingest/extract.js";

// ig-extract: gate-faithful extraction. Every candidate runs the EXISTING isAdmissible gate, so
// junk/date/noise-domain is dropped; gated ambiguous patterns need a context keyword; cross-type
// precedence is by start-offset; domain detection is whitelist-free (FILE_EXT_DENY only).

const types = (text: string) => {
  const m: Record<string, string[]> = {};
  for (const e of extractEntities(text)) (m[e.type] ??= []).push(e.value);
  return m;
};

describe("extractEntities — high-confidence set", () => {
  it("extracts domain + ipv4 + email + EVM wallet + @handle + a t.me link", () => {
    const t = "Contact admin@evil.xyz at evil.xyz, host 93.184.216.34, pay 0x" + "a".repeat(40) + ", dm @scammer123, join t.me/scamchannel";
    const m = types(t);
    expect(m.email).toContain("admin@evil.xyz");
    expect(m.domain).toContain("evil.xyz");
    expect(m.ip).toContain("93.184.216.34");
    expect(m.wallet).toContain("0x" + "a".repeat(40));
    expect(m.handle).toContain("@scammer123");
    expect(m.telegram_channel?.length).toBeGreaterThan(0);
  });

  it("DROPS a bare date and an all-same-digit run (the gate)", () => {
    const m = types("report date 2026-04-19 ref 000000000");
    expect(JSON.stringify(m)).not.toContain("2026-04-19");
    expect(JSON.stringify(m)).not.toContain("000000000");
  });

  it("DROPS a noise/registry domain (iana.org)", () => {
    expect(types("see iana.org for details").domain ?? []).not.toContain("iana.org");
  });

  // clu-email-trailing-punct (fix-goal from the behavioral smoke): a sentence-final email must not keep
  // the trailing period — parity with the original extractor.py (\b-anchored EMAIL_RE). sp-7fe2143d.
  it("strips trailing punctuation from a sentence-final email (parity with the original)", () => {
    const emails = types("Contact the handler abuse@acme-fixture.io. Thanks.").email ?? [];
    expect(emails).toContain("abuse@acme-fixture.io");
    expect(emails).not.toContain("abuse@acme-fixture.io."); // the trailing dot is gone
  });
});

describe("flexible TLDs (whitelist-free, FILE_EXT_DENY only)", () => {
  it("accepts an abuse TLD (.xyz) and a ccTLD (.us)", () => {
    const m = types("evil.xyz and scam.us");
    expect(m.domain).toContain("evil.xyz");
    expect(m.domain).toContain("scam.us");
  });
  it("accepts NOVEL TLDs a whitelist would miss (.beer / .pink / .sale)", () => {
    const m = types("fifa.beer fifa.pink fifaworldcup26.sale");
    const doms = m.domain ?? [];
    expect(doms).toContain("fifa.beer");
    expect(doms).toContain("fifa.pink");
    expect(doms).toContain("fifaworldcup26.sale");
  });
  it("REJECTS file-extension collisions (README.md / main.py / report.pdf / image.png)", () => {
    const doms = types("see README.md and main.py and util.rs and report.pdf and image.png").domain ?? [];
    for (const f of ["readme.md", "main.py", "util.rs", "report.pdf", "image.png"]) expect(doms).not.toContain(f);
  });
  it("recovers a DEFANGED domain (the un-defang pre-pass)", () => {
    const doms = types("sent to worldcup2026-tickets[.]com and hxxps://fifa-hr[.]com").domain ?? [];
    expect(doms).toContain("worldcup2026-tickets.com");
    expect(doms).toContain("fifa-hr.com");
  });
  it("REJECTS prose that isn't a real TLD (IANA-gated: '1.Introduction' / 'fig.somechart')", () => {
    const doms = types("1.Introduction 2.Summary see fig.somechart and lockfile.package").domain ?? [];
    expect(doms).toEqual([]);
  });
});

describe("gated ambiguous patterns (_scan_gated, D9)", () => {
  it("a solana-shaped base58 is NOT emitted without a context keyword, but IS with one", () => {
    const sol = "9ofbTgT7p3ay9ovXyDub1tEFmEh9SMNX23Ne9N6r6q1"; // 43-char base58
    expect(types(`random string ${sol} here`).wallet ?? []).not.toContain(sol.toLowerCase());
    const withCtx = types(`solana address ${sol}`);
    expect((withCtx.wallet ?? []).map((x) => x.toLowerCase())).toContain(sol.toLowerCase());
  });
});

describe("cross-type precedence (D8)", () => {
  it("a 64-hex types as sha256, a gated 32-hex as walletconnect_id (not md5)", () => {
    const sha = "a".repeat(64);
    const wc = "b".repeat(32);
    const m = types(`hash ${sha} and walletconnect projectId ${wc}`);
    expect(m.hash_sha256).toContain(sha);
    expect(m.walletconnect_id).toContain(wc);
    expect(m.hash_md5 ?? []).not.toContain(wc); // walletconnect claimed the span first
  });
});

describe("phone prevalidation (D7)", () => {
  it("a LABELED bare number is admitted; an unlabeled bare number is dropped", () => {
    expect(types("phone 5551234567").phone ?? []).toContain("5551234567");
    expect(types("order id 5551234567").phone ?? []).not.toContain("5551234567");
  });
  it("a formatted number is admitted without a label", () => {
    expect((types("call +1 (555) 123-4567 now").phone ?? []).length).toBeGreaterThan(0);
  });
});
