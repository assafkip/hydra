import { describe, it, expect } from "vitest";
import { pivotLinks } from "../../src/osint/pivots.js";

// ip-pivot (A5, analyze.py:526 PIVOT_TEMPLATES): per-entity external OSINT pivot LINKS. Pure template
// fill — links the analyst clicks, no fetch/key/CORS. Verbatim parity with the original templates.

describe("pivotLinks", () => {
  it("builds the IP pivots (Shodan/AbuseIPDB/Censys/VirusTotal) with the value filled", () => {
    const links = pivotLinks("9.9.9.9", "ip");
    expect(links.map((l) => l.label)).toEqual(["Shodan", "AbuseIPDB", "Censys", "VirusTotal"]);
    expect(links[0].url).toBe("https://www.shodan.io/host/9.9.9.9");
    expect(links[3].url).toBe("https://www.virustotal.com/gui/ip-address/9.9.9.9");
  });

  it("maps the web 'wallet' / 'ip_address' types onto the original crypto_wallet / ip templates", () => {
    expect(pivotLinks("0x" + "a".repeat(40), "wallet")[0].url).toBe("https://etherscan.io/address/0x" + "a".repeat(40));
    expect(pivotLinks("1.2.3.4", "ip_address")[0].label).toBe("Shodan");
  });

  it("uses value_strip (@ + scheme removed) for telegram + handle templates", () => {
    const tg = pivotLinks("t.me/evilchan", "telegram_channel");
    expect(tg[0].url).toBe("https://t.me/t.me%2Fevilchan"); // {strip} of 't.me/evilchan' (no scheme to strip), encoded
    const handle = pivotLinks("@scammer", "handle");
    expect(handle.find((l) => l.label === "X/Twitter")?.url).toBe("https://x.com/search?q=scammer"); // @ stripped
  });

  it("URL-encodes the value so a space / quote / # cannot break the href", () => {
    const links = pivotLinks("a b#c", "domain");
    expect(links.every((l) => !/[ #]/.test(l.url.replace(/^https?:\/\/[^?#]*/, "")) || l.url.includes("%"))).toBe(true);
    expect(links[0].url).toContain("a%20b%23c");
  });

  it("returns [] for a type with no templates or an empty value", () => {
    expect(pivotLinks("x", "unknown_type")).toEqual([]);
    expect(pivotLinks("", "ip")).toEqual([]);
  });

  it("covers the fingerprint pivots the original adds (tracking_tag → PublicWWW)", () => {
    const links = pivotLinks("UA-12345-1", "tracking_tag");
    expect(links[0].url).toContain("publicwww.com");
    expect(links[0].url).toContain("UA-12345-1");
  });
});
