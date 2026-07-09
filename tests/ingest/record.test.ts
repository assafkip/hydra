import { describe, it, expect } from "vitest";
import { recordEntities, mergeEntities } from "../../src/ingest/record.js";
import type { ExtractedEntity } from "../../src/ingest/extract.js";

// ig-record (parity record_ingest.py): a CSV is not prose. A column of usernames / full names has NO
// regex signature, so the flat-text path drops it. Column typing recovers it (value-majority, else
// header hint), and every emitted value still passes the one admission gate.

const has = (es: ExtractedEntity[], type: string, value: string) => es.some((e) => e.type === type && e.value === value);

describe("recordEntities — structured column typing", () => {
  it("types columns by VALUE majority (wallet/email/ip), not just header", () => {
    const header = ["col_a", "col_b", "col_c"];
    const rows = [
      ["0x52908400098527886E0F7030069857D2E4169EE7", "admin@evil.xyz", "9.9.9.9"],
      ["0x52908400098527886E0F7030069857D2E4169EE8", "ops@evil.xyz", "1.1.1.1"],
    ];
    const es = recordEntities(header, rows);
    expect(has(es, "wallet", "0x52908400098527886E0F7030069857D2E4169EE7")).toBe(true);
    expect(has(es, "email", "admin@evil.xyz")).toBe(true);
    expect(has(es, "ip", "9.9.9.9")).toBe(true);
  });

  it("recovers person + handle columns the flat regex has NO signature for (the keystone gain)", () => {
    const header = ["Full Name", "username", "note"];
    const rows = [
      ["Ali Reza Mohammadi", "ali_r99", "lead operator"],
      ["Sara Hosseini", "sara_h", "recruiter"],
    ];
    const es = recordEntities(header, rows);
    expect(has(es, "person", "Ali Reza Mohammadi")).toBe(true);
    expect(has(es, "person", "Sara Hosseini")).toBe(true);
    expect(has(es, "handle", "ali_r99")).toBe(true);
    expect(has(es, "handle", "sara_h")).toBe(true);
  });

  it("a phone column follows the web HARD floor: formatted phones land, bare-digit ids don't", () => {
    // the web admission floor is value-only + hard everywhere; a header does NOT vouch a bare number
    // past the downstream gates (unlike record_ingest.py's gate=False). Documented divergence.
    const es = recordEntities(["phone"], [["+1 (402) 928-3844"], ["5125550199"]]);
    expect(has(es, "phone", "+1 (402) 928-3844")).toBe(true); // formatted → admitted
    expect(es.some((e) => e.value === "5125550199")).toBe(false); // bare id → not a phone, dropped
  });

  it("person column skips ids / non-name junk (looks_like_name filter)", () => {
    const es = recordEntities(["name"], [["Real Person"], ["acct_12345"], ["X"]]);
    expect(has(es, "person", "Real Person")).toBe(true);
    expect(es.some((e) => e.value === "acct_12345")).toBe(false);
    expect(es.some((e) => e.value === "X")).toBe(false);
  });

  it("de-dups repeated cell values within a column", () => {
    const es = recordEntities(["email"], [["a@x.io"], ["a@x.io"], ["b@x.io"]]);
    expect(es.filter((e) => e.value === "a@x.io").length).toBe(1);
  });

  it("returns [] when no column types (caller falls back to flat extraction)", () => {
    expect(recordEntities(["misc", "free_text"], [["lorem", "ipsum"]])).toEqual([]);
  });

  it("does not leak registry boilerplate (admission gate still applies)", () => {
    const es = recordEntities(["domain"], [["namecheap.com"], ["real-target.io"]]);
    expect(es.some((e) => e.value === "namecheap.com")).toBe(false); // noise.ts rejects it
    expect(has(es, "domain", "real-target.io")).toBe(true);
  });

  it("a header-typed wallet/username column does NOT emit junk cells (web HARD floor, codex High)", () => {
    // 'address'->wallet, 'username'->handle by header hint; a junk cell must be dropped, not trusted.
    const es = recordEntities(["address", "username"], [
      ["0x52908400098527886E0F7030069857D2E4169EE7", "ali_r99"], // valid pair
      ["not a wallet at all", "free prose with spaces"], // junk cells
    ]);
    expect(has(es, "wallet", "0x52908400098527886E0F7030069857D2E4169EE7")).toBe(true);
    expect(has(es, "handle", "ali_r99")).toBe(true);
    expect(es.some((e) => e.value === "not a wallet at all")).toBe(false); // junk wallet cell dropped
    expect(es.some((e) => e.value === "free prose with spaces")).toBe(false); // junk handle cell dropped
  });

  it("an API key pasted into a wallet/address column is NOT emitted as an entity", () => {
    const es = recordEntities(["wallet"], [["sk-ant-api03-" + "x".repeat(40)], ["0x" + "a".repeat(40)]]);
    expect(es.some((e) => e.value.startsWith("sk-ant"))).toBe(false); // not a wallet shape → dropped
    expect(has(es, "wallet", "0x" + "a".repeat(40))).toBe(true);
  });

  it("tightened email/url matchers reject extractor.py-excluded fragments (codex Medium)", () => {
    // 'a@b.com.' is not a fullmatch (trailing-dot); a url with a closing quote is excluded.
    const emails = recordEntities(["email"], [["good@x.io"], ["good@x.io"], ["bad@y.io."]]);
    expect(has(emails, "email", "good@x.io")).toBe(true);
    expect(emails.some((e) => e.value === "bad@y.io.")).toBe(false);
    const urls = recordEntities(["url"], [["https://real.io/path"], ["https://real.io/path"], ['https://x.io"']]);
    expect(has(urls, "url", "https://real.io/path")).toBe(true);
    expect(urls.some((e) => e.value.includes('"'))).toBe(false);
  });
});

describe("mergeEntities — strictly additive union", () => {
  it("unions structured + flat, deduped by (type,value), preserving flat-path entities", () => {
    const structured: ExtractedEntity[] = [{ type: "handle", value: "ali_r99" }, { type: "email", value: "a@x.io" }];
    const flat: ExtractedEntity[] = [{ type: "email", value: "a@x.io" }, { type: "ip", value: "9.9.9.9" }];
    const merged = mergeEntities(structured, flat);
    expect(merged.filter((e) => e.value === "a@x.io").length).toBe(1); // deduped
    expect(has(merged, "handle", "ali_r99")).toBe(true); // structured gain kept
    expect(has(merged, "ip", "9.9.9.9")).toBe(true); // flat-path entity never dropped
  });
});
