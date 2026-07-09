import { describe, it, expect } from "vitest";
import {
  attributeFinding,
  attributeFindings,
  gradeFinding,
  isAdmissible,
  promotionGate,
  type Finding,
  type Observed,
} from "../../src/agent/gate.js";

const infra = (provider: string, type: string, value: string): Observed => ({
  provider,
  infra: true,
  entities: [{ type, value }],
});

describe("attribution: counts come from real tool results, not model trust", () => {
  it("scrubs a forged source_count/grade and recomputes from observed (none) -> D, lead", () => {
    const forged: Finding = { entity: "1.2.3.4", entity_type: "ip", source_count: 9, grade: "A", confidence: "high" };
    const f = attributeFinding(forged, []);
    expect(f.source_count).toBe(0);
    expect(f.infra_source_count).toBe(0);
    expect(f.grade).toBeUndefined();
    expect(gradeFinding(f)).toBe("D");
    expect(promotionGate(f).promote).toBe(false);
  });

  it("derives 2 infra confirmations from two infra tools -> grade A, promotes", () => {
    const finding: Finding = { entity: "sub.example.com", entity_type: "subdomain" };
    const observed = [
      infra("crt.sh", "subdomain", "sub.example.com"),
      infra("dns.google", "subdomain", "sub.example.com"),
    ];
    const f = attributeFinding(finding, observed);
    expect(f.source_count).toBe(2);
    expect(f.infra_source_count).toBe(2);
    expect(promotionGate(f)).toMatchObject({ promote: true, grade: "A" });
  });

  it("flags claim_unverified for a hard-fact entity no tool corroborates", () => {
    const f = attributeFinding({ entity: "5.5.5.5", entity_type: "ip" }, [infra("dns.google", "ip", "9.9.9.9")]);
    expect(f.claim_unverified).toBe(true);
    expect(promotionGate(f).promote).toBe(false);
  });

  it("strips a forged identity_anchor annotation", () => {
    const f = attributeFinding({ entity: "x.com", entity_type: "domain", identity_anchor: "match" }, []);
    expect(f.identity_anchor).toBeUndefined();
  });
});

// sp-918b0d0d: CLAIM-PROSE hard-token corroboration (port of investigator.py _attribute_findings'
// claim_unverified branch). Distinct from the hard-fact-ENTITY check above: here the entity itself is
// corroborated, but the finding's CLAIM asserts a date/IP/email/wallet that appears in NO tool result.
const infraWithText = (provider: string, type: string, value: string, text: string): Observed => ({
  provider,
  infra: true,
  text,
  entities: [{ type, value }],
});

describe("claim-prose hard-token corroboration (sp-918b0d0d)", () => {
  it("flags claim_unverified when a claim asserts a date that appears in NO tool result", () => {
    // The ENTITY (the domain) IS corroborated by an infra tool, so the entity path alone promotes it.
    // But the claim prose asserts "registered 2025-12-22" and no tool result text contains that date.
    const finding: Finding = {
      entity: "evil.com",
      entity_type: "domain",
      claim: "evil.com was registered 2025-12-22 by a privacy proxy.",
      confidence: "high",
    };
    const observed = [
      infraWithText("whois", "domain", "evil.com", '{"entities":[{"type":"domain","value":"evil.com"}],"note":"created 2024-01-01"}'),
    ];
    const f = attributeFinding(finding, observed);
    expect(f.claim_tokens).toBe(1); // the ISO date is the one hard token in the claim
    expect(f.claim_tokens_backed).toBe(0); // no tool result text contains 2025-12-22
    expect(f.claim_unverified).toBe(true);
    expect(promotionGate(f).promote).toBe(false); // gate holds it as a lead despite infra-confirmed entity
  });

  it("does NOT flag when the claimed hard token appears in a tool result", () => {
    const finding: Finding = {
      entity: "evil.com",
      entity_type: "domain",
      claim: "evil.com was registered 2025-12-22 by a privacy proxy.",
      confidence: "high",
    };
    const observed = [
      infraWithText("whois", "domain", "evil.com", '{"entities":[{"type":"domain","value":"evil.com"}],"note":"created 2025-12-22"}'),
    ];
    const f = attributeFinding(finding, observed);
    expect(f.claim_tokens).toBe(1);
    expect(f.claim_tokens_backed).toBe(1);
    expect(f.claim_unverified).toBeFalsy();
    expect(promotionGate(f).promote).toBe(true);
  });

  it("does not flag a soft claim with no hard token", () => {
    const finding: Finding = {
      entity: "evil.com",
      entity_type: "domain",
      claim: "evil.com is impersonating a real brand.",
      confidence: "high",
    };
    const observed = [infraWithText("whois", "domain", "evil.com", '{"entities":[{"type":"domain","value":"evil.com"}]}')];
    const f = attributeFinding(finding, observed);
    expect(f.claim_tokens).toBe(0);
    expect(f.claim_unverified).toBeFalsy();
    expect(promotionGate(f).promote).toBe(true);
  });

  it("does NOT falsely back a claimed IP that is only a SUBSTRING of a different observed IP (codex D — fail closed)", () => {
    // The tool saw 11.2.3.45; the claim asserts 1.2.3.4 (a substring of it but a DIFFERENT address).
    // Token-set membership must NOT back it (substring includes() wrongly would), so the gate holds.
    const finding: Finding = {
      entity: "evil.com",
      entity_type: "domain",
      claim: "evil.com resolves to 1.2.3.4.",
      confidence: "high",
    };
    const observed = [infraWithText("dns", "domain", "evil.com", '{"entities":[{"type":"ip","value":"11.2.3.45"}],"raw":"A 11.2.3.45"}')];
    const f = attributeFinding(finding, observed);
    expect(f.claim_tokens).toBe(1);
    expect(f.claim_tokens_backed).toBe(0);
    expect(f.claim_unverified).toBe(true);
    expect(promotionGate(f).promote).toBe(false);
  });

  it("scrubs a model-supplied claim_unverified:false (codex C — derived-trust fields come from us)", () => {
    // A soft claim (no hard token) with a model-asserted claim_unverified:false must not persist that
    // field; we only ever EMIT claim_unverified when our own logic earns it (true).
    const finding: Finding = {
      entity: "evil.com",
      entity_type: "domain",
      claim: "evil.com is a scam.",
      claim_unverified: false,
      claim_tokens: 9,
      confidence: "high",
    } as Finding;
    const observed = [infraWithText("whois", "domain", "evil.com", '{"entities":[{"type":"domain","value":"evil.com"}]}')];
    const f = attributeFinding(finding, observed);
    expect(f.claim_tokens).toBe(0); // recomputed from the claim, not the model's 9
    expect(f.claim_unverified).toBeFalsy();
  });

  it("attributeFindings (plural) precomputes the observed token set once and flags correctly", () => {
    const findings: Finding[] = [
      { entity: "evil.com", entity_type: "domain", claim: "registered 2025-12-22", confidence: "high" },
      { entity: "good.com", entity_type: "domain", claim: "registered 2024-01-01", confidence: "high" },
    ];
    const observed = [
      infraWithText("whois", "domain", "evil.com", '{"entities":[{"type":"domain","value":"evil.com"}],"raw":"created 2024-01-01"}'),
      infraWithText("whois", "domain", "good.com", '{"entities":[{"type":"domain","value":"good.com"}],"raw":"created 2024-01-01"}'),
    ];
    const [a, b] = attributeFindings(findings, observed);
    expect(a.claim_unverified).toBe(true); // 2025-12-22 in no result
    expect(b.claim_unverified).toBeFalsy(); // 2024-01-01 present
  });

  it("requires EVERY-token-missing? no — any one backed token clears the flag (matches Python `not backed`)", () => {
    // Claim asserts two hard tokens; one is in a tool result, one is not. Python sets
    // claim_unverified only when NONE are backed, so this must NOT flag.
    const finding: Finding = {
      entity: "evil.com",
      entity_type: "domain",
      claim: "evil.com resolves to 1.2.3.4 and was seen 2099-01-01.",
      confidence: "high",
    };
    const observed = [infraWithText("dns", "domain", "evil.com", '{"entities":[{"type":"ip","value":"1.2.3.4"}]}')];
    const f = attributeFinding(finding, observed);
    expect(f.claim_tokens).toBe(2);
    expect(f.claim_tokens_backed).toBe(1); // 1.2.3.4 is in the result; 2099-01-01 is not
    expect(f.claim_unverified).toBeFalsy();
  });
});

describe("grade (port of _grade_finding)", () => {
  it("A on 2 infra; A on 1 infra + high confidence", () => {
    expect(gradeFinding({ entity: "d", entity_type: "domain", source_count: 2, infra_source_count: 2 })).toBe("A");
    expect(
      gradeFinding({ entity: "d", entity_type: "domain", source_count: 1, infra_source_count: 1, confidence: "high" }),
    ).toBe("A");
  });
  it("B on 1 infra OR 2 sources; C on a single web source; D on none/unvalidated", () => {
    expect(gradeFinding({ entity: "d", entity_type: "domain", source_count: 1, infra_source_count: 1 })).toBe("B");
    expect(gradeFinding({ entity: "d", entity_type: "domain", source_count: 2, infra_source_count: 0 })).toBe("B");
    expect(gradeFinding({ entity: "d", entity_type: "domain", source_count: 1, infra_source_count: 0 })).toBe("C");
    expect(gradeFinding({ entity: "d", entity_type: "domain", source_count: 0 })).toBe("D");
    expect(
      gradeFinding({ entity: "d", entity_type: "domain", source_count: 5, infra_source_count: 5, unvalidated: true }),
    ).toBe("D");
  });
});

describe("admission parity (the one entity-admission contract)", () => {
  it("blocks junk classes", () => {
    expect(isAdmissible("domain", "@media screen")[0]).toBe(false); // CSS fragment
    expect(isAdmissible("url", "https://x/path\nconfidence: high")[0]).toBe(false); // control char
    expect(isAdmissible("indicatorx", "000000000")[0]).toBe(false); // all-same-digit
    expect(isAdmissible("trackingnum", "20260419")[0]).toBe(false); // YYYYMMDD date
    expect(isAdmissible("number", "260527")[0]).toBe(false); // YYMMDD date fragment (26-05-27) — the junk-node bug
    expect(isAdmissible("number", "123456")[0]).toBe(true); // a real 6-digit id (month 34 invalid) is NOT over-gated
    expect(isAdmissible("number", "100200")[0]).toBe(true); // a real 6-digit id (day 00 invalid) is NOT over-gated
    expect(isAdmissible("number", "120531")[0]).toBe(true); // a plausible order/ticket id (yy 12, not current decade) is NOT over-gated (codex)
    expect(isAdmissible("phone", "4029283844")[0]).toBe(false); // bare id, not a phone
    expect(isAdmissible("domain", "icann.org")[0]).toBe(false); // registry/reference boilerplate
    expect(isAdmissible("domain", "example.com'")[0]).toBe(false); // trailing-quote fragment
    expect(isAdmissible("email", "abuse@verisign.com")[0]).toBe(false); // reference-domain contact
    expect(isAdmissible("domain", "ab")[0]).toBe(false); // too short
    expect(isAdmissible("domain", "")[0]).toBe(false); // empty
  });

  it("rejects registry/registrar nameserver + mailserver noise, keeps target-specific infra (sp-d743695e)", () => {
    // the bug: isAdmissible only ran isNoiseDomain for DOMAINISH types, so a registrar nameserver typed
    // 'nameserver'/'mailserver' reached the graph. Now those types consult the same noise check.
    expect(isAdmissible("nameserver", "ns1.awsdns-53.org")[0]).toBe(false); // awsdns marker
    expect(isAdmissible("nameserver", "kim.ns.cloudflare.com")[0]).toBe(false); // ns.cloudflare.com marker
    expect(isAdmissible("nameserver", "whois.verisign-grs.com")[0]).toBe(false); // whois.* host
    expect(isAdmissible("mailserver", "mail.icann.org")[0]).toBe(false); // reference NOISE_DOMAIN (icann.org)
    // NOT over-gated: a target-specific nameserver in no noise list stays admissible (the real finding)
    expect(isAdmissible("nameserver", "ns1.trumpfundus.com")[0]).toBe(true);
    expect(isAdmissible("mailserver", "mx.target-corp.example")[0]).toBe(true);
  });

  it("gates multilingual-digit dates the same as ASCII (sp-f9d3c9ff, parity with admission.py)", () => {
    // admission.py's `digits.isdigit()` + `int()` are Unicode-aware, so a date written in Arabic-Indic,
    // Farsi, or fullwidth digits is gated server-side. The old TS guard `/^\d+$/` is ASCII-only, so the
    // same date slipped into the graph as a junk node client-side. Normalizing \p{Nd} → ASCII closes it.
    expect(isAdmissible("number", "٢٦٠٥٢٧")[0]).toBe(false); // Arabic-Indic 260527 (YYMMDD)
    expect(isAdmissible("number", "۲۶۰۵۲۷")[0]).toBe(false); // Farsi/Extended-Arabic 260527 (YYMMDD)
    expect(isAdmissible("number", "２６０５２７")[0]).toBe(false); // fullwidth 260527 (YYMMDD)
    expect(isAdmissible("trackingnum", "٢٠٢٦٠٤١٩")[0]).toBe(false); // Arabic-Indic 20260419 (YYYYMMDD)
    expect(isAdmissible("indicatorx", "٠٠٠٠٠٠")[0]).toBe(false); // Arabic-Indic all-same-digit placeholder
    // must NOT over-gate real multilingual 6-digit ids (same narrowing as ASCII):
    expect(isAdmissible("number", "١٢٣٤٥٦")[0]).toBe(true); // Arabic-Indic 123456 (month 34 invalid)
    expect(isAdmissible("number", "۱۲۰۵۳۱")[0]).toBe(true); // Farsi 120531 (yy 12, not current decade)
  });

  it("admits real entities (no false positives)", () => {
    expect(isAdmissible("domain", "example.com")[0]).toBe(true);
    expect(isAdmissible("ip", "9.9.9.9")[0]).toBe(true); // dotted-quad IP, NOT a bare number
    expect(isAdmissible("phone", "+1 (402) 928-3844")[0]).toBe(true); // formatted phone
    expect(isAdmissible("wallet", "00000000000000000000")[0]).toBe(true); // opaque-value type exempt
  });

  it("treats a multilingual-digit IPv4 as structural, not junk (sp-34441101 gap-3, parity with admission.py)", () => {
    // admission.py's _DOTTED_QUAD_RE uses Unicode `\d` + `int()`, so a dotted-quad written in a supported
    // OCR script (ara → Arabic-Indic, fas → Farsi, CJK → fullwidth) is recognized as a real IP and kept.
    // The ASCII-only TS regex missed it: the dot-strip then collapsed ١.١.١.١ → ١١١١ (all-same) and DROPPED
    // it as a placeholder — a data-loss divergence on a supported language. Now the quad check is \p{Nd}-aware
    // over the same 4 scripts toAsciiDigits handles (Python baseline verified: ١.١.١.١ junk=False).
    expect(isAdmissible("ip", "١.١.١.١")[0]).toBe(true); // Arabic-Indic 1.1.1.1
    expect(isAdmissible("ip", "۹.۹.۹.۹")[0]).toBe(true); // Farsi 9.9.9.9
    expect(isAdmissible("ip", "２５５.２５５.２５５.０")[0]).toBe(true); // fullwidth 255.255.255.0
    // an over-255 octet is not a valid quad → it falls to the bare-digit path; admission.py admits it too
    // (٩٩٩١١١ → yy 99 is not the current decade, so the YYMMDD gate does not fire) — parity, not a crash:
    expect(isAdmissible("ip", "٩٩٩.١.١.١")[0]).toBe(true); // Arabic-Indic 999.1.1.1 (octet > 255, matches Python)
  });

  it("rejects the 9 noise.py classes the first port leaked (A2 over-admission regression, 2026-06-22)", () => {
    // The inline gate.ts copy shipped a WEAKER noise list than investigations/noise.py: NANP-short
    // phones, registry switchboard numbers, the full registrar + reference domain lists, whois-prefix
    // and shared-nameserver hosts all leaked onto the graph. Proven 9/9 over-admissions vs admission.py.
    // Now sourced from the faithful ./noise.ts port.
    expect(isAdmissible("phone", "+1703925")[0]).toBe(false); // NANP must be 11 digits — truncated id
    expect(isAdmissible("phone", "+354 578 2030")[0]).toBe(false); // ISNIC registry switchboard
    expect(isAdmissible("domain", "namecheap.com")[0]).toBe(false); // registrar boilerplate
    expect(isAdmissible("domain", "godaddy.com")[0]).toBe(false); // registrar boilerplate
    expect(isAdmissible("domain", "krebsonsecurity.com")[0]).toBe(false); // threat-reporting outlet
    expect(isAdmissible("domain", "bleepingcomputer.com")[0]).toBe(false); // threat-reporting outlet
    expect(isAdmissible("domain", "whois.verisign-grs.com")[0]).toBe(false); // whois-server host
    expect(isAdmissible("domain", "ns1.domaincontrol.com")[0]).toBe(false); // shared nameserver
    expect(isAdmissible("email", "abuse@namecheap.com")[0]).toBe(false); // registrar contact email
  });

  it("does NOT over-reject real entities adjacent to the restored noise lists", () => {
    expect(isAdmissible("phone", "+1 (402) 928-3844")[0]).toBe(true); // full NANP 11-digit
    expect(isAdmissible("phone", "+44 20 7946 0958")[0]).toBe(true); // intl formatted
    expect(isAdmissible("domain", "parity-actor.com")[0]).toBe(true); // a real target domain
    expect(isAdmissible("domain", "ns-cloudflare.evil.com")[0]).toBe(true); // marker as a substring of a real label, host != marker
    expect(isAdmissible("phone", "+٩٨ ٢١ ٨٨٨ ٨٨٨٨")[0]).toBe(true); // Farsi/Arabic-Indic digits — kipi is multilingual (codex 2026-06-22)
  });

  it("does NOT crash on a forged/legacy record with a non-string entity_type/value (the latent crash)", () => {
    // a forged vault record can carry a number/object/null past the `string | undefined` type at runtime —
    // `?? ""` only guarded null/undefined, so `.trim()` used to throw + take down the whole entity-DB build.
    const forged: [unknown, unknown][] = [
      [123, "example.com"], [{ x: 1 }, "example.com"], [true, "example.com"], // non-string TYPE
      ["domain", 456], ["domain", { y: 2 }], // non-string VALUE
      [null, null], [undefined, undefined], [123, 456], // both non-string
    ];
    for (const [t, v] of forged) {
      expect(() => isAdmissible(t as string, v as string)).not.toThrow(); // the regression: no crash
    }
    // a non-string TYPE degrades to "" but a valid VALUE is still admissible (type just unknown)…
    expect(isAdmissible(123 as unknown as string, "example.com")[0]).toBe(true);
    // …while a non-string VALUE degrades to "" → empty → inadmissible.
    expect(isAdmissible("domain", 456 as unknown as string)[0]).toBe(false);
  });
});

describe("promotion gate floors", () => {
  it("admissible A/B promote", () => {
    expect(promotionGate({ entity: "1.2.3.4", entity_type: "ip", source_count: 2, infra_source_count: 2 }).promote).toBe(
      true,
    );
  });

  it("infra floor: a domain/IP with no infra confirmation is a lead, not a node", () => {
    const v = promotionGate({ entity: "evil.com", entity_type: "domain", source_count: 2, infra_source_count: 0 });
    expect(v.promote).toBe(false);
    expect(v.reason).toContain("no infra tool");
  });

  it("person floor: a person/handle with no non-fakeable crosslink is a capped lead", () => {
    const v = promotionGate({
      entity: "John Doe",
      entity_type: "person",
      source_count: 2,
      infra_source_count: 0,
      confidence: "high",
    });
    expect(v.promote).toBe(false);
    expect(v.grade).toBe("C"); // A/B downgraded to C without a crosslink
    expect(v.reason).toContain("non-fakeable crosslink");
  });

  it("person WITH an infra crosslink promotes", () => {
    const v = promotionGate({ entity: "jdoe", entity_type: "handle", source_count: 1, infra_source_count: 1 });
    expect(v.promote).toBe(true);
  });

  it("grade D / C land as leads", () => {
    expect(promotionGate({ entity: "x.com", entity_type: "domain", source_count: 0 }).promote).toBe(false);
    expect(
      promotionGate({ entity: "x.com", entity_type: "domain", source_count: 1, infra_source_count: 0 }).promote,
    ).toBe(false);
  });

  it("an inadmissible value is a lead even with a high grade", () => {
    const v = promotionGate({ entity: "@media", entity_type: "domain", source_count: 2, infra_source_count: 2 });
    expect(v.promote).toBe(false);
    expect(v.reason).toContain("not graphed");
  });

  it("prevalidated bypasses the bare-digits phone check (ig-extract D7) but not the date/junk guard", () => {
    // a bare labeled number: rejected by default, admitted when prevalidated
    expect(isAdmissible("phone", "5551234567")[0]).toBe(false);
    expect(isAdmissible("phone", "5551234567", true)[0]).toBe(true);
    // the universal-junk/date guard still applies even when prevalidated
    expect(isAdmissible("phone", "20260419", true)[0]).toBe(false); // YYYYMMDD date shape
  });
});
