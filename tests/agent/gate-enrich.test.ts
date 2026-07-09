import { describe, it, expect } from "vitest";
import { attributeFinding, promotionGate, type Observed, type Finding } from "../../src/agent/gate.js";

// m3-gate (codex D4/D5): once enrich providers feed the gate, two attribution traps open.
// D4: a provider echoing the QUERIED target back must not corroborate a finding about that same target
//     -> the loop marks the query echo self:true; attributeFinding skips self echoes.
// D5: a provider's person/handle echo must not satisfy the person gate -> infra credit is denied when
//     the MATCHED observed entity's own type is a PERSON type (a domain/ip/wallet match still credits).
// On the OLD gate both traps PROMOTE a weak finding; this is the negative self-test.

const obs = (provider: string, infra: boolean, entities: Observed["entities"]): Observed => ({ provider, infra, entities });

describe("m3-gate — self-echo + entity-type-aware infra credit", () => {
  it("a self:true query echo does not corroborate the finding (D4)", () => {
    const observed = [obs("enrich:shodan", true, [{ type: "ip", value: "8.8.8.8", self: true }])];
    const f = attributeFinding({ entity: "8.8.8.8", entity_type: "ip" }, observed);
    expect(f.source_count).toBe(0);
    expect(f.infra_source_count).toBe(0);
    expect(promotionGate(f).promote).toBe(false); // a self echo alone never promotes
  });

  it("a person-typed infra match gives NO infra credit, so the person gate still holds (D5)", () => {
    const observed = [obs("enrich:otx", true, [{ type: "person", value: "jane roe" }])];
    const f = attributeFinding({ entity: "Jane Roe", entity_type: "person" }, observed);
    expect(f.source_count).toBe(1); // counted as a (weak) source
    expect(f.infra_source_count).toBe(0); // but NOT infra — a person echo is not a non-fakeable crosslink
    expect(promotionGate(f).promote).toBe(false); // person with no infra crosslink stays a lead
  });

  it("a provider-confirmed ip (non-self, infra-typed) still promotes", () => {
    const observed = [obs("enrich:shodan", true, [{ type: "ip", value: "1.2.3.4" }])];
    const f = attributeFinding({ entity: "1.2.3.4", entity_type: "ip" }, observed);
    expect(f.source_count).toBe(1);
    expect(f.infra_source_count).toBe(1);
    const verdict = promotionGate(f);
    expect(verdict.promote).toBe(true);
    expect(verdict.grade).toBe("B");
  });

  it("two distinct infra providers on one ip grade A and promote", () => {
    const observed = [
      obs("enrich:shodan", true, [{ type: "ip", value: "1.2.3.4" }]),
      obs("enrich:censys", true, [{ type: "ip", value: "1.2.3.4" }]),
    ];
    const f = attributeFinding({ entity: "1.2.3.4", entity_type: "ip", confidence: "high" }, observed);
    expect(f.infra_source_count).toBe(2);
    expect(promotionGate(f).grade).toBe("A");
    expect(promotionGate(f).promote).toBe(true);
  });

  it("a non-self related entity (not the query echo) DOES corroborate", () => {
    // Shodan on 8.8.8.8 echoes the IP (self) but ALSO returns dns.google (a related, non-self domain).
    const observed = [
      obs("enrich:shodan", true, [
        { type: "ip", value: "8.8.8.8", self: true },
        { type: "domain", value: "dns.google" },
      ]),
    ];
    const f: Finding = attributeFinding({ entity: "dns.google", entity_type: "domain" }, observed);
    expect(f.source_count).toBe(1);
    expect(f.infra_source_count).toBe(1);
    expect(promotionGate(f).promote).toBe(true);
  });
});
