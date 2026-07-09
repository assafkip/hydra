import { describe, it, expect } from "vitest";
import { collapseObservedTwins, liveTypeRank } from "../../src/agent/gate.js";

// PRD live-graph-quality (Codex finding-1): the node-worthiness rule for live graph growth. A value a tool
// emits under multiple incompatible entity types in ONE observation is tooling noise — collapse it to one
// node by a fixed precedence; a real multi-entity cluster (distinct values) is untouched.

describe("collapseObservedTwins — live-graph worthiness", () => {
  it("collapses an A-record IP echoed as ip + nameserver + mailserver to the single ip node", () => {
    const observed = [
      { type: "ip", value: "93.184.216.34" },
      { type: "nameserver", value: "93.184.216.34" },
      { type: "mailserver", value: "93.184.216.34" },
    ];
    const out = collapseObservedTwins(observed);
    expect(out).toEqual([{ type: "ip", value: "93.184.216.34" }]); // precedence keeps ip, drops the twins
  });

  it("keeps the WHOLE same-operator cluster — distinct values are never collapsed", () => {
    // the 91.195.240.94 recruitment cluster: a shared IP + nameservers + registrar are DISTINCT values.
    const cluster = [
      { type: "ip", value: "91.195.240.94" },
      { type: "nameserver", value: "ns1kpv.name.com" },
      { type: "nameserver", value: "ns2kry.name.com" },
      { type: "registrar", value: "Name.com, Inc." },
      { type: "domain", value: "fifa-careerhub.com" },
    ];
    expect(collapseObservedTwins(cluster)).toEqual(cluster); // every distinct value survives
  });

  it("is case/precedence-correct and order-preserving", () => {
    const observed = [
      { type: "domain", value: "evil.com" },
      { type: "mailserver", value: "1.2.3.4" },
      { type: "ip", value: "1.2.3.4" }, // ip outranks mailserver for the same value, even though it is later
    ];
    expect(collapseObservedTwins(observed)).toEqual([
      { type: "domain", value: "evil.com" },
      { type: "ip", value: "1.2.3.4" },
    ]);
  });

  it("ranks structural types ahead of nameserver/mailserver; unknown types rank last", () => {
    expect(liveTypeRank("ip")).toBeLessThan(liveTypeRank("nameserver"));
    expect(liveTypeRank("domain")).toBeLessThan(liveTypeRank("mailserver"));
    expect(liveTypeRank("totally-unknown")).toBeGreaterThanOrEqual(liveTypeRank("mailserver"));
  });

  it("does NOT collapse a value whose colliding types are ALL unlisted (codex finding-1)", () => {
    // a person and a handle that happen to share a value are legitimately distinct, not tooling noise —
    // neither type is in the structural precedence list, so both must survive.
    const observed = [
      { type: "person", value: "shadowfax" },
      { type: "handle", value: "shadowfax" },
    ];
    expect(collapseObservedTwins(observed)).toEqual(observed);
  });

  it("collapses when a structural type collides with a junk twin, keeping the structural one", () => {
    const observed = [
      { type: "person", value: "1.2.3.4" }, // nonsense twin of a real IP
      { type: "ip", value: "1.2.3.4" },
    ];
    expect(collapseObservedTwins(observed)).toEqual([{ type: "ip", value: "1.2.3.4" }]);
  });

  it("leaves a single-type observation untouched (no false collapse)", () => {
    const observed = [
      { type: "domain", value: "a.com" },
      { type: "domain", value: "b.com" },
      { type: "ip", value: "5.6.7.8" },
    ];
    expect(collapseObservedTwins(observed)).toEqual(observed);
  });
});
