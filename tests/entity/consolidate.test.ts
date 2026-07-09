import { describe, it, expect } from "vitest";
import {
  buildConsolidatePrompt,
  parseConsolidate,
  aliasMergeCandidates,
  buildTypingPrompt,
  parseTyping,
  roleForType,
  MAX_GROUP,
  CONSOLIDATE_ROLES,
  type Presented,
} from "../../src/entity/consolidate.js";

// ct-passes (codex D1-D6): the pure gate-faithful consolidate + typing passes. The model references
// entities ONLY by opaque presented ids; the parser validates ids against the presented set, unions
// overlapping merge groups into disjoint components, gates high-impact roles by confidence, canonicalizes
// against allowlists, and caps the output. None of this exists before this chunk (negative self-test).

const P = (id: string, value: string, type = "domain", role = "ioc", promoted = false): Presented => ({
  id,
  ref: { type, value },
  label: value,
  type,
  role,
  promoted,
});

// e0/e1 carry DISTINCT alias keys (h vs h2) so the deterministic alias prepass (added below) emits nothing
// for BASE — these LLM-path tests merge by id and must isolate the union-find/D1/D2/D4 logic, not the prepass.
const BASE: Presented[] = [P("e0", "@h", "handle", "ioc"), P("e1", "t.me/h2", "handle", "channel"), P("e2", "x.com", "domain", "ioc")];

const consol = (groups: unknown): string => JSON.stringify({ groups });
const typing = (types: unknown): string => JSON.stringify({ types });

describe("ct-passes — consolidate", () => {
  it("the prompt uses opaque ids + a JSON data block + an untrusted-data framing", () => {
    const prompt = buildConsolidatePrompt(BASE);
    expect(prompt).toContain('"e0"');
    expect(prompt).toContain("@h");
    expect(prompt.toLowerCase()).toContain("untrusted"); // D5: treat record fields as untrusted data
  });

  it("roleForType (founder 2026-06-24): an infra-typed entity is never operator from the AI pass", () => {
    // a domain/IP/URL classified `operator` by the model is coerced to infra (operator = people only)
    expect(roleForType("operator", "domain")).toBe("infra");
    expect(roleForType("operator", "subdomain")).toBe("infra");
    expect(roleForType("operator", "url")).toBe("infra");
    expect(roleForType("operator", "ip")).toBe("infra");
    expect(roleForType("operator", "nameserver")).toBe("infra");
    expect(roleForType("operator", "DOMAIN")).toBe("infra"); // case-insensitive
    // people/account types KEEP operator
    expect(roleForType("operator", "person")).toBe("operator");
    expect(roleForType("operator", "handle")).toBe("operator");
    expect(roleForType("operator", "username")).toBe("operator");
    // non-operator roles pass through untouched regardless of type
    expect(roleForType("infra", "domain")).toBe("infra");
    expect(roleForType("ioc", "wallet")).toBe("ioc");
    expect(roleForType("channel", "telegram_channel")).toBe("channel");
  });

  it("role decision (founder 2026-06-24): the prompt says operator = a PERSON/account, and a domain is infra (even a spoof)", () => {
    const prompt = buildConsolidatePrompt(BASE).toLowerCase();
    // the role decision: operator is human-only; a domain (incl. an attacker-controlled spoof) is infra.
    expect(prompt).toContain("human"); // operator = a human actor / account
    expect(prompt).toContain("never a domain"); // operator explicitly excludes domains
    expect(prompt).toContain("spoof"); // infra covers attacker-controlled spoof/lookalike domains
    expect(prompt).toContain("sub_role"); // the operator network-function instruction
  });

  it("A1: a per-case schema feeds the case domain + role definitions + sub_roles into the prompt", () => {
    const schema = {
      domain: "FIFA World Cup ticket/job impersonation phishing",
      summary: "Lookalike domains impersonate FIFA to scam ticket buyers and job seekers.",
      entityTypes: [],
      roles: [
        { name: "operator", description: "an attacker-operated lookalike/spoof domain or account", actor: true, weight: 5 },
        { name: "infra", description: "the legitimate impersonated FIFA brand's own hosts", actor: false, weight: 1 },
      ],
      subRoles: [{ name: "ticket_scam", description: "runs the fake ticket storefront" }],
      noiseNotes: "Registrar and CDN boilerplate is noise.",
    };
    const prompt = buildConsolidatePrompt(BASE, schema);
    expect(prompt).toContain("CASE DOMAIN: FIFA World Cup");
    expect(prompt).toContain("attacker-operated lookalike/spoof domain"); // the case's operator definition
    expect(prompt).toContain("legitimate impersonated FIFA brand"); // the case's infra definition
    expect(prompt).toContain("ticket_scam"); // sub_role category
    expect(prompt).toContain("Registrar and CDN boilerplate is noise"); // noise notes
  });

  it("A1 squares-fix: the prompt instructs FULL classification of EVERY entity (singletons), not just merges", () => {
    const prompt = buildConsolidatePrompt(BASE).toLowerCase();
    // the live bug: 'propose merge groups' meant a standalone spoof domain got NO role → infra → square.
    expect(prompt).toContain("classify"); // the main job is classification, not just merging
    expect(prompt).toContain("every entity"); // each entity gets a role
    expect(prompt).toContain("singleton"); // a standalone entity is a single-id group with its role
    expect(prompt).toContain("do not omit an entity"); // the explicit guard against the merge-only behavior
  });

  it("A1 squares-fix: a STANDALONE domain (no merge partner) classified operator is EMITTED (infra→operator)", () => {
    // a spoof domain presented with its roleFor default (infra); the LLM classifies it operator as a
    // single-id group. This is the exact live case (fifastore.us) that rendered as a square.
    const presented: Presented[] = [P("e0", "fifastore.us", "domain", "infra")];
    const out = parseConsolidate(
      consol([{ ids: ["e0"], role: "operator", sub_role: "infra_provider", confidence: "high", reason: "attacker-controlled lookalike" }]),
      presented,
    );
    expect(out).toHaveLength(1);
    expect(out[0].role).toBe("operator"); // the role CHANGE (infra→operator) survives → circle, not square
    expect(out[0].members[0].label).toBe("fifastore.us");
  });

  it("A1: a single-entity operator group that ASSIGNS a new sub_role is KEPT (not dropped as a no-op)", () => {
    // x.com is presented as role 'operator' already; a normal no-op singleton would be dropped, but a NEW
    // sub_role is real signal (the network function) — consolidate.py keeps single-entity sub_role clusters.
    const presented: Presented[] = [P("e0", "x.com", "domain", "operator")];
    const out = parseConsolidate(
      consol([{ ids: ["e0"], role: "operator", sub_role: "leadership", confidence: "high", reason: "crew lead" }]),
      presented,
    );
    expect(out).toHaveLength(1);
    expect(out[0].subRole).toBe("leadership");
  });

  it("A1: a single-entity group with role unchanged AND no sub_role is still dropped (no-op)", () => {
    const presented: Presented[] = [P("e0", "x.com", "domain", "operator")];
    const out = parseConsolidate(
      consol([{ ids: ["e0"], role: "operator", confidence: "high", reason: "no change" }]),
      presented,
    );
    expect(out).toEqual([]);
  });

  it("A1: parseConsolidate extracts sub_role for an operator group, empty for non-operator", () => {
    const out = parseConsolidate(
      consol([
        { ids: ["e2"], role: "operator", sub_role: "Leadership", confidence: "high", reason: "runs the spoof" },
        { ids: ["e0", "e1"], role: "channel", sub_role: "should_be_dropped", confidence: "high", reason: "alias" },
      ]),
      BASE,
    );
    const op = out.find((s) => s.role === "operator");
    const ch = out.find((s) => s.role === "channel");
    expect(op?.subRole).toBe("leadership"); // lowercased, carried
    expect(ch?.subRole).toBe(""); // a sub_role on a non-operator role is dropped (consolidate.py rule)
  });

  it("drops a group that cites an unknown id (D1)", () => {
    const out = parseConsolidate(consol([{ ids: ["e0", "e99"], role: "channel", confidence: "high", reason: "alias" }]), BASE);
    expect(out).toEqual([]);
  });

  it("unions overlapping groups into one disjoint component (D2)", () => {
    const out = parseConsolidate(
      consol([
        { ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "a" },
        { ids: ["e1", "e2"], role: "channel", confidence: "high", reason: "b" },
      ]),
      BASE,
    );
    expect(out).toHaveLength(1);
    expect(out[0].members.map((m) => m.id).sort()).toEqual(["e0", "e1", "e2"]);
  });

  it("drops a component whose source groups conflict on role (D2)", () => {
    const out = parseConsolidate(
      consol([
        { ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "a" },
        { ids: ["e1", "e2"], role: "operator", confidence: "high", reason: "b" },
      ]),
      BASE,
    );
    expect(out).toEqual([]); // conflicting roles on the merged component
  });

  it("gates a high-impact role (operator) to high confidence (D4)", () => {
    const low = parseConsolidate(consol([{ ids: ["e0", "e1"], role: "operator", confidence: "low", reason: "weak" }]), BASE);
    expect(low).toEqual([]);
    const high = parseConsolidate(consol([{ ids: ["e0", "e1"], role: "operator", confidence: "high", reason: "strong" }]), BASE);
    expect(high).toHaveLength(1);
    expect(high[0].role).toBe("operator");
  });

  it("drops an unknown role, keeps an allowlisted one", () => {
    expect(parseConsolidate(consol([{ ids: ["e0", "e1"], role: "banana", confidence: "high", reason: "x" }]), BASE)).toEqual([]);
    expect(parseConsolidate(consol([{ ids: ["e0", "e1"], role: "channel", confidence: "medium", reason: "x" }]), BASE)).toHaveLength(1);
  });

  it("drops a no-op singleton (role unchanged), keeps a changed-role singleton", () => {
    expect(parseConsolidate(consol([{ ids: ["e0"], role: "ioc", confidence: "high", reason: "same" }]), BASE)).toEqual([]);
    const changed = parseConsolidate(consol([{ ids: ["e0"], role: "channel", confidence: "high", reason: "reclass" }]), BASE);
    expect(changed).toHaveLength(1);
  });

  it("caps group size to MAX_GROUP (D6)", () => {
    const many: Presented[] = Array.from({ length: 12 }, (_, i) => P(`e${i}`, `d${i}.com`));
    const out = parseConsolidate(consol([{ ids: many.map((p) => p.id), role: "ioc", confidence: "high", reason: "all" }]), many);
    expect(out[0].members.length).toBe(MAX_GROUP);
  });

  it("malformed JSON -> []", () => {
    expect(parseConsolidate("not json at all", BASE)).toEqual([]);
    expect(parseConsolidate("{groups: [", BASE)).toEqual([]);
  });
});

// sp-f0d43a6a (founder-signed 2026-06-23): the CONTROLLED-VOCABULARY role taxonomy is a DELIBERATE
// divergence from the original, not a port gap. The original consolidate.py emits the per-case schema's
// role NAMES as output (understand.role_names(schema) → free-text like promoter/registrant); the client
// uses the schema roles only as bucketing GUIDANCE and keeps a FIXED 6-role canonical OUTPUT taxonomy
// (the squares-not-circles keystone + shape/color/D4/MISP all key off these 6). These tests PIN that
// contract deterministically (the parity-and-directives clause-4 mirror of the signed manifest note).
describe("controlled-vocabulary role taxonomy (sp-f0d43a6a, founder-signed)", () => {
  it("a schema's free-text role (promoter/registrant) threads into the prompt as bucketing GUIDANCE, but the canonical OUTPUT vocabulary stays the fixed 6", () => {
    const schema = {
      domain: "Crypto investment fraud",
      summary: "Promoters shill a fraudulent token; registrants own the lookalike domains.",
      entityTypes: [],
      roles: [
        { name: "promoter", description: "a person shilling the fraudulent token", actor: true, weight: 5 },
        { name: "registrant", description: "the domain registrant of record", actor: false, weight: 2 },
      ],
      subRoles: [],
      noiseNotes: "",
    };
    const prompt = buildConsolidatePrompt(BASE, schema);
    // the schema roles ARE used (NOT ignored) — they steer which canonical bucket the model picks:
    expect(prompt).toContain("promoter");
    expect(prompt).toContain("registrant");
    // but the OUTPUT vocabulary the model chooses from is the fixed canonical 6 (the divergence vs the
    // original, which outputs the schema's own role names). Scope to the "Canonical roles:" section so the
    // schema-guidance mentions above don't confuse the assertion.
    const canonicalSection = prompt.slice(prompt.indexOf("Canonical roles:"));
    for (const r of CONSOLIDATE_ROLES) expect(canonicalSection).toContain(`- ${r} —`);
    // NEGATIVE self-test: the free-text schema roles are NOT offered as canonical OUTPUT roles.
    expect(canonicalSection).not.toContain("- promoter —");
    expect(canonicalSection).not.toContain("- registrant —");
  });

  it("a model response emitting a schema free-text role is DROPPED (the closed output vocabulary holds), while the canonical bucket is kept and the nuance survives as sub_role", () => {
    // the original would STORE role='promoter'; the client buckets into the canonical 6, so 'promoter' is
    // dropped and the entity keeps no widened role — this IS the signed divergence, exercised end-to-end.
    const presented: Presented[] = [P("e0", "shiller.example", "domain", "infra")];
    const dropped = parseConsolidate(
      consol([{ ids: ["e0"], role: "promoter", confidence: "high", reason: "shills the token" }]),
      presented,
    );
    expect(dropped).toEqual([]); // promoter is outside the canonical 6 → dropped (output vocabulary holds)
    // the SAME entity classified into the canonical bucket IS kept, and the case-specific label is not lost:
    // it survives as the operator sub_role (the retained analog of the original's free-text role name).
    const kept = parseConsolidate(
      consol([{ ids: ["e0"], role: "operator", sub_role: "promoter", confidence: "high", reason: "shills the token" }]),
      presented,
    );
    expect(kept).toHaveLength(1);
    expect(kept[0].role).toBe("operator");
    expect(kept[0].subRole).toBe("promoter"); // the schema nuance is preserved as sub_role, not discarded
  });
});

// sp-71ec3a0a (A1.5): port the original consolidate.py _alias_key DETERMINISTIC prepass — '@x' (handle)
// and 't.me/x' (telegram_channel) are one actor by construction; the LLM batch demonstrably misses this
// merge, so code does it. ONLY the {handle, telegram_channel} bucket alias-merges; a handle must NEVER
// collapse into a same-named domain/wallet/person (the reason _norm_key keeps '@').
describe("ct-passes — deterministic alias prepass (consolidate.py _alias_key)", () => {
  it("merges @kambala_boss (handle) and t.me/kambala_boss (telegram_channel) with NO LLM call", () => {
    const presented: Presented[] = [
      P("e0", "@kambala_boss", "handle", "operator"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    const cands = aliasMergeCandidates(presented);
    expect(cands).toHaveLength(1);
    expect(cands[0].ids.sort()).toEqual(["e0", "e1"]);
    // composes through parseConsolidate even when the LLM returns NOTHING (empty groups):
    const out = parseConsolidate(JSON.stringify({ groups: [] }), presented);
    expect(out).toHaveLength(1);
    expect(out[0].members.map((m) => m.id).sort()).toEqual(["e0", "e1"]);
    // the merge survives the D4 high-impact gate: a pure alias merge uses the non-high-impact channel role.
    expect(out[0].role).toBe("channel");
  });

  it("strips telegram.me/ and a trailing slash too, case-folded (byte-faithful _alias_key)", () => {
    const presented: Presented[] = [
      P("e0", "@KAMBALA_BOSS", "handle", "operator"),
      P("e1", "https://telegram.me/kambala_boss/", "telegram_channel", "channel"),
    ];
    expect(aliasMergeCandidates(presented)).toHaveLength(1);
  });

  it("NEGATIVE: a @kambala handle does NOT merge with a kambala.com domain", () => {
    const presented: Presented[] = [
      P("e0", "@kambala", "handle", "operator"),
      P("e1", "kambala.com", "domain", "infra"),
    ];
    expect(aliasMergeCandidates(presented)).toEqual([]);
    const out = parseConsolidate(JSON.stringify({ groups: [] }), presented);
    expect(out).toEqual([]); // neither is alias-merged; no LLM groups => nothing
  });

  it("NEGATIVE: a @kambala handle does NOT merge with a wallet or person named kambala", () => {
    const presented: Presented[] = [
      P("e0", "@kambala", "handle", "operator"),
      P("e1", "kambala", "wallet", "ioc"),
      P("e2", "kambala", "person", "operator"),
    ];
    expect(aliasMergeCandidates(presented)).toEqual([]);
  });

  it("a lone alias-bucket entity (no twin) yields no candidate", () => {
    const presented: Presented[] = [P("e0", "@solo", "handle", "operator")];
    expect(aliasMergeCandidates(presented)).toEqual([]);
  });

  it("composes with an LLM merge without double-merging (union-find folds the deterministic + LLM groups)", () => {
    // the LLM independently merges the SAME pair; the union-find must yield ONE component, not two.
    const presented: Presented[] = [
      P("e0", "@kambala_boss", "handle", "operator"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    const out = parseConsolidate(
      JSON.stringify({ groups: [{ ids: ["e0", "e1"], role: "channel", confidence: "high", reason: "llm alias" }] }),
      presented,
    );
    expect(out).toHaveLength(1);
    expect(out[0].members.map((m) => m.id).sort()).toEqual(["e0", "e1"]);
  });

  it("alias edge is authoritative over conflicting LLM SINGLETON roles (codex High: the bench miss case)", () => {
    // The LLM MISSES the merge and classifies the pair as two singletons with DIFFERENT roles. The alias
    // edge asserts they are one entity, so the per-member singleton roles must NOT trigger the D2 drop —
    // the merge survives as the deterministic (channel) role, not dropped.
    const presented: Presented[] = [
      P("e0", "@kambala_boss", "handle", "operator"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    const out = parseConsolidate(
      consol([
        { ids: ["e0"], role: "operator", sub_role: "leadership", confidence: "high", reason: "the operator" },
        { ids: ["e1"], role: "channel", confidence: "high", reason: "a channel" },
      ]),
      presented,
    );
    expect(out).toHaveLength(1);
    expect(out[0].members.map((m) => m.id).sort()).toEqual(["e0", "e1"]);
    expect(out[0].role).toBe("channel");
  });

  it("a REAL LLM multi-merge that conflicts with the alias edge still drops (D2 genuine conflict)", () => {
    // The LLM merges e0 with a THIRD entity e2 as operator; the alias edge merges e0+e1 as channel. The
    // multi-group merge is a genuine identity claim, so the conflicting component is still dropped.
    const presented: Presented[] = [
      P("e0", "@kambala_boss", "handle", "operator"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
      P("e2", "kambala-boss.com", "domain", "operator"),
    ];
    const out = parseConsolidate(
      consol([{ ids: ["e0", "e2"], role: "operator", sub_role: "leadership", confidence: "high", reason: "same actor" }]),
      presented,
    );
    expect(out).toEqual([]); // operator(e0,e2) vs channel(e0,e1) — real conflict on a merged component
  });

  it("alias merge runs even when the LLM response is malformed/absent (codex Medium)", () => {
    const presented: Presented[] = [
      P("e0", "@kambala_boss", "handle", "operator"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    for (const bad of ["", "not json", "{", "{\"groups\": \"oops\"}"]) {
      const out = parseConsolidate(bad, presented);
      expect(out.map((s) => s.members.map((m) => m.id).sort())).toEqual([["e0", "e1"]]);
    }
  });

  it("never merges a real account into `noise`; skips an all-noise alias pair (codex Med/Low)", () => {
    // a noise-marked handle + a real telegram channel -> merge as channel, NOT noise.
    const mixed: Presented[] = [
      P("e0", "@kambala_boss", "handle", "noise"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    expect(aliasMergeCandidates(mixed)[0].role).toBe("channel");
    // a `source`-flagged handle is NOT buried as source either (codex round-2): merge as channel.
    const srcMixed: Presented[] = [
      P("e0", "@kambala_boss", "handle", "source"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    expect(aliasMergeCandidates(srcMixed)[0].role).toBe("channel");
    // an `ioc`-flagged (attacker-controlled) member IS preserved as ioc.
    const iocMixed: Presented[] = [
      P("e0", "@kambala_boss", "handle", "ioc"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "channel"),
    ];
    expect(aliasMergeCandidates(iocMixed)[0].role).toBe("ioc");
    // an all-INERT pair (every member noise OR source) -> no resurrection into a real comms role.
    const allNoise: Presented[] = [
      P("e0", "@kambala_boss", "handle", "noise"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "noise"),
    ];
    expect(aliasMergeCandidates(allNoise)).toEqual([]);
    const allSource: Presented[] = [
      P("e0", "@kambala_boss", "handle", "source"),
      P("e1", "t.me/kambala_boss", "telegram_channel", "source"),
    ];
    expect(aliasMergeCandidates(allSource)).toEqual([]);
  });
});

describe("ct-passes — typing", () => {
  it("the prompt uses opaque ids + an untrusted-data framing", () => {
    const prompt = buildTypingPrompt(BASE);
    expect(prompt).toContain('"e2"');
    expect(prompt.toLowerCase()).toContain("untrusted");
  });

  it("keeps only a known id + an allowlisted + changed surface type", () => {
    const out = parseTyping(typing([{ id: "e2", type: "url", confidence: "high", reason: "it is a url" }]), BASE);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: "e2", fromType: "domain", toType: "url" });
  });

  it("drops an unknown id, a non-allowlist type, and a no-op", () => {
    expect(parseTyping(typing([{ id: "e99", type: "url", confidence: "high", reason: "x" }]), BASE)).toEqual([]);
    expect(parseTyping(typing([{ id: "e2", type: "banana", confidence: "high", reason: "x" }]), BASE)).toEqual([]);
    expect(parseTyping(typing([{ id: "e0", type: "handle", confidence: "high", reason: "x" }]), BASE)).toEqual([]); // e0 already handle
  });

  it("malformed JSON -> []", () => {
    expect(parseTyping("garbage", BASE)).toEqual([]);
  });
});

// PRD-B typing-case-type: the typing pass now re-buckets each entity into the schema's case_type
// (port of typing.py retype_entities), distinct from the surface type. Each assertion has its negative.
describe("ct-passes — typing case_type (PRD-B)", () => {
  const schema = {
    domain: "crypto-fraud",
    summary: "a wallet-drainer ring",
    entityTypes: [
      { name: "scam_domain", description: "attacker lookalike payout site" },
      { name: "wallet_address", description: "payout wallet" },
    ],
    roles: [],
    subRoles: [],
    noiseNotes: "",
  };

  it("feeds the schema entity_types as the case_type vocabulary", () => {
    const prompt = buildTypingPrompt(BASE, schema);
    expect(prompt).toContain("case_type");
    expect(prompt).toContain("scam_domain"); // the schema vocabulary reached the prompt
    expect(prompt).toContain("CASE DOMAIN: crypto-fraud");
  });

  it("extracts case_type and KEEPS a case_type-only entry (no surface change)", () => {
    // e0 is already a handle (no surface change) but gets a case_type → kept.
    const out = parseTyping(typing([{ id: "e0", case_type: "channel_operator", confidence: "high", reason: "runs the tg channel" }]), BASE);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ id: "e0", caseType: "channel_operator" });
    // NEGATIVE: the SAME entry with no case_type and no surface change drops.
    expect(parseTyping(typing([{ id: "e0", confidence: "high", reason: "x" }]), BASE)).toEqual([]);
  });

  it("carries case_type alongside a surface-type change", () => {
    const out = parseTyping(typing([{ id: "e2", type: "url", case_type: "scam_domain", confidence: "high", reason: "x" }]), BASE);
    expect(out[0]).toMatchObject({ id: "e2", toType: "url", caseType: "scam_domain" });
  });

  it("coerces a non-schema case_type to 'other' when the schema vocabulary is supplied (typing.py parity)", () => {
    const vocab = ["scam_domain", "wallet_address"];
    // a value IN the vocab is kept; a value OUTSIDE it becomes 'other'.
    const kept = parseTyping(typing([{ id: "e0", case_type: "scam_domain" }]), BASE, vocab);
    expect(kept[0].caseType).toBe("scam_domain");
    const coerced = parseTyping(typing([{ id: "e0", case_type: "totally_made_up" }]), BASE, vocab);
    expect(coerced[0].caseType).toBe("other"); // negative: not kept verbatim
    // with NO vocab (no schema), the free-text label is kept as-is.
    const free = parseTyping(typing([{ id: "e0", case_type: "totally_made_up" }]), BASE);
    expect(free[0].caseType).toBe("totally_made_up");
  });
});
