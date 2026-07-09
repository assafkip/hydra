import { describe, it, expect } from "vitest";
import { AI_DOSSIER_PERSONA, buildDossierPrompt, parseDossier } from "../../src/entity/dossier.js";
import type { Connection, EntityRecord } from "../../src/entity/db.js";

// adr-pass: the AI dossier grounds ONLY on the gated entity DB and STRIPS any fabricated source
// the model emits (the dossier has no real URLs/reports to cite — codex D3).

function entity(over: Partial<EntityRecord> = {}): EntityRecord {
  return {
    ref: { type: "domain", value: "evil.com" },
    label: "evil.com",
    type: "domain",
    role: "infra",
    promoted: true,
    grade: "A",
    sourceCount: 2,
    infraSourceCount: 2,
    runs: ["Investigate evil.com", "Probe the ring"],
    reasons: [],
    ...over,
  };
}

function conn(otherValue: string): Connection {
  return {
    other: { type: "ip", value: otherValue },
    otherLabel: otherValue,
    otherType: "ip",
    otherRole: "infra",
    relType: "co_occurs",
    direction: "undirected",
    confidence: "medium",
    runs: ["Investigate evil.com"],
    count: 1,
  };
}

describe("AI_DOSSIER_PERSONA", () => {
  it("is frozen + timestamp-free (so the cache prefix is stable)", () => {
    expect(AI_DOSSIER_PERSONA).not.toMatch(/\d{4}-\d{2}-\d{2}/); // no date
    expect(AI_DOSSIER_PERSONA).toContain("unattributed");
    expect(AI_DOSSIER_PERSONA).toContain("no web access and no tools");
  });
});

describe("buildDossierPrompt", () => {
  it("grounds on the entity facts + the allowed sources + the connections + the four headers", () => {
    const p = buildDossierPrompt(entity(), [conn("1.1.1.1")]);
    expect(p).toContain("ENTITY: evil.com");
    expect(p).toContain("GRADE: A");
    expect(p).toContain('ALLOWED SOURCES'); // the run-label whitelist
    expect(p).toContain('"Investigate evil.com"');
    expect(p).toContain("1.1.1.1"); // the connection
    expect(p).toContain("## Summary");
    expect(p).toContain("## Open questions");
  });
  it("a held lead surfaces its reason; an empty-connections entity still builds a valid prompt", () => {
    const p = buildDossierPrompt(entity({ promoted: false, reasons: ["web-recall only — no infra tool confirmed this"] }), []);
    expect(p).toContain("HELD BECAUSE: web-recall only");
    expect(p).toContain("(none)");
  });
});

describe("parseDossier (fabricated-source stripping — codex D3)", () => {
  it("strips a wrapping fence, trims, caps", () => {
    expect(parseDossier("```markdown\n## Summary\nhi\n```")).toBe("## Summary\nhi");
    expect(parseDossier("  hi  ")).toBe("hi");
    expect(parseDossier("x".repeat(20000)).length).toBe(8000);
  });
  it("removes a fabricated 'Source:' citation line", () => {
    const out = parseDossier("## Summary\nReal claim.\nSource: http://evil-fabricated.example\nMore.");
    expect(out).not.toContain("evil-fabricated");
    expect(out).not.toMatch(/^source:/im);
    expect(out).toContain("Real claim.");
  });
  it("replaces a bare hallucinated URL with a placeholder", () => {
    const out = parseDossier("See more at http://made-up.example/page for details.");
    expect(out).not.toContain("made-up.example");
    expect(out).toContain("[external link removed]");
  });
});
