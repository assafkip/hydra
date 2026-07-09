import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { REL_VOCAB, REL_SYNONYMS, normalizeRel, slugRel, evidenceRemap, isCleanToken, gloss } from "../../src/entity/rel-vocab.js";

// rel-vocab parity (INC-4a, codex P4): the TS vocab is an EXACT port of investigations/enrich/rel_vocab.py.
// This test reads the Python source and asserts term-for-term key parity, so the two enums cannot drift
// (no hardcoded count to chase). Plus the normalizeRel gate behavior (the two paths — codex P1).

function pythonRelVocabKeys(): string[] {
  const py = readFileSync(fileURLToPath(new URL("../../../investigations/enrich/rel_vocab.py", import.meta.url)), "utf8");
  // isolate the REL_VOCAB dict body, then pull each "key": at the start of a (possibly indented) line
  const block = py.slice(py.indexOf("REL_VOCAB: dict[str, str] = {"), py.indexOf("# Near-dupe"));
  const keys: string[] = [];
  for (const m of block.matchAll(/^\s{4}"([a-z0-9_]+)":/gm)) keys.push(m[1]);
  return keys;
}

describe("rel-vocab parity + gate (INC-4a)", () => {
  it("REL_VOCAB matches rel_vocab.py term-for-term (no drift, no padding)", () => {
    const pyKeys = pythonRelVocabKeys();
    expect(pyKeys.length).toBeGreaterThan(40); // sanity: the parse found the block
    expect(new Set(Object.keys(REL_VOCAB))).toEqual(new Set(pyKeys));
  });

  it("every REL_SYNONYMS value resolves to a vocab term", () => {
    for (const v of Object.values(REL_SYNONYMS)) expect(REL_VOCAB).toHaveProperty(v);
  });

  it("slugRel collapses punctuation/case/hyphens; non-string -> ''", () => {
    expect(slugRel("Drains To!")).toBe("drains_to");
    expect(slugRel("drains-to")).toBe("drains_to");
    expect(slugRel(42 as unknown)).toBe("");
  });

  it("normalizeRel: vocab term passes; synonym maps; co-occurrence flag drops", () => {
    expect(normalizeRel("resolves_to")).toBe("resolves_to");
    expect(normalizeRel("runs_on")).toBe("hosted_on"); // synonym
    expect(normalizeRel("flagged_malicious_alongside")).toBeNull(); // DROP_RELS
    expect(normalizeRel("anything_alongside")).toBeNull(); // _alongside suffix
    expect(normalizeRel(null)).toBeNull(); // empty slug
  });

  it("normalizeRel allowNovel=false: an unknown token generalizes to linked_to (codex P1)", () => {
    expect(normalizeRel("totally_made_up_label")).toBe("linked_to");
    expect(normalizeRel("found_via_search")).toBe("linked_to"); // found_via_ prefix
  });

  it("normalizeRel allowNovel=true: a clean schema label is KEPT as-is (codex P1)", () => {
    expect(normalizeRel("deployed", "", true)).toBe("deployed"); // per-case schema label survives
    expect(normalizeRel("totally_made_up_label", "", true)).toBe("totally_made_up_label");
    // but synonyms + drops STILL fire first on the novel path (junk can't ride in)
    expect(normalizeRel("runs_on", "", true)).toBe("hosted_on");
    expect(normalizeRel("flagged_malicious_alongside", "", true)).toBeNull();
  });

  it("normalizeRel: a vague label sharpens against the evidence text", () => {
    expect(normalizeRel("linked_to", "DNS A record resolves to 1.2.3.4")).toBe("resolves_to");
    expect(normalizeRel("linked_to", "shared ASN with the other domain")).toBe("shared_infra");
    expect(normalizeRel("linked_to", "no useful provenance here")).toBe("linked_to");
  });

  it("evidenceRemap + isCleanToken + gloss behave", () => {
    expect(evidenceRemap("registered by NameCheap")).toBe("registered_by");
    expect(isCleanToken("deployed")).toBe(true);
    expect(isCleanToken("123")).toBe(false); // all-digits rejected
    expect(gloss("drains_to")).toBe("drains funds to");
  });
});
