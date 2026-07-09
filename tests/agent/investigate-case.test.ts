// A3 (port of investigator.py:investigate_case_agentic, max_passes=1): the WHOLE-CASE pass. One un-caged
// agent works EVERY seed; afterward the still-uninvestigated in-scope entities are surfaced as the analyst's
// recommendedPivots. Negative self-test: a fresh build had NO whole-case entry (only per-objective
// runInvestigation) — this drives the new investigateCase end-to-end with a scripted model + canned OSINT.

import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, ingestText, investigateCase, entityDbFor } from "../../src/agent/session.js";
import { allEntities } from "../../src/entity/db.js";
import type { FetchLike } from "../../src/osint/types.js";

// captures every request body so we can assert WHAT task the agent was handed (the whole-case roster prompt).
function scriptedAnthropic(bodies: string[]): FetchLike {
  const turns = [
    {
      content: [
        { type: "text", text: "Working the case — starting with the first seed." },
        // the tool INPUT names ONE roster seed → that seed counts as investigated (touchedValues).
        { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "seed-a.com" } },
      ],
      stop_reason: "tool_use",
      usage: { output_tokens: 10 },
    },
    {
      content: [{ type: "text", text: "Seed-a resolved; reporting. The other seeds still need work." }],
      stop_reason: "end_turn",
      usage: { output_tokens: 12 },
    },
  ];
  return (async (_url: string, init?: { body?: string }) => {
    if (init?.body) bodies.push(init.body);
    // PRD-B agent-completeness-stop: the loop now nudges the agent to keep digging when it surfaced a target
    // (here seed-a's resolved IP) it neither worked nor reported, so it may make MORE requests than scripted.
    // Tolerate the extra turn with an empty end_turn (the loop then plateaus + stops) — like loop.test's mock.
    return { ok: true, status: 200, json: async () => turns.shift() ?? { content: [], stop_reason: "end_turn", usage: {} } };
  }) as unknown as FetchLike;
}
function cannedOsint(): FetchLike {
  return (async (url: string) =>
    String(url).includes("dns.google")
      ? { ok: true, status: 200, json: async () => ({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }) }
      : { ok: false, status: 404, json: async () => ({}) }) as unknown as FetchLike;
}

async function caseVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, "sk-ant-CASE-KEY-1");
  // seed a 3-entity roster (the case's seeds) via the real ingest path.
  await ingestText(vault, "seeds.txt", "Targets: seed-a.com, seed-b.com, seed-c.com.");
  return vault;
}

describe("A3 — investigateCase (whole-case pass)", () => {
  it("builds a roster task naming every seed and runs ONE un-caged pass", async () => {
    const vault = await caseVault();
    const roster = allEntities(entityDbFor(vault, null)).map((e) => e.label);
    expect(roster).toContain("seed-a.com");
    expect(roster).toContain("seed-b.com");
    expect(roster).toContain("seed-c.com");

    const bodies: string[] = [];
    const result = await investigateCase({
      vault,
      fetchImpl: scriptedAnthropic(bodies),
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });

    expect(result.rosterSize).toBe(3);
    // the agent's TASK (first request body) is a WHOLE-CASE prompt naming >= 2 seeds (not a single target).
    const task = bodies[0] ?? "";
    expect(task.toLowerCase()).toContain("whole case");
    const named = ["seed-a.com", "seed-b.com", "seed-c.com"].filter((s) => task.includes(s));
    expect(named.length).toBeGreaterThanOrEqual(2);
  });

  it("returns the still-uninvestigated in-scope entities as recommendedPivots (touched 1 of 3 → 2 pivots)", async () => {
    const vault = await caseVault();
    const result = await investigateCase({
      vault,
      fetchImpl: scriptedAnthropic([]),
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });

    const pivotNames = result.recommendedPivots.map((p) => p.name).sort();
    // seed-a.com was queried (tool input) → investigated; the other two are the analyst's next moves.
    expect(pivotNames).toEqual(["seed-b.com", "seed-c.com"]);
    expect(result.recommendedPivots.some((p) => p.name === "seed-a.com")).toBe(false);
  });

  it("codex: touched honors NESTED target arrays + a target-field whitelist (no incidental-param suppression)", async () => {
    const vault = await caseVault();
    // tool input: a NESTED array target (seed-b worked via recursion) + seed-c in a NON-target 'note'
    // field (must NOT suppress its pivot). seed-a is never mentioned → also a pivot.
    const turns = [
      {
        content: [
          { type: "text", text: "Batch-resolving." },
          { type: "tool_use", id: "t1", name: "dns_lookup", input: { target: ["seed-b.com"], note: "seed-c.com" } },
        ],
        stop_reason: "tool_use",
        usage: { output_tokens: 8 },
      },
      { content: [{ type: "text", text: "done." }], stop_reason: "end_turn", usage: { output_tokens: 5 } },
    ];
    const fetchImpl = (async () => ({ ok: true, status: 200, json: async () => turns.shift() })) as unknown as FetchLike;
    const result = await investigateCase({ vault, fetchImpl, toolOpts: { fetchImpl: cannedOsint(), retries: 0 } });
    const pivots = result.recommendedPivots.map((p) => p.name).sort();
    expect(pivots).toEqual(["seed-a.com", "seed-c.com"]); // seed-b touched (nested target); seed-c's 'note' mention does NOT count
  });

  it("persists the pass under a readable whole-case label (NOT the long task), key-sanitized", async () => {
    const vault = await caseVault();
    const result = await investigateCase({
      vault,
      fetchImpl: scriptedAnthropic([]),
      toolOpts: { fetchImpl: cannedOsint(), retries: 0 },
    });
    expect(result.objective).toMatch(/^whole-case investigation #/);
    const persisted = vault.get(`run:${result.objective}`);
    expect(persisted).toBeTruthy();
    expect(JSON.stringify(persisted)).not.toContain("sk-ant-CASE-KEY-1");
  });
});
