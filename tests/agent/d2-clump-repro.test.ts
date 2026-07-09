import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { ingestText, graphModelForCase, entityDbFor } from "../../src/agent/session.js";

// D2 (prd-kipi-web-4points-investigator-parity / finding-3) + DISCOVERY-GROW (d2b98925, founder 2026-06-25,
// SUPERSEDES the prior "typed pivot board at ingest" decision): at ingest the document's entities are LEADS,
// not graph nodes. The original D2 fix dropped only the co-occurrence EDGE clump (54 edges → 0) but still
// rendered every extracted entity as a NODE — that node dump was "graph = extraction state", the bug
// d2b98925 names. Under discovery-grow the home graph contributes PROMOTED-ONLY from an intake record, so a
// raw upload (everything low-confidence) renders ZERO entity nodes; the entities are retained in the entity
// DB (/entities + /reports) and the coOccur SIGNAL is preserved on the record (it feeds the agent + Q&A
// relatedness). The graph grows only when a DIG promotes a lead.

async function freshVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  return Vault.unlock(storage, "pw");
}

// A FIFA-IC3-shaped doc: domain/URL/IP heavy (the scam-doc reality), a few off-class entities, and a
// mix of close-together and far-apart mentions — the same fixture that reproduced the 54-edge hairball.
const FIFA_DOC = [
  "Investigation into fifa-rewards.com and fifaworldcup-claim.net, both resolving to 104.21.5.9.",
  "Related domains observed: fifa2026-prize.org, claim-fifa.io, fifa-fan-token.com, worldcup-fifa.net.",
  "",
  "A separate cluster references gateway.fifapay.app and host 172.67.10.20 on a different page.",
  "",
  "The operator contact surfaced as support@fifa-rewards.com and a payout wallet 0x" + "b".repeat(40) + ".",
  "",
  "An unrelated paragraph mentions promo-cdn.net and assets.fifastatic.com with no other entities nearby.",
].join("\n");

describe("D2 + discovery-grow: an intake record contributes NO graph nodes; data retained", () => {
  it("renders ZERO entity nodes + ZERO edges at ingest; entities retained in the DB; coOccur signal preserved", async () => {
    const vault = await freshVault();
    const { objective } = await ingestText(vault, "fifa-ic3.txt", FIFA_DOC);

    const model = graphModelForCase(vault);
    expect(model).not.toBeNull();
    const m = model!;

    const entityNodes = m.nodes.filter((n) => n.kind !== "objective");
    // eslint-disable-next-line no-console
    console.log(`\n[D2/discovery-grow] graphNodes=${entityNodes.length} edges=${m.edges.length}\n`);

    // DISCOVERY-GROW (d2b98925, founder 2026-06-25): a raw upload (all low-confidence) promotes nothing, so
    // the intake record contributes ZERO entity nodes to the home graph — the node dump ("graph = extraction
    // state") is gone. The graph grows only when a DIG promotes a lead.
    expect(entityNodes.length).toBe(0);

    // Still zero edges (the intake co-occurrence hairball, was 54, stays gone).
    expect(m.edges.length).toBe(0);

    // Data is NOT lost — the extracted entities are retained as LEADS in the entity DB (/entities + /reports).
    const store = entityDbFor(vault);
    const dbLabels = Object.values(store.entities).map((e) => e.label);
    expect(dbLabels).toContain("fifa-rewards.com");
    expect(dbLabels.length).toBeGreaterThan(0);

    // The coOccur SIGNAL is NOT discarded: the run record still carries the proximity pairs, so the agent can
    // be told "the document hints these may be related — verify" and Q&A relatedness still works.
    const rec = vault.get(`run:${objective}`) as { coOccur?: Array<[string, string]> };
    expect(Array.isArray(rec.coOccur)).toBe(true);
    expect(rec.coOccur!.length).toBeGreaterThan(0);

    // No objective hub re-introduced by the projection.
    expect(m.nodes.some((n) => n.kind === "objective")).toBe(false);
  });
});
