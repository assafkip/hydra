import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { ingestText, runProcess, graphModelForCase, entityDbFor, setApiKey } from "../../src/agent/session.js";
import type { FetchLike } from "../../src/osint/types.js";

// THE role-decision end-to-end smoke (founder 2026-06-24, [USER-DIRECTED]): a DOMAIN is NEVER `operator`,
// even an attacker-controlled spoof/lookalike — it is INFRASTRUCTURE (a square). `operator` is a PERSON /
// account only. This REVERSES the earlier "squares→circles" call (878f116a), which made spoof domains
// operator and, on a domain-heavy case like FIFA, turned EVERY node into an operator circle (the bug the
// founder reported). It drives the REAL front door — ingestText → runProcess (schema → consolidate → … the
// actual pipeline). The ONLY mocked boundary is the LLM judgment. The consolidate model here is made to
// return `operator` for the spoof domains (the exact bug) — the deterministic roleForType guard must coerce
// them to `infra` anyway.
//
// DISCOVERY-GROW UPDATE (d2b98925, founder 2026-06-25, supersedes the prior "labeled graph after auto-Process"
// behavior): an upload + auto-Process no longer populates the GRAPH — the graph is pure investigation state
// and grows only when a DIG promotes a lead. So the role guard is now asserted where the role actually lives
// after Process — the ENTITY DB (entityDbFor) — and we additionally assert the intake entities are NOT on the
// home graph (promoted-only). The infra→rectangle SHAPE map is covered by tests/graph/cy-adapter.test.ts.

function llm(text: string) {
  return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }], stop_reason: "end_turn", usage: {} }) };
}

const SPOOFS = new Set(["fifastore.us", "worldcup2026-tickets.com"]);

// Read the consolidate prompt's ENTITIES block. The model here MIS-classifies the spoof DOMAINS as
// `operator` (the exact pre-fix bug) — the deterministic guard in runProcess must override it to `infra`.
function classifyConsolidate(prompt: string): string {
  const m = prompt.match(/ENTITIES:\s*(\[[\s\S]*\])\s*$/);
  const ents: { id: string; label: string }[] = m ? JSON.parse(m[1]) : [];
  const groups = ents.map((e) =>
    SPOOFS.has(e.label)
      ? { ids: [e.id], role: "operator", sub_role: "infra_provider", confidence: "high", reason: "attacker-controlled lookalike domain" }
      : { ids: [e.id], role: "infra", sub_role: "", confidence: "high", reason: "legitimate impersonated brand host" },
  );
  return JSON.stringify({ groups });
}

const SCHEMA = JSON.stringify({
  domain: "FIFA World Cup ticket impersonation phishing",
  summary: "Lookalike domains impersonate FIFA to scam ticket buyers; the legit brand is fifa.com.",
  entity_types: [],
  roles: [
    { name: "operator", description: "the human actor / account behind the scam", actor: true, weight: 5 },
    { name: "infra", description: "any domain/host — the lookalikes and the legit FIFA host alike", actor: false, weight: 1 },
    { name: "noise", description: "registrar / CDN boilerplate", actor: false, weight: 0 },
  ],
  sub_roles: [{ name: "infra_provider", description: "hosts the scam" }],
  noise_notes: "Registrar and CDN boilerplate is noise.",
});

// One dispatching offline LLM: pick the response by which Process step's prompt this is.
function processFetch(): FetchLike {
  return (async (_url: string, init: { body?: unknown }) => {
    const body = JSON.parse(String(init.body ?? "{}"));
    const prompt = String(body.messages?.[0]?.content ?? "");
    if (/propose the ENTITY TYPES/i.test(prompt)) return llm(SCHEMA); // schema (autoModelSchema)
    if (/Canonical roles/i.test(prompt) && /ENTITIES:/.test(prompt)) return llm(classifyConsolidate(prompt)); // consolidate
    if (/refine each .*SURFACE type/i.test(prompt)) return llm(JSON.stringify({ types: [] })); // typing — no change
    if (/cluster/i.test(prompt)) return llm(JSON.stringify({ clusters: [], relationships: [] })); // analyze
    return llm("# Brief\nLookalike domains impersonate FIFA."); // synthesize / dossiers — harmless
  }) as unknown as FetchLike;
}

describe("auto-process end-to-end: a Processed DOMAIN is coerced to infra — domains are never operator", () => {
  async function freshVault(): Promise<Vault> {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    return Vault.unlock(storage, "pw");
  }

  it("ingest → runProcess (real pipeline): every domain = infra in the entity DB, even a model-tagged 'operator' spoof; graph stays empty (discovery-grow)", async () => {
    const vault = await freshVault();
    await setApiKey(vault, "sk-ant-test-key");
    // the REAL intake path — a report naming the legit brand + two attacker lookalikes
    await ingestText(
      vault,
      "fifa-scam-report.txt",
      "FIFA ticket scam alert. The official site is fifa.com. Fake stores fifastore.us and worldcup2026-tickets.com impersonate it to sell counterfeit World Cup tickets.",
    );

    const fetch = processFetch();
    await runProcess(vault, {
      wire: { schemaFetch: fetch, consolidateFetch: fetch, typeFetch: fetch, analyzeFetch: fetch, synthesizeFetch: fetch, dossierFetch: fetch },
    });

    // The role decision lands in the ENTITY DB (where Process writes roles): a DOMAIN is INFRA even when the
    // model tagged it `operator` — the deterministic roleForType guard coerces it. (infra→rectangle SHAPE is
    // covered by tests/graph/cy-adapter.test.ts.)
    const store = entityDbFor(vault);
    const role = (label: string): string | undefined =>
      Object.values(store.entities).find((e) => e.label === label)?.role;
    expect(role("fifastore.us")).toBe("infra");
    expect(role("worldcup2026-tickets.com")).toBe("infra");
    expect(role("fifa.com")).toBe("infra");

    // DISCOVERY-GROW (d2b98925, founder 2026-06-25): the intake entities are LEADS — present in the entity DB
    // (asserted above) but NOT dumped onto the home graph. The graph grows only when a DIG promotes a lead.
    const model = graphModelForCase(vault);
    const graphLabels = new Set((model?.nodes ?? []).map((n) => n.label));
    expect(graphLabels.has("fifastore.us")).toBe(false);
    expect(graphLabels.has("worldcup2026-tickets.com")).toBe(false);
    expect(graphLabels.has("fifa.com")).toBe(false);
  });
});
