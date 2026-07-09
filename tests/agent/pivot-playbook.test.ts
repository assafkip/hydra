import { describe, it, expect } from "vitest";
import { PERSONA } from "../../src/agent/persona.js";
import { OSINT_TOOLS, runTool } from "../../src/agent/tools.js";
import { investigate } from "../../src/agent/loop.js";
import { AnthropicClient } from "../../src/llm/client.js";
import { CAP_BYO_NOTE, CAP_DISCLOSURE_NOTE } from "../../src/osint/catalog.js";
import type { FetchLike } from "../../src/osint/types.js";

type Payload = { content: unknown[]; stop_reason: string; usage?: { output_tokens?: number } };
function scriptedClient(responses: Payload[]): AnthropicClient {
  const queue = [...responses];
  const impl = (async () => {
    const payload = queue.shift() ?? { content: [], stop_reason: "end_turn", usage: {} };
    return { ok: true, status: 200, json: async () => payload };
  }) as unknown as FetchLike;
  return new AnthropicClient("sk-ant-test", impl);
}

// Every net-new free provider tool this PRD added, grouped by the target kind it pivots from.
const NEW_TOOLS_BY_KIND: Record<string, string[]> = {
  ip: ["shodan_internetdb", "ripestat_network", "ip_guide", "ipwho_is", "stopforumspam_ip", "sans_isc_ip"],
  domain: ["certspotter_issuances", "hibp_breach_catalog"],
  address: ["blockstream_address", "blockcypher_address", "blockscout_address"],
  handle: ["github_user", "gitlab_user", "hackernews_user", "npm_user"],
  email: ["xposedornot_email", "disposable_email"],
  company: ["gleif_lei", "wikidata_entity"],
};

describe("pivot playbook (finding-4): the persona maps each target kind to the new tools", () => {
  it("the persona names every new provider tool as a pivot", () => {
    for (const tools of Object.values(NEW_TOOLS_BY_KIND)) {
      for (const t of tools) expect(PERSONA).toContain(t);
    }
  });
  it("the persona playbook names each target kind", () => {
    for (const kind of ["IP", "domain", "Bitcoin", "Ethereum", "handle", "email", "company"]) {
      expect(PERSONA).toContain(kind);
    }
  });
  it("every new tool is a registered, dispatchable OSINT_TOOL", () => {
    const names = new Set(OSINT_TOOLS.map((t) => t.name));
    for (const tools of Object.values(NEW_TOOLS_BY_KIND)) {
      for (const t of tools) expect(names.has(t)).toBe(true);
    }
  });
});

describe("capabilities disclosure surface (finding-4 privacy contract)", () => {
  it("CAP_BYO_NOTE (the rendered note) carries the per-target-kind browser-side disclosure", () => {
    expect(CAP_BYO_NOTE).toContain(CAP_DISCLOSURE_NOTE); // the disclosure actually ships in the rendered string
    expect(CAP_DISCLOSURE_NOTE).toContain("directly from your browser");
    // names a provider for each new target kind so a user sees which provider receives what
    for (const provider of ["GLEIF", "XposedOrNot", "GitHub", "Blockscout", "certspotter"]) {
      expect(CAP_DISCLOSURE_NOTE).toContain(provider);
    }
    expect(CAP_DISCLOSURE_NOTE).toContain("never proof"); // the breach-DB privacy caveat (finding-3) is stated here too
  });
});

describe("smoke: the agent picks + runs a NEW tool for a NEW target kind end-to-end", () => {
  // A scripted client that picks gleif_lei (the company target kind is net-new this PRD) on turn 1, then
  // emits the findings JSON on turn 2. Proves the full path: tool registered → picked → dispatched via the
  // REAL runTool (with a fake GLEIF fetch) → the typed org entity flows into a promoted finding.
  const gleifFetch = (async () =>
    ({
      ok: true,
      status: 200,
      json: async () => ({ data: [{ attributes: { lei: "HWUPKR0MPOU8FGXBT394", entity: { legalName: { name: "Apple Inc." } } } }] }),
    })) as unknown as FetchLike;

  it("picks gleif_lei on a company objective and surfaces the typed org finding", async () => {
    const client = scriptedClient([
      { content: [{ type: "tool_use", id: "t1", name: "gleif_lei", input: { company: "Apple Inc." } }], stop_reason: "tool_use", usage: { output_tokens: 10 } },
      {
        content: [
          {
            type: "text",
            text: '```json\n{"findings":[{"entity":"Apple Inc.","entity_type":"org","confidence":"high","claim":"GLEIF LEI registry record"}],"relationships":[]}\n```',
          },
        ],
        stop_reason: "end_turn",
        usage: { output_tokens: 20 },
      },
    ]);
    const r = await investigate({
      objective: "identify the company Apple Inc.",
      client,
      runTool: (name, input) => runTool(name, input, { fetchImpl: gleifFetch, retries: 0 }),
    });
    // the new tool actually executed in the loop for the new company target kind.
    expect(r.steps.some((s) => s.kind === "tool" && (s as { tool?: string }).tool === "gleif_lei")).toBe(true);
    // and its typed org finding survived to promoted or leads.
    const allEntities = [...r.promoted.map((f) => f.entity), ...r.leads.map((l) => l.finding.entity)];
    expect(allEntities).toContain("Apple Inc.");
  });
});
