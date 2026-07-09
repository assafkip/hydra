import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { parseGraphCommand } from "../../src/chat/commands.js";
import { parseTradecraftCommand } from "../../src/chat/tradecraft.js";

// ccc-parity-harness (PRD prd-chat-control-center-2026-06-25): the un-gameable parity gate for the
// Chat Control Center redesign. parity-affordances.json pins every CURRENT affordance from the PRD's
// pinned ledger; this test proves each row still has a live home. A row PASSES iff at least one of its
// `proof` anchors is satisfied (OR semantics) against the SHIPPED sources + the live command router:
//   - "source"     : a substring (a DOM id / a bound handler / a render symbol) is present in `file`.
//   - "command"    : parseGraphCommand(phrase) resolves to `kind` — the chat command router (a
//                    chat-driven control resolves the phrase to its graph action).
//   - "tradecraft" : parseTradecraftCommand(phrase) resolves to `kind`.
// The manifest is frozen (only ccc-parity-harness's allowed_files include it). Issues 2-5 rehome
// affordances but CANNOT edit the manifest, so they must keep every row green: as the old home is
// deleted the contracted new home (a chat node card via renderNodeCard, a chat command via the router)
// satisfies the row instead. A row that goes red = a silently dropped affordance = the gate fails.
// "Renders the UI" is NOT enough — a row whose only home is deleted with no replacement fails here.

interface Anchor {
  type: "source" | "command" | "tradecraft";
  file?: string;
  contains?: string;
  phrase?: string;
  kind?: string;
}
interface Affordance {
  id: string;
  label: string;
  category: string;
  kind: string;
  source: string;
  proof: Anchor[];
}
interface Manifest {
  categories: string[];
  affordances: Affordance[];
}

const manifest = JSON.parse(
  readFileSync(new URL("../../parity-affordances.json", import.meta.url), "utf8"),
) as Manifest;

// Read each referenced source file ONCE (cache by relative path). A missing file is a hard failure —
// a proof can't anchor on a file that no longer exists.
const fileCache = new Map<string, string>();
function readSource(rel: string): string {
  if (!fileCache.has(rel)) {
    fileCache.set(rel, readFileSync(new URL("../../" + rel, import.meta.url), "utf8"));
  }
  return fileCache.get(rel)!;
}

/** True iff this single anchor is satisfied against the live sources / command router. */
function anchorSatisfied(a: Anchor): boolean {
  if (a.type === "source") {
    if (!a.file || !a.contains) return false;
    return readSource(a.file).includes(a.contains);
  }
  if (a.type === "command") {
    if (!a.phrase || !a.kind) return false;
    return parseGraphCommand(a.phrase)?.kind === a.kind;
  }
  if (a.type === "tradecraft") {
    if (!a.phrase || !a.kind) return false;
    return parseTradecraftCommand(a.phrase)?.kind === a.kind;
  }
  return false;
}

describe("parity manifest integrity", () => {
  it("has at least one affordance", () => {
    expect(manifest.affordances.length).toBeGreaterThan(0);
  });

  it("every affordance id is unique", () => {
    const ids = manifest.affordances.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every affordance has the required fields + at least one proof anchor", () => {
    for (const a of manifest.affordances) {
      expect(a.id, `id on ${JSON.stringify(a)}`).toBeTruthy();
      expect(a.label, `label on ${a.id}`).toBeTruthy();
      expect(a.category, `category on ${a.id}`).toBeTruthy();
      expect(a.source, `source on ${a.id}`).toBeTruthy();
      expect(Array.isArray(a.proof) && a.proof.length >= 1, `proof on ${a.id}`).toBe(true);
    }
  });

  it("every affordance's category is declared in the manifest categories list", () => {
    const declared = new Set(manifest.categories);
    for (const a of manifest.affordances) {
      expect(declared.has(a.category), `undeclared category '${a.category}' on ${a.id}`).toBe(true);
    }
  });

  it("every pinned-ledger category is represented by at least one affordance", () => {
    // The PRD's pinned affordance ledger — none may be absent from the manifest.
    const required = [
      "nav",
      "graph-controls",
      "lifecycle",
      "intake",
      "tradecraft",
      "node-card",
      "edge-card",
      "run-control",
      "run-path-ids",
      "cases",
      "search",
      "analyst-correct",
      "routes",
      "config",
    ];
    const present = new Set(manifest.affordances.map((a) => a.category));
    for (const cat of required) {
      expect(present.has(cat), `ledger category '${cat}' has no affordance row`).toBe(true);
    }
  });
});

describe("every affordance is preserved (>= 1 proof anchor satisfied) against the CURRENT app", () => {
  for (const a of manifest.affordances) {
    it(`${a.id} (${a.category}) — ${a.label}`, () => {
      const satisfied = a.proof.some(anchorSatisfied);
      expect(
        satisfied,
        `No proof anchor satisfied for '${a.id}'. The affordance has NO live home — a silent drop. ` +
          `Anchors: ${JSON.stringify(a.proof)}`,
      ).toBe(true);
    });
  }
});

describe("route completeness — every app.ts ROUTES entry has a parity row", () => {
  // Read the live ROUTES set from app.ts so a future route added without a parity row fails CI
  // (the silent-drop guard for the route map). Each route maps to the affordance id that covers it.
  const appTs = readSource("src/app.ts");
  const routesMatch = appTs.match(/const ROUTES = new Set\(\[([^\]]+)\]\)/);

  it("the ROUTES set is found in app.ts", () => {
    expect(routesMatch).toBeTruthy();
  });

  // route string -> the parity affordance id that proves it has a home.
  const routeToAffordance: Record<string, string> = {
    "/": "route-home",
    "/entities": "route-entities",
    "/clusters": "route-clusters",
    "/bridges": "route-bridges",
    "/focus": "route-focus",
    "/runs": "route-runs",
    "/deliverables": "route-deliverables",
    "/briefs": "route-briefs",
    "/cross-case": "route-cross-case",
    "/reports": "route-reports",
    "/tools": "route-tools",
    "/enrich": "config-osint",
    "/capabilities": "route-capabilities",
    "/full-tool": "route-full-tool",
    "/inbox": "route-inbox",
    "/cross-domain": "route-cross-domain",
    "/corrections": "route-corrections",
    "/activity": "route-activity",
    "/exports": "route-exports",
    "/report": "route-report",
    "/cases": "route-cases",
    "/alerts": "route-alerts",
    "/account": "config-account",
  };

  it("every route in app.ts ROUTES has a parity affordance that covers it", () => {
    const routes = [...routesMatch![1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    const byId = new Map(manifest.affordances.map((a) => [a.id, a]));
    for (const route of routes) {
      const affId = routeToAffordance[route];
      expect(affId, `route '${route}' has no parity mapping — add a row before adding the route`).toBeTruthy();
      expect(byId.has(affId), `route '${route}' maps to missing affordance '${affId}'`).toBe(true);
    }
  });
});
