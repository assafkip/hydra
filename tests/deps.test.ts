import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

// PRD cytoscape-graph cyg-deps (fable-discipline "declare and pin every new dependency"):
// every third-party graph package imported by src/graph/*.ts must be declared in
// kipi-web/package.json dependencies — so the bundle never relies on a transitive/CDN copy.
// The graph deps are the Cytoscape stack; this catches an undeclared/typo'd import.

const GRAPH_DIR = "src/graph";
// A bare specifier is third-party (not a relative ./path and not a node: builtin).
const IMPORT_RE = /(?:import|export)[^'"]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]/g;

function packageRoot(specifier: string): string {
  // "@scope/name/sub" -> "@scope/name"; "name/sub" -> "name"
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function thirdPartyImports(text: string): string[] {
  const out = new Set<string>();
  let m: RegExpExecArray | null;
  const re = new RegExp(IMPORT_RE.source, "g");
  while ((m = re.exec(text)) !== null) {
    const spec = m[1] ?? m[2];
    if (!spec || spec.startsWith(".") || spec.startsWith("node:")) continue;
    out.add(packageRoot(spec));
  }
  return [...out];
}

function declaredDeps(): Set<string> {
  const pkg = JSON.parse(readFileSync("package.json", "utf8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  return new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]);
}

// INC-4a (codex P5): the graph analytics import the graphology stack from src/entity/metrics.ts, which
// the src/graph scan above does not cover. Include it explicitly so a new/typo'd graphology import is
// caught by the same dependency-manifest proof (bundled, never a CDN/transitive copy).
const EXTRA_DEP_FILES = ["src/entity/metrics.ts"];

describe("graph dependency manifest", () => {
  it("every third-party import in src/graph/*.ts + the analytics modules is a declared dependency", () => {
    const deps = declaredDeps();
    const offenders: string[] = [];
    const files: string[] = [];
    if (existsSync(GRAPH_DIR)) for (const f of readdirSync(GRAPH_DIR).filter((n) => n.endsWith(".ts"))) files.push(join(GRAPH_DIR, f));
    for (const f of EXTRA_DEP_FILES) if (existsSync(f)) files.push(f);
    for (const f of files) {
      const text = readFileSync(f, "utf8");
      for (const spec of thirdPartyImports(text)) {
        if (!deps.has(spec)) offenders.push(`${f}: ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("declares the Cytoscape graph stack as runtime dependencies", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { dependencies?: Record<string, string> };
    const deps = pkg.dependencies ?? {};
    for (const p of ["cytoscape", "cytoscape-dagre", "dagre", "cytoscape-expand-collapse", "cytoscape-fcose", "layout-base", "cose-base"]) {
      expect(deps[p], `${p} must be a runtime dependency (bundled, not CDN)`).toBeTruthy();
    }
  });

  it("declares the graphology analytics stack as runtime dependencies (INC-4a, bundled not CDN)", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { dependencies?: Record<string, string> };
    const deps = pkg.dependencies ?? {};
    for (const p of ["graphology", "graphology-metrics", "graphology-communities-louvain"]) {
      expect(deps[p], `${p} must be a runtime dependency (bundled, not CDN)`).toBeTruthy();
    }
  });

  it("negative self-test: an undeclared specifier is detected", () => {
    // proves the membership check actually fails on a violation (not a rubber stamp)
    expect(thirdPartyImports(`import x from "totally-not-installed-pkg";`)).toContain("totally-not-installed-pkg");
    expect(declaredDeps().has("totally-not-installed-pkg")).toBe(false);
  });
});

// cl-copy (audit M4 / codex D2-D5): a 100%-CLIENT app has NO back-end store, so no src/ string may
// frame a feature as belonging to one. The forbidden phrases are built FROM FRAGMENTS (the `${BE}`
// token, never the literal) so this test file can never self-match, and ONLY src/ is scanned.
const BE = "server";
const FORBIDDEN = [`${BE} entity database`, `${BE} DB`, `${BE}-DB`, `${BE}-coupled`];

function srcTsFiles(dir = "src"): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) out.push(...srcTsFiles(p));
    else if (ent.name.endsWith(".ts")) out.push(p);
  }
  return out;
}

describe("no back-end-store framing in a 100%-client app (cl-copy)", () => {
  it("no src/ file frames a feature as belonging to a back-end store", () => {
    const offenders: string[] = [];
    for (const f of srcTsFiles("src")) {
      const text = readFileSync(f, "utf8").toLowerCase();
      for (const phrase of FORBIDDEN) {
        if (text.includes(phrase.toLowerCase())) offenders.push(`${f}: "${phrase}"`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("negative self-test: the scan detects a planted forbidden phrase", () => {
    const planted = `these come from the ${BE} entity database`; // built from fragments, not a literal
    expect(FORBIDDEN.some((p) => planted.toLowerCase().includes(p.toLowerCase()))).toBe(true);
  });
});
