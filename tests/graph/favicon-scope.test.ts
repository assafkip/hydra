import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { modelToElements } from "../../src/graph/cy-adapter.js";
import type { GraphModel } from "../../src/graph/model.js";

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...sourceFiles(p));
    else if (/\.(ts|tsx|js|mjs)$/.test(name)) out.push(p);
  }
  return out;
}

function node(over: Partial<GraphModel["nodes"][number]> & { id: string; label: string; kind: any }) {
  return { promoted: false, ...over } as GraphModel["nodes"][number];
}

describe("favicon scope", () => {
  it("keeps the raw Google favicon host scoped to src/graph/favicon.ts", () => {
    const hits = sourceFiles("src")
      .filter((file) => readFileSync(file, "utf8").includes("t0.gstatic.com"))
      .map((file) => relative(process.cwd(), file).replaceAll("\\", "/"));

    expect(hits).toEqual(["src/graph/favicon.ts"]);
  });

  it("renders favicons only for confirmed or intake web-host nodes", () => {
    const objective = node({ id: "objective", label: "o", kind: "objective" });
    const confirmed = node({ id: "confirmed", label: "confirmed.example", kind: "finding", promoted: true, entityType: "domain" });
    const intake = node({ id: "intake", label: "intake.example", kind: "finding", promoted: false, origin: "intake", entityType: "domain" });
    const lead = node({ id: "lead", label: "lead.example", kind: "lead", promoted: false, origin: "osint", entityType: "domain" });
    const ip = node({ id: "ip", label: "1.2.3.4", kind: "finding", promoted: true, entityType: "ip" });

    const data = Object.fromEntries(
      modelToElements({ objective: "o", nodes: [objective, confirmed, intake, lead, ip], edges: [] })
        .nodes.map((n) => [n.data.id, n.data]),
    );

    expect(data.confirmed.thumbnail).toContain("https://t0.gstatic.com/faviconV2");
    expect(data.intake.thumbnail).toContain("https://t0.gstatic.com/faviconV2");
    expect(data.lead.thumbnail).toBeUndefined();
    expect(data.ip.thumbnail).toBeUndefined();
  });
});
