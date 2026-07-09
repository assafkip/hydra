import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { strToU8, zipSync } from "fflate";
import { fileToText, type ReadableFile } from "../../src/ingest/files.js";

// ig-files (codex D14): a GENERIC third-party import manifest over ALL src/**/*.ts — so a new bundled
// dep can never be a transitive/undeclared/CDN copy. Plus the node-safe file->text
// paths (CSV/text/unsupported; PDF needs the DOM worker so it is a browser-smoke proof in ig-smoke).

const STATIC_RE = /(?:import|export)[^'"]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]/g;
const DYNAMIC_RE = /import\(\s*['"]([^'"]+)['"]\s*\)/g;
const NEWURL_RE = /new URL\(\s*['"]([^'".][^'"]+)['"]/g; // new URL("pkg/asset", import.meta.url)

function packageRoot(spec: string): string {
  const clean = spec.split("?")[0]; // strip ?url / ?worker
  const parts = clean.split("/");
  return clean.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function stripComments(text: string): string {
  // drop block + line comments so prose like "import.meta.url … from 'self'" is not mis-parsed.
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

function thirdPartySpecs(raw: string): string[] {
  const text = stripComments(raw);
  const out = new Set<string>();
  for (const re of [STATIC_RE, DYNAMIC_RE, NEWURL_RE]) {
    const r = new RegExp(re.source, "g");
    let m: RegExpExecArray | null;
    while ((m = r.exec(text)) !== null) {
      const spec = m[1] ?? m[2];
      if (!spec || spec.startsWith(".") || spec.startsWith("node:") || spec.startsWith("http")) continue;
      out.add(packageRoot(spec));
    }
  }
  return [...out];
}

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
}

function declaredDeps(): Set<string> {
  const pkg = JSON.parse(readFileSync("package.json", "utf8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  return new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]);
}

const enc = (s: string) => new TextEncoder().encode(s).buffer;

function xlsxFixture(site = "xlsxhost.top"): ArrayBuffer {
  const files: Record<string, Uint8Array> = {
    "[Content_Types].xml": strToU8(`<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`),
    "_rels/.rels": strToU8(`<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`),
    "xl/workbook.xml": strToU8(`<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>
</workbook>`),
    "xl/_rels/workbook.xml.rels": strToU8(`<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`),
    "xl/worksheets/sheet1.xml": strToU8(`<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="inlineStr"><is><t>site</t></is></c><c r="B1" t="inlineStr"><is><t>wallet</t></is></c></row>
    <row r="2"><c r="A2" t="inlineStr"><is><t>${site}</t></is></c><c r="B2" t="inlineStr"><is><t>0x${"b".repeat(40)}</t></is></c></row>
  </sheetData>
</worksheet>`),
  };
  const zipped = zipSync(files);
  return zipped.buffer.slice(zipped.byteOffset, zipped.byteOffset + zipped.byteLength);
}

describe("third-party import manifest (all src/**/*.ts)", () => {
  it("every third-party import/dynamic-import/new-URL specifier is a declared dependency", () => {
    const deps = declaredDeps();
    const files: string[] = [];
    walk("src", files);
    const offenders: string[] = [];
    for (const f of files) {
      for (const spec of thirdPartySpecs(readFileSync(f, "utf8"))) {
        if (!deps.has(spec)) offenders.push(`${f}: ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("mupdf + audited xlsx reader are declared and vulnerable SheetJS is absent", () => {
    // mupdf-swap: the PDF engine is mupdf (MuPDF.js WASM), declared + pinned so it is bundled
    // same-origin, never a transitive/CDN copy. pdfjs-dist was removed in the same change.
    const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { dependencies?: Record<string, string> };
    expect(pkg.dependencies?.["mupdf"]).toBeTruthy();
    expect(pkg.dependencies?.["pdfjs-dist"]).toBeFalsy();
    expect(pkg.dependencies?.["xlsx"]).toBeFalsy();
    expect(pkg.dependencies?.["read-excel-file"]).toBeTruthy();
  });

  it("negative self-test: an undeclared specifier is detected", () => {
    expect(thirdPartySpecs(`import x from "totally-not-installed-pkg";`)).toContain("totally-not-installed-pkg");
    expect(thirdPartySpecs(`const m = await import("another-missing-pkg/sub");`)).toContain("another-missing-pkg");
    expect(declaredDeps().has("totally-not-installed-pkg")).toBe(false);
  });
});

describe("fileToText — node-safe paths", () => {
  it("parses a quoted CSV locally and extracts the cell text", async () => {
    const file: ReadableFile = { name: "leads.csv", arrayBuffer: async () => enc('name,wallet\n"bob, jr",0x' + "a".repeat(40)), text: async () => 'name,wallet\n"bob, jr",0x' + "a".repeat(40) };
    const r = await fileToText(file);
    expect(r.kind).toBe("csv");
    expect(r.text).toContain("0x" + "a".repeat(40));
  });

  it("parses a bounded xlsx with the audited reader and extracts the cell text", async () => {
    const file: ReadableFile = { name: "leads.xlsx", arrayBuffer: async () => xlsxFixture() };
    const r = await fileToText(file);
    expect(r.kind).toBe("xlsx");
    expect(r.text).toContain("xlsxhost.top");
    expect(r.text).toContain("0x" + "b".repeat(40));
    expect(r.entities?.map((e) => e.value)).toContain("xlsxhost.top");
  });

  it("fails closed for legacy spreadsheet formats", async () => {
    const file: ReadableFile = { name: "leads.xlsm", arrayBuffer: async () => enc("not parsed") };
    const r = await fileToText(file);
    expect(r.kind).toBe("unsupported");
    expect(r.text).toBe("");
  });

  it("reads a plain text file", async () => {
    const file: ReadableFile = { name: "note.txt", arrayBuffer: async () => enc("hello evil.xyz"), text: async () => "hello evil.xyz" };
    const r = await fileToText(file);
    expect(r.kind).toBe("text");
    expect(r.text).toContain("evil.xyz");
  });

  it("an unknown binary blob -> unsupported (D16)", async () => {
    const bin = new Uint8Array([0, 1, 2, 3, 0, 255, 254, 0, 7, 8]).buffer;
    const file: ReadableFile = { name: "blob.bin", arrayBuffer: async () => bin };
    const r = await fileToText(file);
    expect(r.kind).toBe("unsupported");
    expect(r.text).toBe("");
  });
});
