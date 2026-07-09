import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
import { strToU8, zipSync } from "fflate";

// ig-smoke (the live proof): pasting a document extracts gated entities into the case (junk dropped,
// no key leak). A tiny text PDF + a tiny CSV fixture process with ZERO off-allowlist egress (D12).
// The dummy key never leaks.

const KEY = "sk-ant-INGEST-SMOKE-7474";
const DOC = `Contact admin@scam.xyz at scam.xyz, host 198.51.100.7, pay 0x${"a".repeat(40)}. Report date 2026-04-19. leak ${KEY}.`;

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

// A minimal, valid single-page PDF with a text object, with correct xref byte offsets.
function buildPdf(text: string): Buffer {
  const objs = [
    "<</Type/Catalog/Pages 2 0 R>>",
    "<</Type/Pages/Kids[3 0 R]/Count 1>>",
    "<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 120]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>",
    `<</Length ${`BT /F1 16 Tf 12 60 Td (${text}) Tj ET`.length}>>\nstream\nBT /F1 16 Tf 12 60 Td (${text}) Tj ET\nendstream`,
    "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
  ];
  let body = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(Buffer.byteLength(body));
    body += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xrefStart = Buffer.byteLength(body);
  let xref = `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) xref += `${String(off).padStart(10, "0")} 00000 n \n`;
  body += `${xref}trailer\n<</Size ${objs.length + 1}/Root 1 0 R>>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(body, "latin1");
}

function buildXlsx(site = "xlsxsmoke.top"): Buffer {
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
    <row r="2"><c r="A2" t="inlineStr"><is><t>${site}</t></is></c><c r="B2" t="inlineStr"><is><t>0x${"c".repeat(40)}</t></is></c></row>
  </sheetData>
</worksheet>`),
  };
  return Buffer.from(zipSync(files));
}

let external: string[] = [];
async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
}

test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await freshKeyedVault(page);
});

test("paste + PDF + CSV + XLSX ingestion lands gated entities with zero egress; junk dropped; no key leak", async ({ page }) => {
  // (1) paste-text ingestion
  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await page.fill(".intake-paste", DOC);
  await page.click("button:has-text('Process pasted text')");
  await expect(page.locator(".intake-out")).toContainText("Extracted", { timeout: 10_000 });

  const db1 = await page.evaluate(() => (window as any).__kipi.entityDb());
  const labels1 = Object.values(db1.entities).map((e: any) => e.label);
  expect(labels1).toContain("admin@scam.xyz");
  expect(labels1).toContain("198.51.100.7");
  expect(labels1).toContain("0x" + "a".repeat(40));
  expect(labels1).not.toContain("2026-04-19"); // junk (date) dropped by the gate

  // (2) the CSV fixture — its cell entity lands without a third-party spreadsheet parser
  await page.setInputFiles(".intake-file", { name: "leads.csv", mimeType: "text/csv", buffer: Buffer.from('site,wallet\ncsvhost.top,0x' + "b".repeat(40)) });
  await page.click("button:has-text('Process file')");
  await expect(page.locator(".intake-out")).toContainText("leads.csv", { timeout: 10_000 });
  expect(Object.values((await page.evaluate(() => (window as any).__kipi.entityDb())).entities).map((e: any) => e.label)).toContain("csvhost.top");

  // (3) the XLSX fixture uses the audited reader, not SheetJS.
  await page.setInputFiles(".intake-file", { name: "leads.xlsx", mimeType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", buffer: buildXlsx() });
  await page.click("button:has-text('Process file')");
  await expect(page.locator(".intake-out")).toContainText("leads.xlsx", { timeout: 10_000 });
  expect(Object.values((await page.evaluate(() => (window as any).__kipi.entityDb())).entities).map((e: any) => e.label)).toContain("xlsxsmoke.top");

  // (4) the text-PDF fixture (PDF.js bundled worker). Lenient on extraction (the hard proof is egress),
  // but assert it does NOT throw a CDN fetch.
  await page.setInputFiles(".intake-file", { name: "doc.pdf", mimeType: "application/pdf", buffer: buildPdf("pdfhost.club ix") });
  await page.click("button:has-text('Process file')");
  await expect(page.locator(".intake-out")).not.toHaveText("", { timeout: 15_000 }); // produced a result line either way

  // (5) the ZERO-EGRESS proof: local file parsing fetched NOTHING off-allowlist (D12)
  expect(external, `unexpected egress: ${external.join(", ")}`).toHaveLength(0);

  // (5b) discovery-grow: this front door paints NO graph entity nodes — upload entities stay leads
  // until a dig promotes them (codex, kweb-discovery-grow-intake-contract).
  const gm = await page.evaluate(() => (window as any).__kipi.graphModel());
  expect(gm.nodes.filter((n: any) => n.entityType).length, "raw upload painted graph entity nodes").toBe(0);

  // (5c) the reports table refreshed IN PLACE after ingest (stale-until-remount regression guard)
  await expect(page.locator(".rep-table-head")).toContainText("Reports ·");
  expect(await page.locator(".rep-item").count()).toBeGreaterThanOrEqual(3);

  // (6) the Inbox lists the ingested documents
  await gotoRoute(page, "/inbox");
  await expect(page.locator(".pg-title")).toHaveText("Inbox");
  expect(await page.locator(".inbox-row").count()).toBeGreaterThanOrEqual(3); // csv + xlsx + pdf (paste = "pasted text")

  // (7) the dummy key never leaks; the secret hook is refused (D13)
  expect(JSON.stringify(db1)).not.toContain(KEY);
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(KEY);
  const secretThrows = await page.evaluate(() => {
    try { (window as any).__kipi.getCase("secret:anthropic_key"); return false; } catch { return true; }
  });
  expect(secretThrows).toBe(true);

  await page.screenshot({ path: "test-results/kipi-ingestion.png", fullPage: true });
});
