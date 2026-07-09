// ig-files: file -> text, BUNDLED, ZERO CDN. PDF + OCR engines are DYNAMIC-imported
// (via injectable deps) so this module loads node-safe
// (vitest never pulls the DOM-dependent pdfjs/tesseract unless a real PDF/image is parsed). The PDF
// worker + the OCR assets are BUNDLED same-origin assets (Vite emits / scripts/copy-ocr-assets.mjs
// vendors them; served from 'self', allowed by the existing CSP) — NEVER a CDN (docs/17 F1).
//
// ocr-ingest (parity B1): an image (png/jpg/...) → OCR → text; a scanned (image-only) PDF page →
// render to canvas → OCR. The OCR engine + canvas render + pdf loader are INJECTABLE deps so the unit
// test runs node-safe with fakes (D10); the real recognize/render is proven by tests/smoke/ocr.spec.ts.

import { unzipSync, strFromU8 } from "fflate"; // clu-docx-and-empty-graph: bundled, zero-CDN unzip for .docx
import { imageToText as realImageToText, createOcrSession as realCreateOcrSession, type OcrInput, type OcrSession, type OcrProgressCb } from "./ocr.js";
import { recordEntities } from "./record.js"; // ig-record: structured CSV/XLSX column typing
import type { ExtractedEntity } from "./extract.js";

export interface FileText {
  text: string;
  kind: string; // pdf | image | docx | xlsx | csv | text | unsupported
  warnings?: string[]; // D9: structured (e.g. the OCR page cap) — surfaced in the intake UI, never console
  // ig-record: structured entities from a delimited file's typed columns (CSV/XLSX only). The caller
  // unions these with the flat-text extraction, so a person/handle column (no regex signature) lands.
  entities?: ExtractedEntity[];
}

/** A browser File, or a test double with name + arrayBuffer()/text(). */
export interface ReadableFile {
  name: string;
  type?: string;
  arrayBuffer(): Promise<ArrayBuffer>;
  text?(): Promise<string>;
}

// ---- injectable deps (node-safe seams; defaults are the real lazy engines) ----

// PDF engine seam (mupdf-swap 2026-06-22): NEUTRAL, engine-agnostic page shape. The old shape was
// pdf.js-specific (getTextContent items + canvas render); its fragment-join mangled text and DROPPED
// IOCs (FIFA report_id=6: 7 entities vs the server PyMuPDF's 12). MuPDF.js — Artifex's WASM build of
// the SAME C engine PyMuPDF wraps — is the single PDF chokepoint now. text() is structured-text;
// renderPNG() rasterizes an image-only page for the (unchanged) tesseract OCR fallback.
interface PdfPageLike {
  text(): Promise<string>;
  renderPNG(scale: number): Promise<Blob | null>;
  close?(): void; // release the underlying engine page (mupdf WASM objects must be freed explicitly)
}
interface PdfDocLike {
  numPages: number;
  getPage(n: number): Promise<PdfPageLike>; // 1-indexed (unchanged convention)
  close?(): void; // release the underlying engine document
}

export interface FileDeps {
  // clu-chat-intake: onProgress threads tesseract's multi-stage OCR progress out to the chat intake bar.
  imageToText: (input: OcrInput, onProgress?: OcrProgressCb) => Promise<string>;
  createOcrSession: (onProgress?: OcrProgressCb) => Promise<OcrSession>;
  loadPdf: (data: Uint8Array) => Promise<PdfDocLike>;
}

const IMAGE_EXT = new Set(["png", "jpg", "jpeg", "tif", "tiff", "webp", "bmp", "gif"]);
const TEXT_EXT = new Set(["txt", "text", "md", "markdown", "log", "json", "csv", "tsv"]);
const PDF_TEXT_LAYER_MIN = 16; // a page with < this many text-layer chars is treated as image-only
const MAX_PDF_OCR_PAGES = 10; // D8: bound the OCR fallback on a huge scan (cap surfaced as a warning)
const OCR_RENDER_SCALE = 2; // render at 2x for legible OCR
const MAX_RENDER_DIM = 2600; // D8: clamp the canvas so a giant page can't blow memory
const MAX_XLSX_BYTES = 2_000_000;
const MAX_XLSX_ROWS = 1_000;
const MAX_XLSX_COLS = 50;
const MAX_XLSX_CELL_CHARS = 2_000;

// mupdf-swap: the mupdf module is lazy-imported (node-safe until a PDF is parsed). Its WASM loads
// SAME-ORIGIN via mupdf's own `new URL("mupdf-wasm.wasm", import.meta.url)`, which Vite bundles as a
// hashed asset and fetches with credentials:"same-origin" — zero-CDN (docs/17 F1), the SAME mechanism
// the removed pdf.js worker used (files.ts previously). MuPDF renders without a DOM canvas, so the
// OCR-fallback render is headless (no `document` guard).
let mupdfMod: typeof import("mupdf") | null = null;
async function defaultLoadPdf(data: Uint8Array): Promise<PdfDocLike> {
  const mupdf = (mupdfMod ??= await import("mupdf"));
  const doc = mupdf.Document.openDocument(data, "application/pdf");
  return {
    numPages: doc.countPages(),
    async getPage(n: number): Promise<PdfPageLike> {
      const page = doc.loadPage(n - 1); // mupdf is 0-indexed; our convention is 1-indexed
      return {
        // toStructuredText().asText() === the server's PyMuPDF get_text("text") (the same C engine).
        // Every mupdf WASM object (stext, pixmap, page, doc) leaks heap until .destroy() — free in finally.
        async text(): Promise<string> {
          const stext = page.toStructuredText("preserve-whitespace");
          try {
            return stext.asText();
          } finally {
            stext.destroy();
          }
        },
        async renderPNG(scale: number): Promise<Blob | null> {
          const [x0, y0, x1, y1] = page.getBounds();
          const bounded = Math.min(scale, MAX_RENDER_DIM / Math.max(x1 - x0, y1 - y0, 1));
          const s = Math.max(bounded, 0.1);
          const pix = page.toPixmap(mupdf.Matrix.scale(s, s), mupdf.ColorSpace.DeviceRGB);
          try {
            return new Blob([pix.asPNG() as BlobPart], { type: "image/png" });
          } finally {
            pix.destroy();
          }
        },
        close(): void {
          page.destroy();
        },
      };
    },
    close(): void {
      doc.destroy();
    },
  };
}

const DEFAULT_DEPS: FileDeps = {
  // clu-chat-intake: pass onProgress through to the real engines (undefined langs → DEFAULT_OCR_LANGS).
  imageToText: (input, onProgress) => realImageToText(input, undefined, onProgress),
  createOcrSession: (onProgress) => realCreateOcrSession(undefined, onProgress),
  loadPdf: defaultLoadPdf,
};

// ---- text decoders ----

async function readText(file: ReadableFile): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new TextDecoder().decode(new Uint8Array(await file.arrayBuffer()));
}

// D16: only accept an unknown blob as text if it decodes to mostly-printable characters.
function looksLikeText(s: string): boolean {
  if (!s) return false;
  const sample = s.slice(0, 4096);
  let printable = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c !== 127)) printable++;
  }
  return printable / sample.length > 0.85;
}

/** PDF → text; an image-only page (empty/near-empty text layer) is rendered + OCR'd, bounded by
 *  MAX_PDF_OCR_PAGES and reported in `warnings` (D8/D9 — no console, no silent truncation). One OCR
 *  session is reused across all OCR'd pages (D6). */
async function pdfToText(file: ReadableFile, deps: FileDeps, onProgress?: OcrProgressCb): Promise<{ text: string; warnings: string[] }> {
  const data = new Uint8Array(await file.arrayBuffer());
  const pdf = await deps.loadPdf(data);
  const parts: string[] = [];
  const warnings: string[] = [];
  let session: OcrSession | null = null;
  let ocrPages = 0;
  let skipped = 0;
  try {
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      try {
        const text = await page.text();
        if (text.trim().length >= PDF_TEXT_LAYER_MIN) {
          parts.push(text);
          continue;
        }
        if (ocrPages >= MAX_PDF_OCR_PAGES) {
          skipped++;
          continue;
        }
        const img = await page.renderPNG(OCR_RENDER_SCALE);
        if (!img) continue; // render produced nothing → skip the OCR fallback for this page
        session = session ?? (await deps.createOcrSession(onProgress)); // clu-chat-intake: progress to the bar
        parts.push(await session.recognize(img));
        ocrPages++;
      } finally {
        page.close?.(); // free the engine page even if text/render/OCR throws
      }
    }
  } finally {
    if (session) await session.terminate();
    pdf.close?.(); // free the engine document
  }
  if (skipped > 0) warnings.push(`OCR page cap (${MAX_PDF_OCR_PAGES}) reached: ${skipped} image-only page(s) were not OCR'd.`);
  return { text: parts.join("\n"), warnings };
}

function delimitedRows(text: string): string[][] {
  const delimiter = (text.match(/\t/g)?.length ?? 0) > (text.match(/,/g)?.length ?? 0) ? "\t" : ",";
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') {
        quoted = false;
      } else {
        cell += ch;
      }
      continue;
    }
    if (ch === '"') quoted = true;
    else if (ch === delimiter) {
      row.push(cell.trim());
      cell = "";
    } else if (ch === "\n") {
      row.push(cell.trim());
      if (row.some((c) => c)) rows.push(row);
      row = [];
      cell = "";
    } else if (ch !== "\r") {
      cell += ch;
    }
  }
  row.push(cell.trim());
  if (row.some((c) => c)) rows.push(row);
  return rows;
}

function csvCell(s: string): string {
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function rowsToCsv(rows: string[][]): string {
  return rows.map((r) => r.map(csvCell).join(",")).join("\n");
}

// ig-record: structured typed entities from a CSV/TSV (header + rows -> typed columns -> cells). Empty
// when there is no header or no typed column; the caller still has the flat-text path.
function recordEntitiesFromRows(rows: string[][]): ExtractedEntity[] {
  try {
    if (rows.length < 2) return [];
    return recordEntities(rows[0], rows.slice(1));
  } catch {
    return []; // a parse failure degrades to flat-only extraction, never a crash
  }
}

// clu-docx-and-empty-graph: extract the paragraph TEXT from a .docx (a zip; the text lives in
// word/document.xml as <w:t> runs inside <w:p> paragraphs). Pure + node-safe (fflate is pure JS, no DOM)
// — the original tool supports docx, so the client must too or a dropped report silently extracts nothing.
function docxBodyText(bytes: Uint8Array): string {
  const zip = unzipSync(bytes, { filter: (f) => f.name === "word/document.xml" });
  const xml = zip["word/document.xml"];
  if (!xml) return "";
  return strFromU8(xml)
    .replace(/<w:tab\b[^>]*\/?>/g, " ") // a tab is a space
    .replace(/<\/w:p>/g, "\n") // paragraph end -> newline
    .replace(/<[^>]+>/g, "") // strip the remaining tags, leaving the <w:t> text content
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

const DOCX_IMG_EXT = new Set(["png", "jpg", "jpeg", "bmp", "tif", "tiff", "gif", "webp"]);

// A2b (parity with docx_ingest.py:_ocr_media): a Word report often pastes SCREENSHOTS into the
// body — the entities live in word/media/ images, not the <w:t> text. The original OCRs every
// embedded image and appends it; without this the client silently drops that text. Same OCR
// session-reuse + injectable-deps pattern as pdfToText (D6/D10) so it stays node-safe. recognize()
// takes bytes directly, so unlike a PDF page no canvas render is needed.
async function docxToText(bytes: Uint8Array, deps: FileDeps, onProgress?: OcrProgressCb): Promise<string> {
  const parts: string[] = [];
  const body = docxBodyText(bytes);
  if (body) parts.push(body);
  // Pull every embedded image (separate unzip pass; the body pass filters to document.xml only).
  const media = unzipSync(bytes, { filter: (f) => f.name.toLowerCase().startsWith("word/media/") && DOCX_IMG_EXT.has(extOf(f.name)) });
  const names = Object.keys(media).sort(); // deterministic order (codex parity: stable across runs)
  let session: OcrSession | null = null;
  try {
    for (const name of names) {
      session = session ?? (await deps.createOcrSession(onProgress));
      const text = (await session.recognize(media[name])).trim();
      if (text) parts.push(`\n[IMAGE ${name.split("/").pop()} (OCR)]\n${text}`);
    }
  } finally {
    if (session) await session.terminate();
  }
  return parts.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}

// CSV/TSV through a local parser. XLS/XLSX is intentionally unsupported until a safe parser is chosen.
async function csvToText(file: ReadableFile): Promise<{ text: string; entities: ExtractedEntity[] }> {
  const text = await readText(file);
  const rows = delimitedRows(text);
  return { text: rows.length ? rowsToCsv(rows) : text, entities: recordEntitiesFromRows(rows) };
}

async function xlsxToText(file: ReadableFile): Promise<{ text: string; entities: ExtractedEntity[]; warnings?: string[] }> {
  const data = await file.arrayBuffer();
  const bytes = data.byteLength;
  if (bytes > MAX_XLSX_BYTES) {
    return { text: "", entities: [], warnings: [`XLSX file cap (${Math.round(MAX_XLSX_BYTES / 1_000_000)} MB) exceeded.`] };
  }
  const { readSheet } = typeof document === "undefined"
    ? await import("read-excel-file/universal")
    : await import("read-excel-file/browser");
  const rawRows = await readSheet(data);
  const warnings: string[] = [];
  if (rawRows.length > MAX_XLSX_ROWS) warnings.push(`XLSX row cap (${MAX_XLSX_ROWS}) reached; extra rows were ignored.`);
  const rows = rawRows.slice(0, MAX_XLSX_ROWS).map((r) => {
    if (r.length > MAX_XLSX_COLS) warnings.push(`XLSX column cap (${MAX_XLSX_COLS}) reached; extra cells were ignored.`);
    return r.slice(0, MAX_XLSX_COLS).map((c) => {
      const s = c instanceof Date ? c.toISOString() : String(c ?? "");
      if (s.length > MAX_XLSX_CELL_CHARS) {
        warnings.push(`XLSX cell cap (${MAX_XLSX_CELL_CHARS} chars) reached; long cell text was truncated.`);
        return s.slice(0, MAX_XLSX_CELL_CHARS);
      }
      return s.trim();
    });
  }).filter((r) => r.some((c) => c));
  return { text: rowsToCsv(rows), entities: recordEntitiesFromRows(rows), warnings: [...new Set(warnings)] };
}

function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i < 0 ? "" : name.slice(i + 1).toLowerCase();
}

/** Decode a file to text by type. Bundled parsers only — nothing is fetched from a CDN. `deps` is
 *  injected by the unit test with fakes; production uses the real lazy OCR/pdf engines. */
export async function fileToText(file: ReadableFile, deps: FileDeps = DEFAULT_DEPS, onProgress?: OcrProgressCb): Promise<FileText> {
  const ext = extOf(file.name ?? "");
  if (ext === "pdf") {
    try {
      const { text, warnings } = await pdfToText(file, deps, onProgress);
      return warnings.length ? { text, kind: "pdf", warnings } : { text, kind: "pdf" };
    } catch (e) {
      // Do NOT swallow the reason: a PDF the engine can't read in-browser must SAY what broke (verified: MuPDF
      // reads text PDFs fine in node, so a browser failure is a real, diagnosable bug — not "just unsupported").
      return { text: "", kind: "unsupported", warnings: [`PDF read failed: ${e instanceof Error ? e.message : String(e)}`] };
    }
  }
  if (IMAGE_EXT.has(ext)) {
    try {
      const text = await deps.imageToText(await file.arrayBuffer(), onProgress);
      return { text, kind: "image" };
    } catch {
      return { text: "", kind: "unsupported" }; // an unreadable/corrupt image degrades honestly
    }
  }
  if (ext === "docx") {
    try {
      const text = await docxToText(new Uint8Array(await file.arrayBuffer()), deps, onProgress);
      return text.trim() ? { text, kind: "docx" } : { text: "", kind: "unsupported" }; // a .doc / empty docx degrades honestly
    } catch {
      return { text: "", kind: "unsupported" }; // a malformed/legacy .doc is not a zip
    }
  }
  if (ext === "xlsx") {
    try {
      const { text, entities, warnings } = await xlsxToText(file);
      return warnings?.length ? { text, kind: text.trim() ? "xlsx" : "unsupported", entities, warnings } : { text, kind: text.trim() ? "xlsx" : "unsupported", entities };
    } catch {
      return { text: "", kind: "unsupported" };
    }
  }
  if (ext === "xls" || ext === "xlsm") return { text: "", kind: "unsupported" };
  if (ext === "csv" || ext === "tsv") {
    const { text, entities } = await csvToText(file);
    return { text, kind: "csv", entities };
  }
  if (TEXT_EXT.has(ext)) return { text: await readText(file), kind: "text" };
  // unknown extension: accept ONLY if it decodes to mostly-printable text (D16)
  const txt = await readText(file).catch(() => "");
  return looksLikeText(txt) ? { text: txt, kind: "text" } : { text: "", kind: "unsupported" };
}
