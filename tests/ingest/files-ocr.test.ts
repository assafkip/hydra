import { describe, it, expect } from "vitest";
import { fileToText, type FileDeps, type ReadableFile } from "../../src/ingest/files.js";

// ocr-ingest: image files OCR to text; an image-only PDF page renders + OCRs; a text-layer page does
// NOT; the OCR fallback is page-capped with a structured warning. All driven by injected fakes so the
// unit stays node-safe (no real tesseract/mupdf/WASM) — the real engine is the live ocr-smoke.
// mupdf-swap: the neutral PDF page exposes text() + renderPNG() (no pdf.js getTextContent/canvas).

const fileOf = (name: string): ReadableFile => ({ name, arrayBuffer: async () => new ArrayBuffer(8) });

function deps(over: Partial<FileDeps> = {}): FileDeps {
  return {
    imageToText: async () => "IMG OCR",
    createOcrSession: async () => ({ recognize: async () => "PAGE OCR", terminate: async () => {} }),
    loadPdf: async () => ({ numPages: 0, getPage: async () => textPage("") }),
    ...over,
  };
}
// neutral page: text() is the structured text; renderPNG() rasterizes for the OCR fallback. A null
// renderPNG models a render that produced nothing (the page is then skipped, no crash).
function textPage(str: string, renderPng: Blob | null = new Blob([new Uint8Array([1, 2, 3])])) {
  return {
    text: async () => str,
    renderPNG: async () => renderPng,
  };
}
const docOf = (pages: ReturnType<typeof textPage>[]) => ({ numPages: pages.length, getPage: async (n: number) => pages[n - 1] });

describe("fileToText OCR wiring", () => {
  it("an image file dispatches to imageToText -> kind 'image'", async () => {
    const r = await fileToText(fileOf("shot.png"), deps());
    expect(r.kind).toBe("image");
    expect(r.text).toBe("IMG OCR");
  });

  it("an image-only PDF page triggers the OCR fallback", async () => {
    const d = deps({ loadPdf: async () => docOf([textPage("")]) });
    const r = await fileToText(fileOf("scan.pdf"), d);
    expect(r.kind).toBe("pdf");
    expect(r.text).toContain("PAGE OCR");
  });

  it("a PDF page WITH a text layer is NOT OCR'd", async () => {
    let ocrCalls = 0;
    const d = deps({
      loadPdf: async () => docOf([textPage("this page has a real text layer with plenty of characters")]),
      createOcrSession: async () => ({ recognize: async () => { ocrCalls++; return "X"; }, terminate: async () => {} }),
    });
    const r = await fileToText(fileOf("doc.pdf"), d);
    expect(r.text).toContain("real text layer");
    expect(ocrCalls).toBe(0);
  });

  it("the OCR page cap holds and emits a structured warning (no console)", async () => {
    let ocrCalls = 0;
    const d = deps({
      loadPdf: async () => docOf(Array.from({ length: 12 }, () => textPage(""))),
      createOcrSession: async () => ({ recognize: async () => { ocrCalls++; return "P"; }, terminate: async () => {} }),
    });
    const r = await fileToText(fileOf("big-scan.pdf"), d);
    expect(ocrCalls).toBe(10); // MAX_PDF_OCR_PAGES
    expect((r.warnings ?? []).join(" ")).toMatch(/page cap/i);
  });

  it("when renderPNG yields nothing (null), the image-only page is skipped, no crash", async () => {
    const d = deps({ loadPdf: async () => docOf([textPage("", null)]) });
    const r = await fileToText(fileOf("scan.pdf"), d);
    expect(r.kind).toBe("pdf");
    expect(r.text).toBe("");
  });
});
