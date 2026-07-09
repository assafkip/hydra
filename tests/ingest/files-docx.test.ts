import { describe, it, expect } from "vitest";
import { zipSync, strToU8 } from "fflate";
import { fileToText, type ReadableFile, type FileDeps } from "../../src/ingest/files.js";

// clu-docx-and-empty-graph: kipi-web must extract text from .docx (the original tool does). A .docx is a
// zip; the text lives in word/document.xml as <w:t> runs inside <w:p> paragraphs. Without this a dropped
// docx report silently extracts NOTHING → an empty graph (the founder hit this live).

function docxFixture(paras: string[]): ReadableFile {
  const body = paras.map((p) => `<w:p><w:r><w:t>${p}</w:t></w:r></w:p>`).join("");
  const xml = `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}</w:body></w:document>`;
  const zipped = zipSync({ "word/document.xml": strToU8(xml) });
  const ab = zipped.buffer.slice(zipped.byteOffset, zipped.byteOffset + zipped.byteLength);
  return { name: "report.docx", arrayBuffer: async () => ab as ArrayBuffer };
}

describe("fileToText — .docx (clu-docx-and-empty-graph)", () => {
  it("extracts paragraph text from a .docx (kind 'docx')", async () => {
    const f = docxFixture([
      "The operator runs evil-fixture.io from 9.9.9.9.",
      "Payments go to 0x52908400098527886E0F7030069857D2E4169EE7.",
    ]);
    const r = await fileToText(f);
    expect(r.kind).toBe("docx");
    expect(r.text).toContain("evil-fixture.io");
    expect(r.text).toContain("9.9.9.9");
    expect(r.text).toContain("0x52908400098527886E0F7030069857D2E4169EE7");
    expect(r.text).toMatch(/\n/); // paragraphs separated
  });

  it("un-escapes XML entities in the docx text (&amp; → &)", async () => {
    const r = await fileToText(docxFixture(["Acme &amp; Co at acme-fixture.io"]));
    expect(r.text).toContain("Acme & Co");
    expect(r.text).not.toContain("&amp;");
  });

  it("a non-docx blob with a .docx name degrades honestly (unsupported, not a crash)", async () => {
    const junk: ReadableFile = { name: "fake.docx", arrayBuffer: async () => new Uint8Array([1, 2, 3, 4]).buffer };
    const r = await fileToText(junk);
    expect(r.kind).toBe("unsupported");
  });

  // A2b (parity with docx_ingest.py:_ocr_media): a Word report's pasted screenshots carry entities
  // in word/media/ images, not the <w:t> text. The original OCRs them; the client must too.
  function docxWithMedia(paras: string[], media: Record<string, Uint8Array>): ReadableFile {
    const body = paras.map((p) => `<w:p><w:r><w:t>${p}</w:t></w:r></w:p>`).join("");
    const xml = `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}</w:body></w:document>`;
    const entries: Record<string, Uint8Array> = { "word/document.xml": strToU8(xml), ...media };
    const zipped = zipSync(entries);
    const ab = zipped.buffer.slice(zipped.byteOffset, zipped.byteOffset + zipped.byteLength);
    return { name: "report.docx", arrayBuffer: async () => ab as ArrayBuffer };
  }

  // fake OCR session: returns text keyed by the (PNG-magic-prefixed) image bytes' last byte → lets us
  // assert distinct images each get OCR'd and the body+image text are joined. Node-safe (no tesseract).
  function ocrDeps(map: Record<number, string>): Partial<FileDeps> {
    let terminated = 0;
    return {
      createOcrSession: async () => ({
        recognize: async (input: Blob | ArrayBuffer | Uint8Array) => {
          const u8 = input instanceof Uint8Array ? input : new Uint8Array(input as ArrayBuffer);
          return map[u8[u8.length - 1]] ?? "";
        },
        terminate: async () => { terminated++; },
      }),
      get _terminated() { return terminated; },
    } as unknown as Partial<FileDeps>;
  }

  it("OCRs embedded word/media images and appends their text to the body", async () => {
    const img1 = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1]); // ends in 1
    const img2 = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 2]); // ends in 2
    const f = docxWithMedia(["Body mentions paragraph-fixture.io."], {
      "word/media/image1.png": img1,
      "word/media/image2.jpg": img2,
    });
    const deps = ocrDeps({ 1: "wallet 0xAAA from the first screenshot", 2: "second screenshot says evil-ocr.io" }) as FileDeps;
    const r = await fileToText(f, deps);
    expect(r.kind).toBe("docx");
    expect(r.text).toContain("paragraph-fixture.io"); // body text
    expect(r.text).toContain("0xAAA"); // image 1 OCR
    expect(r.text).toContain("evil-ocr.io"); // image 2 OCR
    expect(r.text).toContain("(OCR)"); // labeled as image-sourced
  });

  it("a docx whose ONLY content is an image still extracts (kind docx, not unsupported)", async () => {
    const img = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 7]);
    const f = docxWithMedia([], { "word/media/image1.png": img });
    const deps = ocrDeps({ 7: "the only entity lives here: image-only-fixture.io" }) as FileDeps;
    const r = await fileToText(f, deps);
    expect(r.kind).toBe("docx");
    expect(r.text).toContain("image-only-fixture.io");
  });
});
