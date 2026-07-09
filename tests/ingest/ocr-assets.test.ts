import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, existsSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ocr-assets: the build-time vendoring of the Tesseract worker + ALL FOUR v5 core wrappers + the eng
// traineddata into a same-origin dir (D1/D11/D12). The test runs the real copy script into a CLEAN
// TEMP dir (isolation — never the real public/tesseract) and asserts the bundling contract.

const EXPECTED = [
  "worker.min.js",
  "tesseract-core.wasm",
  "tesseract-core.wasm.js",
  "tesseract-core-simd.wasm",
  "tesseract-core-simd.wasm.js",
  "tesseract-core-lstm.wasm",
  "tesseract-core-lstm.wasm.js",
  "tesseract-core-simd-lstm.wasm",
  "tesseract-core-simd-lstm.wasm.js",
  // cap-ocr multilingual: all 7 language models vendored same-origin (eng + the original's
  // ara/fas/heb/rus/chi_sim + the chi_tra superset). A missing one => no non-English OCR.
  "eng.traineddata.gz",
  "ara.traineddata.gz",
  "fas.traineddata.gz",
  "heb.traineddata.gz",
  "rus.traineddata.gz",
  "chi_sim.traineddata.gz",
  "chi_tra.traineddata.gz",
];

describe("copy-ocr-assets", () => {
  it("vendors the worker + 4 core wrappers + eng traineddata + a manifest into a clean dest", () => {
    const dest = mkdtempSync(join(tmpdir(), "ocr-assets-"));
    // run the real build script against the temp dest (no stale, no real public/ touched)
    execFileSync("node", ["scripts/copy-ocr-assets.mjs"], { env: { ...process.env, KIPI_OCR_DEST: dest } });

    for (const f of EXPECTED) {
      const p = join(dest, f);
      expect(existsSync(p), `${f} exists`).toBe(true);
      expect(statSync(p).size, `${f} non-empty`).toBeGreaterThan(0);
    }
    // a manifest is written, lists exactly the expected files, and carries the pinned versions
    const mf = JSON.parse(readFileSync(join(dest, "manifest.json"), "utf8")) as { versions: Record<string, string>; files: { name: string; bytes: number }[] };
    expect(mf.files.map((x) => x.name).sort()).toEqual([...EXPECTED].sort());
    expect(mf.versions["tesseract.js"]).toBe("5.1.1");
    expect(mf.files.every((x) => x.bytes > 0)).toBe(true);
  });
});
