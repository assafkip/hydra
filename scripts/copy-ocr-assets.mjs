// ocr-assets (parity B1): vendor the Tesseract.js OCR engine from node_modules into a SAME-ORIGIN
// directory at BUILD time, so the deployed app is ZERO-CDN (docs/17 F1) and the build is reproducible
// (no committed binary, no manual download). Run before tsc/vite (package.json build) and predev.
//
// What ships (all single-thread — no pthread variant exists in tesseract.js-core@5):
//  - tesseract.js/dist/worker.min.js
//  - ALL FOUR v5 core wrappers + their .wasm (oem=LSTM loads the -lstm variant; SIMD detection picks
//    the -simd* one — D1). corePath stays the DIRECTORY, so tesseract resolves the right one at runtime.
//  - @tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz (the smaller best-int model)
//
// Reproducibility (D11/D12): the EXACT installed versions are validated, the dest is CLEARED first, a
// missing/empty source FAILS the build (never a silent runtime 404 -> jsdelivr fallback), and a
// manifest is written for tests/ingest/ocr-assets.test.ts to assert.

import { existsSync, mkdirSync, rmSync, copyFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// ocr-langs (cap-ocr multilingual parity): the original (investigations/ingest/screenshot.py,
// DEFAULT_LANGS="eng+ara+fas+heb+rus+chi_sim") OCRs six languages — load-bearing for the Iranian/
// Farsi/Arabic design-partner reports. We vendor each language's traineddata SAME-ORIGIN (zero-CDN
// forbids tesseract's jsdelivr lazy-load — docs/17 F1) so a multilingual worker loads any of them
// from /tesseract/ on demand. chi_tra is added as a deliberate superset of the original (founder
// directive "chi sim+tra"). Each is a pinned @tesseract.js-data/<lang>@1.0.0 build-time dep; the eng
// vendoring path (4.0.0_best_int/<lang>.traineddata.gz) generalizes to all of them.
const OCR_LANGS = ["eng", "ara", "fas", "heb", "rus", "chi_sim", "chi_tra"];

// Exact pinned versions — a mismatch fails the build (D11: a version bump must be a deliberate change).
const EXPECT = {
  "tesseract.js": "5.1.1",
  "tesseract.js-core": "5.1.1",
  ...Object.fromEntries(OCR_LANGS.map((l) => [`@tesseract.js-data/${l}`, "1.0.0"])),
};

const CORE_FILES = [
  "tesseract-core.wasm",
  "tesseract-core.wasm.js",
  "tesseract-core-simd.wasm",
  "tesseract-core-simd.wasm.js",
  "tesseract-core-lstm.wasm",
  "tesseract-core-lstm.wasm.js",
  "tesseract-core-simd-lstm.wasm",
  "tesseract-core-simd-lstm.wasm.js",
];

function pkgVersion(name) {
  return require(`${name}/package.json`).version;
}
function pkgDir(name) {
  return dirname(require.resolve(`${name}/package.json`));
}

export function copyOcrAssets(dest = join(ROOT, "public", "tesseract")) {
  for (const [name, want] of Object.entries(EXPECT)) {
    const got = pkgVersion(name);
    if (got !== want) {
      throw new Error(`OCR vendor version mismatch: ${name} is ${got}, expected ${want} (update EXPECT in copy-ocr-assets.mjs deliberately).`);
    }
  }

  rmSync(dest, { recursive: true, force: true }); // D12: clear stale assets
  mkdirSync(dest, { recursive: true });

  const tessDir = pkgDir("tesseract.js");
  const coreDir = pkgDir("tesseract.js-core");

  const sources = [
    [join(tessDir, "dist", "worker.min.js"), "worker.min.js"],
    ...CORE_FILES.map((f) => [join(coreDir, f), f]),
    // one traineddata per OCR language (the smaller best-int model — matches the eng vendoring).
    ...OCR_LANGS.map((l) => [join(pkgDir(`@tesseract.js-data/${l}`), "4.0.0_best_int", `${l}.traineddata.gz`), `${l}.traineddata.gz`]),
  ];

  const files = [];
  for (const [src, name] of sources) {
    if (!existsSync(src) || statSync(src).size === 0) {
      throw new Error(`OCR vendor source missing or empty: ${src}`);
    }
    copyFileSync(src, join(dest, name));
    files.push({ name, bytes: statSync(join(dest, name)).size });
  }

  writeFileSync(join(dest, "manifest.json"), JSON.stringify({ versions: EXPECT, files }, null, 2) + "\n");
  return files;
}

// Run when invoked directly (the build/predev step). KIPI_OCR_DEST lets the test target a temp dir.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const dest = process.env.KIPI_OCR_DEST ? resolve(process.env.KIPI_OCR_DEST) : undefined;
    const files = copyOcrAssets(dest);
    console.log(`OCR assets vendored: ${files.length} files (${files.reduce((a, f) => a + f.bytes, 0)} bytes).`);
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    process.exit(1);
  }
}
