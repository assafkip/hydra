// ocr-engine (parity B1): the bundled, ZERO-CDN Tesseract OCR engine. tesseract.js is DYNAMICALLY
// imported so this module is node-safe and the ~6 MB engine loads ONLY when an image / scanned page is
// actually OCR'd. Every path is pinned to the same-origin /tesseract/* assets vendored at build by
// scripts/copy-ocr-assets.mjs — docs/17 F1 (zero-CDN); tesseract's jsdelivr default is never hit
// (proven by tests/smoke/ocr.spec.ts). This module does PURE extraction: it imports no vault/session
// write API (the OCR'd text routes through the existing ingestText gate at the call site — D15).

// One source of truth for the engine config (D3): a typo here is the ONLY way OCR could fall back to
// the CDN default, so OCR_OPTIONS is unit-tested for EXACT values.
export const OCR_OPTIONS = {
  workerPath: "/tesseract/worker.min.js",
  corePath: "/tesseract",
  langPath: "/tesseract",
  workerBlobURL: false, // D4: no blob: worker -> worker-src 'self' suffices (no CSP change)
  cacheMethod: "none",
  gzip: true,
};

export const OCR_LANG = "eng";

// ocr-multilingual (cap-ocr parity): the original (investigations/ingest/screenshot.py) OCRs
// "eng+ara+fas+heb+rus+chi_sim" by default — load-bearing for the Iranian/Farsi/Arabic design-partner
// reports. DEFAULT_OCR_LANGS is a SUPERSET (adds chi_tra per the founder directive "chi sim+tra"). Each
// language's traineddata is vendored SAME-ORIGIN under /tesseract/ (scripts/copy-ocr-assets.mjs); a
// "+"-joined worker loads the requested set from langPath on init (zero-CDN — never jsdelivr). The
// `langs` param on createOcrSession/imageToText lets a caller narrow it (e.g. "eng"); the default
// matches the original's "try all languages" behavior.
export const DEFAULT_OCR_LANGS = "eng+ara+fas+heb+rus+chi_sim+chi_tra";
export const OCR_OEM = 1; // LSTM

// Hard bounds (D8): a huge image or a runaway result can't hang the tab or blow memory.
export const MAX_OCR_BYTES = 12 * 1024 * 1024; // decoded-image byte cap
export const MAX_OCR_TEXT = 200_000; // cap the returned text BEFORE it reaches ingestText

export type OcrInput = Blob | ArrayBuffer | Uint8Array;

// clu-chat-intake: OCR progress. tesseract.js reports multi-stage progress (loading core, initializing,
// recognizing) through a createWorker-level `logger`; we normalize each tick to {stage, progress} so the
// chat intake can show a live OCR bar. Pure data — no DOM here (the bar is drawn in src/chat/dock.ts).
export interface OcrProgress {
  stage: string; // tesseract status, e.g. "loading tesseract core" | "recognizing text"
  progress: number; // 0..1
}
export type OcrProgressCb = (p: OcrProgress) => void;

type OcrLogger = (m: { status?: string; progress?: number }) => void;
/** The worker options forwarded to tesseract's createWorker — OCR_OPTIONS plus an optional progress logger.
 *  OCR_OPTIONS itself is NEVER mutated (its exact values are unit-pinned, D3). */
export type OcrWorkerOptions = typeof OCR_OPTIONS & { logger?: OcrLogger };

/** The minimal tesseract worker surface we use (recognize text + terminate). */
interface TessWorker {
  recognize(input: Blob, a?: unknown, b?: unknown): Promise<{ data: { text?: string } }>;
  terminate(): Promise<void>;
}
type CreateWorker = (langs: string, oem: number, options: OcrWorkerOptions) => Promise<TessWorker>;

/** D14: reject strings (a path/URL string would let tesseract fetch — incl. its CDN default) and any
 *  non-binary input, BEFORE any worker is created. */
function assertBinaryInput(input: unknown): asserts input is OcrInput {
  if (typeof input === "string") throw new Error("OCR input must be binary (Blob/ArrayBuffer), not a string.");
  const ok =
    (typeof Blob !== "undefined" && input instanceof Blob) ||
    input instanceof ArrayBuffer ||
    (typeof Uint8Array !== "undefined" && input instanceof Uint8Array);
  if (!ok) throw new Error("OCR input must be a Blob, ArrayBuffer, or Uint8Array.");
}

function byteLength(input: OcrInput): number {
  if (input instanceof ArrayBuffer) return input.byteLength;
  if (input instanceof Uint8Array) return input.byteLength;
  return input.size; // Blob
}

/** A reusable OCR session: ONE tesseract worker, recognize many inputs, terminate once (D6) — the
 *  scanned-PDF page loop reuses this instead of reloading the 6 MB engine per page. */
export interface OcrSession {
  recognize(input: OcrInput): Promise<string>;
  terminate(): Promise<void>;
}

// A many-language tesseract worker init can HANG rather than throw: tesseract.js 5.1.1's createWorker
// spawns the Worker then chains loadLanguage/initialize with a trailing `.catch(() => {})` that SWALLOWS
// a load/init failure — so the returned promise NEVER rejects on a missing/corrupt model, it stays
// pending (codex-adversarial finding). A timeout is therefore the only reliable signal, and it mirrors
// screenshot.py's subprocess `timeout=_OCR_TIMEOUT`. (A hung multilingual promise can't be terminated
// from here — the worker handle never resolved — so it leaks, but the timeout unblocks the caller and
// triggers the eng fallback, which is the behavior the original guaranteed.)
export const OCR_INIT_TIMEOUT_MS = 120_000; // matches screenshot.py _OCR_TIMEOUT

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`OCR worker init timed out after ${ms}ms (${label})`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

/** Create the tesseract worker for `langs`, falling back to an eng-only worker if the multilingual init
 *  THROWS or HANGS (D4 — mirrors screenshot.py's `_run_tesseract(langs) or _run_tesseract("eng")`: a
 *  many-language init that OOMs / hits a corrupt model must never drop English OCR below the original;
 *  eng is vendored + asserted present). `createWorker` is a parameter so the fallback is unit-testable
 *  without spinning the real engine (D10 seam); `timeoutMs` is too. Single retry only — when `langs` is
 *  already eng there is nothing to fall back to, so the failure surfaces (no infinite retry). */
export async function createWorkerWithFallback<W>(
  createWorker: (langs: string, oem: number, options: OcrWorkerOptions) => Promise<W>,
  langs: string,
  timeoutMs: number = OCR_INIT_TIMEOUT_MS,
  // clu-chat-intake: options is a NEW trailing param (after timeoutMs so existing 2/3-arg callers are
  // untouched). It carries the optional progress `logger`; defaults to the pinned OCR_OPTIONS.
  options: OcrWorkerOptions = OCR_OPTIONS,
): Promise<W> {
  try {
    return await withTimeout(createWorker(langs, OCR_OEM, options), timeoutMs, langs);
  } catch (err) {
    if (langs === OCR_LANG) throw err; // already eng-only — no fallback left, surface the failure
    return await withTimeout(createWorker(OCR_LANG, OCR_OEM, options), timeoutMs, OCR_LANG);
  }
}

export async function createOcrSession(
  langs: string = DEFAULT_OCR_LANGS,
  onProgress?: OcrProgressCb,
  // clu-chat-intake: createWorker is injectable (default = the lazy tesseract import) so the progress
  // wiring is unit-testable in node without spinning the 6 MB engine.
  createWorker?: CreateWorker,
): Promise<OcrSession> {
  const make: CreateWorker =
    createWorker ?? ((await import("tesseract.js")).createWorker as unknown as CreateWorker); // dynamic -> node-safe + lazy
  // clu-chat-intake: when a progress callback is given, attach a logger (normalized to {stage, progress}).
  // OCR_OPTIONS is spread into a NEW object — never mutated (its exact values are unit-pinned, D3).
  const options: OcrWorkerOptions = onProgress
    ? { ...OCR_OPTIONS, logger: (m) => onProgress({ stage: m.status ?? "", progress: typeof m.progress === "number" ? m.progress : 0 }) }
    : OCR_OPTIONS;
  const worker = await createWorkerWithFallback(make, langs, OCR_INIT_TIMEOUT_MS, options);
  return {
    async recognize(input: OcrInput): Promise<string> {
      assertBinaryInput(input);
      if (byteLength(input) > MAX_OCR_BYTES) throw new Error("Image too large for OCR.");
      // D7: text-only output (skip the expensive blocks/hocr/tsv formats).
      const { data } = await worker.recognize(input as Blob, {}, { text: true, blocks: false });
      return (data.text ?? "").slice(0, MAX_OCR_TEXT);
    },
    async terminate(): Promise<void> {
      await worker.terminate();
    },
  };
}

/** OCR a single image to text (a fresh worker, terminated in a finally — no leak). clu-chat-intake:
 *  onProgress threads tesseract's multi-stage progress out to the chat intake bar. */
export async function imageToText(
  input: OcrInput,
  langs: string = DEFAULT_OCR_LANGS,
  onProgress?: OcrProgressCb,
): Promise<string> {
  assertBinaryInput(input); // reject before spinning a worker
  const session = await createOcrSession(langs, onProgress);
  try {
    return await session.recognize(input);
  } finally {
    await session.terminate();
  }
}
