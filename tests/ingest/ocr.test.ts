import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { OCR_OPTIONS, OCR_LANG, OCR_OEM, DEFAULT_OCR_LANGS, imageToText, createWorkerWithFallback } from "../../src/ingest/ocr.js";

// ocr-engine: the config is the only thing that, if wrong, degrades from zero-CDN to a jsdelivr
// fallback (D3) — so it is pinned + unit-tested. The real recognize is the live ocr-smoke.

describe("ocr engine config (D3/D4)", () => {
  it("OCR_OPTIONS pins the same-origin /tesseract paths + workerBlobURL:false + no cache + gzip", () => {
    expect(OCR_OPTIONS.workerPath).toBe("/tesseract/worker.min.js");
    expect(OCR_OPTIONS.corePath).toBe("/tesseract");
    expect(OCR_OPTIONS.langPath).toBe("/tesseract");
    expect(OCR_OPTIONS.workerBlobURL).toBe(false);
    expect(OCR_OPTIONS.cacheMethod).toBe("none");
    expect(OCR_OPTIONS.gzip).toBe(true);
    expect(OCR_LANG).toBe("eng");
    expect(OCR_OEM).toBe(1);
    // no CDN/absolute URL anywhere in the options (a typo can't silently use tesseract's jsdelivr default)
    expect(JSON.stringify(OCR_OPTIONS)).not.toMatch(/jsdelivr|cdn\.|https?:\/\//);
  });

  it("DEFAULT_OCR_LANGS is the multilingual superset of the original (cap-ocr)", () => {
    // the original (investigations/ingest/screenshot.py) is eng+ara+fas+heb+rus+chi_sim; we add chi_tra
    // as a deliberate superset (founder directive "chi sim+tra"). Each lang is vendored same-origin.
    expect(DEFAULT_OCR_LANGS).toBe("eng+ara+fas+heb+rus+chi_sim+chi_tra");
    for (const lang of ["eng", "ara", "fas", "heb", "rus", "chi_sim", "chi_tra"]) {
      expect(DEFAULT_OCR_LANGS.split("+")).toContain(lang);
    }
    // every original language is still present (no feature-strip)
    for (const lang of ["eng", "ara", "fas", "heb", "rus", "chi_sim"]) {
      expect(DEFAULT_OCR_LANGS).toContain(lang);
    }
  });

  it("createWorkerWithFallback falls back to an eng worker when the multilingual init throws (D4)", async () => {
    // mirrors screenshot.py's `_run_tesseract(langs) or _run_tesseract("eng")`: a many-language init
    // failure must NOT drop English OCR. The injected createWorker throws for the multi-lang string and
    // succeeds for eng — proving the single eng retry.
    const calls: string[] = [];
    const fake = async (langs: string) => {
      calls.push(langs);
      if (langs !== OCR_LANG) throw new Error("simulated 7-model OOM");
      return { id: "eng-worker" };
    };
    const worker = await createWorkerWithFallback(fake, DEFAULT_OCR_LANGS);
    expect(worker).toEqual({ id: "eng-worker" });
    expect(calls).toEqual([DEFAULT_OCR_LANGS, OCR_LANG]); // tried multilingual, then fell back to eng
  });

  it("createWorkerWithFallback falls back to eng when the multilingual init HANGS, via timeout (D4/codex-A1)", async () => {
    // tesseract.js 5.1.1 swallows a loadLanguage/initialize reject (.catch(()=>{})), so a bad model
    // leaves the createWorker promise PENDING — only a timeout breaks the hang. A short timeout proves
    // the eng fallback still fires on a hang (not just on a throw).
    const calls: string[] = [];
    const fake = (langs: string): Promise<{ id: string }> => {
      calls.push(langs);
      if (langs !== OCR_LANG) return new Promise<{ id: string }>(() => {}); // never resolves (hang)
      return Promise.resolve({ id: "eng-worker" });
    };
    const worker = await createWorkerWithFallback(fake, DEFAULT_OCR_LANGS, 50);
    expect(worker).toEqual({ id: "eng-worker" });
    expect(calls).toEqual([DEFAULT_OCR_LANGS, OCR_LANG]); // hung on multilingual, timed out, fell back to eng
  });

  it("createWorkerWithFallback does NOT double-retry when eng itself fails (D4)", async () => {
    // when langs is already eng there is nothing to fall back to — surface the failure, no infinite retry.
    let calls = 0;
    const fake = async () => { calls++; throw new Error("eng broke"); };
    await expect(createWorkerWithFallback(fake, OCR_LANG)).rejects.toThrow(/eng broke/);
    expect(calls).toBe(1);
  });

  it("imports node-safe and rejects string inputs (D14)", async () => {
    // the import above succeeded with no DOM/tesseract at module load -> node-safe
    await expect(imageToText("/etc/passwd" as unknown as Blob)).rejects.toThrow(/binary|string/i);
  });

  it("ocr.ts imports NO vault/session write API (D15)", () => {
    const src = readFileSync(new URL("../../src/ingest/ocr.ts", import.meta.url), "utf8");
    expect(src).not.toMatch(/from ['"][^'"]*\/vault/);
    expect(src).not.toMatch(/from ['"][^'"]*\/session/);
    expect(src).not.toMatch(/createWritable/);
  });
});
