import { test, expect } from "@playwright/test";
import { gotoRoute } from "./_nav";
// ocr-smoke (the live proof, parity B1): a dropped image is OCR'd by the BUNDLED, ZERO-CDN Tesseract
// engine and its text flows through the real ingest gate. The deterministic contract: every tesseract
// asset (worker/core/traineddata) loads from the SAME ORIGIN and there is ZERO request to jsdelivr or
// any other off-app origin (proving the dead jsdelivr default is never hit — D2/D3). If the CSP blocked
// the WASM/worker, OCR would produce no text and the extraction assertion would fail (D5).

const KEY = "sk-ant-OCR-SMOKE-3131";

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

let reqs: string[] = [];
let consoleErrors: string[] = [];
test.beforeEach(async ({ page }) => {
  reqs = [];
  consoleErrors = [];
  page.on("request", (r) => reqs.push(r.url())); // before goto: catch every load-time + worker fetch
  page.on("console", (m) => { if (m.type() === "error") consoleErrors.push(m.text()); });
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  // ac-ui: the Anthropic key card moved off the graph home to the /account page, so reach it there
  // before saving the key (mirrors verify-process.spec — the home is now purely graph + chat).
  await gotoRoute(page, "/account");
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
});

test("a dropped PNG is OCR'd through the real gate; assets same-origin only; zero egress", async ({ page }) => {
  test.setTimeout(120_000); // OCR worker init + recognize is several seconds

  // render a high-contrast PNG with known text (an IP — digits OCR very reliably) in the browser
  const dataUrl = await page.evaluate(() => {
    const c = document.createElement("canvas");
    c.width = 640;
    c.height = 220;
    const ctx = c.getContext("2d")!;
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.fillStyle = "#000000";
    ctx.font = "bold 56px sans-serif";
    ctx.fillText("8.8.8.8", 40, 90);
    ctx.fillText("scanhost.org", 40, 170);
    return c.toDataURL("image/png");
  });
  const buffer = Buffer.from(dataUrl.split(",")[1], "base64");

  await page.evaluate((r) => { location.hash = "#" + r; }, "/reports"); // clu-workspace-nav: removed from sidebar, still resolves via hash
  await page.setInputFiles(".intake-file", { name: "scan.png", mimeType: "image/png", buffer });
  await page.click("button:has-text('Process file')");
  await expect(page.locator(".intake-out")).toContainText("Extracted", { timeout: 90_000 });

  // OCR actually read the image: the IP landed as a gated entity (proves the WASM ran under the CSP)
  const db = await page.evaluate(() => (window as any).__kipi.entityDb());
  const labels = Object.values(db.entities).map((e: any) => e.label);
  expect(labels, `OCR'd entities: ${labels.join(", ")}`).toContain("8.8.8.8");

  // the engine loaded its assets from the SAME ORIGIN (at least the worker), and NOTHING off-app
  const tessReqs = reqs.filter((u) => u.includes("/tesseract/"));
  expect(tessReqs.length, "tesseract assets must load from /tesseract/ (same origin)").toBeGreaterThan(0);
  const ext = reqs.filter(isExternal);
  expect(ext, `unexpected egress (no jsdelivr/CDN allowed): ${ext.join(", ")}`).toHaveLength(0);

  // no CSP/WASM block surfaced in the console (the frame-ancestors meta warning is benign + ignored)
  const blocking = consoleErrors.filter((e) => /content security|wasm|refused to|blocked/i.test(e) && !/frame-ancestors/i.test(e));
  expect(blocking, `CSP/WASM errors: ${blocking.join(" | ")}`).toHaveLength(0);

  // the key never leaks
  expect(JSON.stringify(db)).not.toContain(KEY);

  await page.screenshot({ path: "test-results/kipi-ocr.png", fullPage: true });
});

test("a non-English (Arabic/Persian) scan is RECOGNIZED: non-Latin glyphs in the OCR output; ara+fas models load same-origin; zero egress", async ({ page }) => {
  test.setTimeout(120_000); // multilingual worker init loads all vendored models + recognize

  // render a clear, high-contrast Arabic + Persian image. The original OCRs eng+ara+fas+heb+rus+chi;
  // Ally's design-partner reports are Farsi/Arabic, so the load-bearing proof is that non-Latin script
  // is actually transcribed (not just that the models load). ingestText discards raw text by design
  // (key hygiene), so the smoke reads the raw recognized text via the TEST-ONLY __kipi.ocrText hook.
  const bytes = await page.evaluate(() => {
    const c = document.createElement("canvas");
    c.width = 900;
    c.height = 320;
    const ctx = c.getContext("2d")!;
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.fillStyle = "#000000";
    ctx.direction = "rtl";
    ctx.font = "bold 84px sans-serif";
    ctx.fillText("سلام", 700, 120); // Arabic: "salaam" (hello)
    ctx.fillText("تهران", 700, 240); // Persian: "Tehran"
    const url = c.toDataURL("image/png");
    const bin = atob(url.split(",")[1]);
    const arr = new Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  });

  // OCR the non-Latin scan through the REAL multilingual engine and read the raw recognized text.
  const { text } = await page.evaluate(
    (b) => (window as unknown as { __kipi: { ocrText(x: number[]): Promise<{ text: string }> } }).__kipi.ocrText(b),
    bytes,
  );

  // the non-eng models actually RECOGNIZED the rendered WORDS — not just "some Arabic glyph appeared"
  // (codex-adversarial: a single garbage glyph must not flip the cap). Assert the normalized output
  // CONTAINS an expected token (سلام / تهران). An eng-only worker emits Latin/garbage and this fails.
  const normalized = text.replace(/\s+/g, "");
  const recognizedWord = normalized.includes("سلام") || normalized.includes("تهران");
  expect(recognizedWord, `OCR did not recognize the rendered Arabic/Persian words (سلام/تهران). Raw: ${JSON.stringify(text).slice(0, 200)}`).toBe(true);
  // and still carries real Arabic-script codepoints (U+0600-U+06FF), not transliterated Latin
  const arabicCodepoints = (text.match(/[؀-ۿ]/g) ?? []).length;
  expect(arabicCodepoints, `OCR output had no Arabic-script codepoints. Raw: ${JSON.stringify(text).slice(0, 200)}`).toBeGreaterThan(0);

  // the multilingual worker loaded the non-English models from the SAME ORIGIN (not eng-only)
  const tessReqs = reqs.filter((u) => u.includes("/tesseract/"));
  expect(tessReqs.some((u) => u.includes("ara.traineddata")), `ara model must load same-origin: ${tessReqs.join(", ")}`).toBe(true);
  expect(tessReqs.some((u) => u.includes("fas.traineddata")), "fas model must load same-origin").toBe(true);

  // zero off-app egress (no jsdelivr/CDN) and no key leak in the recognized text
  const ext = reqs.filter(isExternal);
  expect(ext, `unexpected egress (no jsdelivr/CDN allowed): ${ext.join(", ")}`).toHaveLength(0);
  expect(text).not.toContain(KEY);

  // no CSP/WASM block surfaced (the benign frame-ancestors meta warning is ignored)
  const blocking = consoleErrors.filter((e) => /content security|wasm|refused to|blocked/i.test(e) && !/frame-ancestors/i.test(e));
  expect(blocking, `CSP/WASM errors: ${blocking.join(" | ")}`).toHaveLength(0);

  await page.screenshot({ path: "test-results/kipi-ocr-nonlatin.png", fullPage: true });
});
