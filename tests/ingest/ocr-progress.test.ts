import { describe, it, expect } from "vitest";
import { createOcrSession, type OcrProgress, type OcrWorkerOptions } from "../../src/ingest/ocr.js";

// clu-chat-intake: image OCR must emit PROGRESS so the chat intake can show a live bar. The injected
// fake createWorker drives the tesseract-style `logger` through multiple stages (init + recognize); we
// assert the normalized onProgress fired >=2 times with the {stage, progress} shape.
describe("OCR progress (clu-chat-intake)", () => {
  it("emits >=2 progress callbacks across a multi-stage OCR", async () => {
    const events: OcrProgress[] = [];
    const fakeCreateWorker = async (_langs: string, _oem: number, options: OcrWorkerOptions) => {
      options.logger?.({ status: "loading tesseract core", progress: 0.1 }); // init stage
      options.logger?.({ status: "initializing api", progress: 0.4 }); // init stage
      return {
        async recognize(_input: Blob) {
          options.logger?.({ status: "recognizing text", progress: 0.5 }); // recognize stage
          options.logger?.({ status: "recognizing text", progress: 1 });
          return { data: { text: "hello" } };
        },
        async terminate() {},
      };
    };
    const session = await createOcrSession("eng", (p) => events.push(p), fakeCreateWorker);
    const text = await session.recognize(new Uint8Array([1, 2, 3]).buffer);
    await session.terminate();

    expect(text).toBe("hello");
    expect(events.length).toBeGreaterThanOrEqual(2);
    for (const e of events) {
      expect(typeof e.stage).toBe("string");
      expect(typeof e.progress).toBe("number");
    }
    expect(events.some((e) => e.stage === "recognizing text")).toBe(true);
  });

  it("works without an onProgress callback (progress is optional)", async () => {
    const fakeCreateWorker = async () => ({
      async recognize() {
        return { data: { text: "ok" } };
      },
      async terminate() {},
    });
    const session = await createOcrSession("eng", undefined, fakeCreateWorker);
    expect(await session.recognize(new Uint8Array([1]).buffer)).toBe("ok");
    await session.terminate();
  });
});
