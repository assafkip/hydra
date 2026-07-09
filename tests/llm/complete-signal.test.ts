import { describe, it, expect, vi } from "vitest";
import { AnthropicClient } from "../../src/llm/client.js";
import type { FetchLike } from "../../src/osint/types.js";

// adr-pass (codex D8): complete() honors an AbortSignal (parity with run()) so a user-spend
// AI button can be cancelled and an already-aborted call never issues a request.

describe("AnthropicClient.complete — AbortSignal", () => {
  it("an already-aborted signal rejects WITHOUT calling fetch", async () => {
    const fetchImpl = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ content: [] }) })) as unknown as FetchLike;
    const client = new AnthropicClient("sk-ant-test", fetchImpl);
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      client.complete({ messages: [{ role: "user", content: "x" }], signal: ctrl.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("threads the signal into the fetch init", async () => {
    let seenSignal: AbortSignal | undefined;
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      seenSignal = init.signal ?? undefined;
      return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text: "ok" }], usage: {} }) };
    }) as unknown as FetchLike;
    const client = new AnthropicClient("sk-ant-test", fetchImpl);
    const ctrl = new AbortController();
    const { text } = await client.complete({ messages: [{ role: "user", content: "x" }], signal: ctrl.signal });
    expect(text).toBe("ok");
    expect(seenSignal).toBe(ctrl.signal);
  });
});
