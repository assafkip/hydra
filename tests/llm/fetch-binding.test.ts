import { describe, it, expect, afterEach } from "vitest";
import { AnthropicClient } from "../../src/llm/client.js";

// Regression (live-reported on the hosted build the first time an investigation called
// Anthropic): the client must call the GLOBAL fetch with the global as receiver. A bare
// `fetchImpl = fetch` default invoked as `this.fetchImpl(...)` passes the CLIENT INSTANCE
// as `this`, which the browser rejects with
//   "Failed to execute 'fetch' on 'Window': Illegal invocation".
// Every other test injects a fake fetch, so the DEFAULT path was never exercised. This pins
// it by mimicking the WebIDL brand check (fetch only accepts the global / a detached undefined
// as `this`).

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function brandCheckedFetch() {
  return function (this: unknown, _input: unknown, _init?: unknown) {
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      json: async () => ({ content: [{ type: "text", text: "ok" }], stop_reason: "end_turn", usage: {} }),
    });
  };
}

describe("AnthropicClient default fetch binding (no Illegal invocation)", () => {
  it("run() with the DEFAULT fetch calls the global with a valid receiver", async () => {
    globalThis.fetch = brandCheckedFetch() as unknown as typeof fetch;
    const client = new AnthropicClient("sk-ant-default-path"); // NO injected fetch -> exercises the default
    const res = await client.run({ messages: [{ role: "user", content: "hi" }], tools: [], system: "s" });
    expect(res.stopReason).toBe("end_turn");
  });

  it("complete() with the DEFAULT fetch calls the global with a valid receiver", async () => {
    globalThis.fetch = brandCheckedFetch() as unknown as typeof fetch;
    const client = new AnthropicClient("sk-ant-default-path");
    await expect(
      client.complete({ system: "s", messages: [{ role: "user", content: "hi" }], kind: "judgment" }),
    ).resolves.toBeDefined();
  });
});
