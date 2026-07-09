import { describe, it, expect, vi } from "vitest";
import { AnthropicClient, LlmError, MODEL_JUDGMENT, MODEL_CLASSIFY } from "../../src/llm/client";
import type { FetchLike } from "../../src/osint/types";

function captureFetch(): { calls: { url: string; init: RequestInit }[]; impl: FetchLike } {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url: String(url), init });
    return {
      ok: true,
      status: 200,
      json: async () => ({
        content: [{ type: "text", text: "ack" }],
        usage: { input_tokens: 11, output_tokens: 7 },
      }),
    };
  }) as unknown as FetchLike;
  return { calls, impl };
}

describe("AnthropicClient (BYO key)", () => {
  it("builds the correct request: endpoint, headers, model routing", () => {
    const c = new AnthropicClient("sk-ant-secret");
    const judgment = c.buildRequest({ messages: [{ role: "user", content: "hi" }] });
    expect(judgment.url).toBe("https://api.anthropic.com/v1/messages");
    const h = judgment.init.headers as Record<string, string>;
    expect(h["anthropic-dangerous-direct-browser-access"]).toBe("true");
    expect(h["anthropic-version"]).toBe("2023-06-01");
    expect(h["x-api-key"]).toBe("sk-ant-secret");
    expect(JSON.parse(String(judgment.init.body)).model).toBe(MODEL_JUDGMENT);

    const classify = c.buildRequest({ messages: [{ role: "user", content: "x" }], kind: "classify" });
    expect(JSON.parse(String(classify.init.body)).model).toBe(MODEL_CLASSIFY);
  });

  it("no-key path returns a clear error, not a crash", async () => {
    const c = new AnthropicClient("");
    await expect(c.complete({ messages: [{ role: "user", content: "hi" }] })).rejects.toBeInstanceOf(
      LlmError,
    );
  });

  it("token meter accumulates from usage", async () => {
    const { impl } = captureFetch();
    const c = new AnthropicClient("sk-ant-secret", impl);
    await c.complete({ messages: [{ role: "user", content: "hi" }] });
    await c.complete({ messages: [{ role: "user", content: "again" }] });
    expect(c.tokensUsed).toEqual({ input: 22, output: 14 });
  });

  // KEY HYGIENE (finding-9): the key must never appear in the URL/query, and must
  // never be written to the console.
  it("never leaks the key into the URL or the console", async () => {
    const { calls, impl } = captureFetch();
    const spy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const c = new AnthropicClient("sk-ant-TOPSECRET", impl);
    await c.complete({ messages: [{ role: "user", content: "hi" }] });
    expect(calls[0].url).toBe("https://api.anthropic.com/v1/messages");
    expect(calls[0].url).not.toContain("sk-ant-TOPSECRET");
    const logged = [...spy.mock.calls, ...errSpy.mock.calls].flat().join(" ");
    expect(logged).not.toContain("sk-ant-TOPSECRET");
    spy.mockRestore();
    errSpy.mockRestore();
  });
});

// ---- PRD-2: tool-use run() ----

function runFetch(): { calls: { url: string; init: RequestInit }[]; impl: FetchLike } {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url: String(url), init });
    return {
      ok: true,
      status: 200,
      json: async () => ({
        content: [{ type: "tool_use", id: "tu_1", name: "dns_lookup", input: { domain: "example.com" } }],
        stop_reason: "tool_use",
        usage: { input_tokens: 30, output_tokens: 9 },
      }),
    };
  }) as unknown as FetchLike;
  return { calls, impl };
}

const TOOLS = [
  { name: "dns_lookup", description: "DNS", input_schema: { type: "object" } },
  { name: "rdap_domain", description: "RDAP", input_schema: { type: "object" } },
];

describe("AnthropicClient.run (tool use)", () => {
  it("returns content blocks + stop_reason + usage, accumulates the meter", async () => {
    const { impl } = runFetch();
    const c = new AnthropicClient("sk-ant-secret", impl);
    const r = await c.run({ messages: [{ role: "user", content: "investigate example.com" }], tools: TOOLS });
    expect(r.stopReason).toBe("tool_use");
    expect(r.content[0]).toMatchObject({ type: "tool_use", name: "dns_lookup" });
    expect(c.tokensUsed).toEqual({ input: 30, output: 9 });
  });

  it("cache_control sits on the system's text block and the LAST tool only", () => {
    const c = new AnthropicClient("sk-ant-secret");
    const { init } = c.buildRunRequest({
      messages: [{ role: "user", content: "go" }],
      system: "PERSONA",
      tools: TOOLS,
      cache: true,
    });
    const body = JSON.parse(String(init.body));
    expect(body.system).toEqual([{ type: "text", text: "PERSONA", cache_control: { type: "ephemeral" } }]);
    expect(body.tools[0].cache_control).toBeUndefined();
    expect(body.tools[1].cache_control).toEqual({ type: "ephemeral" });
  });

  it("without cache, system is a plain string and tools carry no markers", () => {
    const c = new AnthropicClient("sk-ant-secret");
    const { init } = c.buildRunRequest({ messages: [{ role: "user", content: "go" }], system: "P", tools: TOOLS });
    const body = JSON.parse(String(init.body));
    expect(body.system).toBe("P");
    expect(body.tools[1].cache_control).toBeUndefined();
  });

  it("keeps the key in the header only (never the URL)", async () => {
    const { calls, impl } = runFetch();
    const c = new AnthropicClient("sk-ant-RUNSECRET", impl);
    await c.run({ messages: [{ role: "user", content: "go" }], tools: TOOLS });
    expect(calls[0].url).not.toContain("sk-ant-RUNSECRET");
    expect((calls[0].init.headers as Record<string, string>)["x-api-key"]).toBe("sk-ant-RUNSECRET");
  });

  it("no-key run() returns a clear error, not a crash", async () => {
    const c = new AnthropicClient("");
    await expect(c.run({ messages: [{ role: "user", content: "go" }] })).rejects.toBeInstanceOf(LlmError);
  });

  it("an already-aborted signal stops the run (no fetch, no hang)", async () => {
    const { calls, impl } = runFetch();
    const c = new AnthropicClient("sk-ant-secret", impl);
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      c.run({ messages: [{ role: "user", content: "go" }], tools: TOOLS, signal: ctrl.signal }),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(calls.length).toBe(0);
  });

  it("passes the signal through to fetch for in-flight cancellation", async () => {
    const { calls, impl } = runFetch();
    const c = new AnthropicClient("sk-ant-secret", impl);
    const ctrl = new AbortController();
    await c.run({ messages: [{ role: "user", content: "go" }], tools: TOOLS, signal: ctrl.signal });
    expect(calls[0].init.signal).toBe(ctrl.signal);
  });
});
