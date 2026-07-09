import { describe, expect, it } from "vitest";
import { AnthropicClient } from "../../src/llm/client";
import type { FetchLike } from "../../src/osint/types";

function sseEvent(event: string, data: unknown): string {
  return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

function streamResponse(events: string): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(events));
      controller.close();
    },
  });
  return new Response(body, { status: 200 });
}

describe("AnthropicClient.run streaming", () => {
  it("adds stream:true to the Messages request body", () => {
    const c = new AnthropicClient("sk-ant-secret");
    const { init } = c.buildRunRequest({
      messages: [{ role: "user", content: "investigate example.com" }],
      stream: true,
    });
    expect(JSON.parse(String(init.body)).stream).toBe(true);
  });

  it("assembles standard Anthropic SSE events into the same content blocks as non-streaming run()", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const events = [
      sseEvent("message_start", {
        type: "message_start",
        message: {
          id: "msg_1",
          type: "message",
          role: "assistant",
          content: [],
          stop_reason: null,
          usage: { input_tokens: 10, output_tokens: 0 },
        },
      }),
      sseEvent("content_block_start", {
        type: "content_block_start",
        index: 0,
        content_block: { type: "text", text: "" },
      }),
      sseEvent("content_block_delta", {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: "Hello " },
      }),
      sseEvent("content_block_delta", {
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: "world" },
      }),
      sseEvent("content_block_stop", { type: "content_block_stop", index: 0 }),
      sseEvent("content_block_start", {
        type: "content_block_start",
        index: 1,
        content_block: { type: "tool_use", id: "tu_1", name: "dns_lookup", input: {} },
      }),
      sseEvent("content_block_delta", {
        type: "content_block_delta",
        index: 1,
        delta: { type: "input_json_delta", partial_json: "{\"domain\":\"example.com\"}" },
      }),
      sseEvent("content_block_stop", { type: "content_block_stop", index: 1 }),
      sseEvent("message_delta", {
        type: "message_delta",
        delta: { stop_reason: "tool_use" },
        usage: { output_tokens: 9 },
      }),
      sseEvent("message_stop", { type: "message_stop" }),
    ].join("");
    const impl = (async (url: string, init: RequestInit) => {
      calls.push({ url: String(url), init });
      return streamResponse(events);
    }) as unknown as FetchLike;
    const deltas: string[] = [];
    const c = new AnthropicClient("sk-ant-secret", impl);

    const result = await c.run({
      messages: [{ role: "user", content: "investigate example.com" }],
      tools: [{ name: "dns_lookup", description: "DNS", input_schema: { type: "object" } }],
      stream: true,
      onTextDelta: (text) => deltas.push(text),
    });

    expect(JSON.parse(String(calls[0].init.body)).stream).toBe(true);
    expect(deltas).toEqual(["Hello ", "world"]);
    expect(result.stopReason).toBe("tool_use");
    expect(result.content).toEqual([
      { type: "text", text: "Hello world" },
      { type: "tool_use", id: "tu_1", name: "dns_lookup", input: { domain: "example.com" } },
    ]);
    expect(result.usage).toEqual({ input_tokens: 10, output_tokens: 9 });
    expect(c.tokensUsed).toEqual({ input: 10, output: 9 });
  });
});
