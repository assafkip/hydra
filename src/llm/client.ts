// BYO-key Anthropic Messages API client. A thin fetch wrapper, not the SDK, so
// the shipped bundle has ZERO third-party runtime code in the vault context
// (audit finding F1 — the strongest answer is "no third-party code at all").
// The key is the USER's own, kept only in the encrypted vault; this client only
// ever puts it in the x-api-key HEADER, never in a URL/query, never logs it.
// docs/17 section 4: this replaces the `claude` CLI agent; Managed Agents is
// rejected (stateful, server-side). Default model Opus 4.8 (not Fable 5: Fable's
// cyber classifiers false-positive on security work and it forbids ZDR).

import type { FetchLike } from "../osint/types.js";

const ENDPOINT = "https://api.anthropic.com/v1/messages";
const API_VERSION = "2023-06-01";
export const MODEL_JUDGMENT = "claude-opus-4-8";
export const MODEL_CLASSIFY = "claude-haiku-4-5";

export class LlmError extends Error {}

export interface CompleteOpts {
  messages: { role: "user" | "assistant"; content: string }[];
  system?: string;
  kind?: "judgment" | "classify";
  model?: string;
  maxTokens?: number;
  /** Cancellation (parity with run()) — an aborted signal rejects, never hangs (codex D8). */
  signal?: AbortSignal;
}

interface Usage {
  input_tokens?: number;
  output_tokens?: number;
}

// ---- Messages API tool-use (PRD-2 agent loop) ----

export interface ToolDef {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

/** An Anthropic content block: text, thinking, tool_use, or tool_result. */
export interface ContentBlock {
  type: string;
  [k: string]: unknown;
}

export interface Message {
  role: "user" | "assistant";
  content: string | ContentBlock[];
}

export interface RunOpts {
  messages: Message[];
  tools?: ToolDef[];
  system?: string;
  kind?: "judgment" | "classify";
  model?: string;
  maxTokens?: number;
  signal?: AbortSignal;
  /** Attach cache_control to the stable prefix (system last block + last tool). */
  cache?: boolean;
  /** Use Anthropic Messages SSE streaming while preserving the assembled RunResult shape. */
  stream?: boolean;
  /** Fired for each streamed text_delta. Caller owns projection/redaction. */
  onTextDelta?: (text: string) => void;
}

export interface RunResult {
  content: ContentBlock[];
  stopReason: string | null;
  usage: Usage;
}

export class AnthropicClient {
  private inputTokens = 0;
  private outputTokens = 0;

  constructor(
    private readonly apiKey: string,
    // Default to a wrapper that calls the GLOBAL fetch, NOT a bare `= fetch`. A bare
    // reference invoked as `this.fetchImpl(...)` passes the client as `this`, which the
    // browser rejects: "Failed to execute 'fetch' on 'Window': Illegal invocation". The
    // arrow always calls fetch with the engine's correct receiver. (Tests inject their own.)
    private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
  ) {}

  get tokensUsed(): { input: number; output: number } {
    return { input: this.inputTokens, output: this.outputTokens };
  }

  modelFor(kind: "judgment" | "classify"): string {
    return kind === "classify" ? MODEL_CLASSIFY : MODEL_JUDGMENT;
  }

  // The key lives ONLY here, in the header. Never a URL/query/log.
  private authHeaders(): Record<string, string> {
    return {
      "content-type": "application/json",
      "x-api-key": this.apiKey,
      "anthropic-version": API_VERSION,
      "anthropic-dangerous-direct-browser-access": "true",
    };
  }

  /** Build the request without sending it (used by tests; keeps the wire shape in one place). */
  buildRequest(opts: CompleteOpts): { url: string; init: RequestInit } {
    const model = opts.model ?? this.modelFor(opts.kind ?? "judgment");
    const body: Record<string, unknown> = {
      model,
      max_tokens: opts.maxTokens ?? 4096,
      messages: opts.messages,
    };
    if (opts.system) body.system = opts.system;
    return {
      url: ENDPOINT, // never put the key here
      init: { method: "POST", headers: this.authHeaders(), body: JSON.stringify(body) },
    };
  }

  /**
   * Build a tool-use request. cache_control attaches to the STABLE PREFIX in a
   * deterministic place — the system prompt's single text block and the LAST tool
   * definition — so the large persona + tool list cache and per-turn cost drops
   * (docs/17 section 4.5). A misplaced marker silently misses the cache, so the
   * placement is pinned here and asserted by a request-shape test.
   */
  buildRunRequest(opts: RunOpts): { url: string; init: RequestInit } {
    const model = opts.model ?? this.modelFor(opts.kind ?? "judgment");
    const body: Record<string, unknown> = {
      model,
      max_tokens: opts.maxTokens ?? 4096,
      messages: opts.messages,
    };
    if (opts.system) {
      body.system = opts.cache
        ? [{ type: "text", text: opts.system, cache_control: { type: "ephemeral" } }]
        : opts.system;
    }
    if (opts.tools && opts.tools.length > 0) {
      const last = opts.tools.length - 1;
      body.tools = opts.cache
        ? opts.tools.map((t, i) => (i === last ? { ...t, cache_control: { type: "ephemeral" } } : t))
        : opts.tools;
    }
    if (opts.stream) body.stream = true;
    return {
      url: ENDPOINT,
      init: { method: "POST", headers: this.authHeaders(), body: JSON.stringify(body) },
    };
  }

  /** One tool-use turn. Returns the assembled content blocks + stop_reason + usage.
   *  Honors an AbortSignal (the Stop button) — an aborted run rejects, never hangs. */
  async run(opts: RunOpts): Promise<RunResult> {
    if (!this.apiKey) {
      throw new LlmError("Add your Anthropic API key in Settings to use AI features.");
    }
    if (opts.signal?.aborted) throw new DOMException("aborted", "AbortError");
    const { url, init } = this.buildRunRequest(opts);
    if (opts.signal) init.signal = opts.signal;
    const res = await this.fetchImpl(url, init);
    if (!res.ok) {
      throw new LlmError(
        res.status === 401
          ? "Anthropic rejected the key (401). Check your key in Settings."
          : `Anthropic API error (HTTP ${res.status}).`,
      );
    }
    if (opts.stream) {
      const streamed = await parseRunStream(res, opts.onTextDelta);
      this.inputTokens += streamed.usage.input_tokens ?? 0;
      this.outputTokens += streamed.usage.output_tokens ?? 0;
      return streamed;
    }
    const json = (await res.json()) as {
      content?: ContentBlock[];
      stop_reason?: string;
      usage?: Usage;
    };
    const usage = json.usage ?? {};
    this.inputTokens += usage.input_tokens ?? 0;
    this.outputTokens += usage.output_tokens ?? 0;
    return { content: json.content ?? [], stopReason: json.stop_reason ?? null, usage };
  }

  async complete(opts: CompleteOpts): Promise<{ text: string; usage: Usage; stopReason: string | null }> {
    if (!this.apiKey) {
      throw new LlmError("Add your Anthropic API key in Settings to use AI features.");
    }
    if (opts.signal?.aborted) throw new DOMException("aborted", "AbortError");
    const { url, init } = this.buildRequest(opts);
    if (opts.signal) init.signal = opts.signal;
    const res = await this.fetchImpl(url, init);
    if (!res.ok) {
      const status = res.status;
      // Do not echo the body verbatim into logs; surface a clean message.
      throw new LlmError(
        status === 401
          ? "Anthropic rejected the key (401). Check your key in Settings."
          : `Anthropic API error (HTTP ${status}).`,
      );
    }
    const json = (await res.json()) as { content?: { type: string; text?: string }[]; usage?: Usage; stop_reason?: string };
    const usage = json.usage ?? {};
    this.inputTokens += usage.input_tokens ?? 0;
    this.outputTokens += usage.output_tokens ?? 0;
    const text = (json.content ?? [])
      .filter((b) => b.type === "text" && typeof b.text === "string")
      .map((b) => b.text)
      .join("");
    // kweb-classify-batch: surface stop_reason so a caller can turn a truncated response into an HONEST
    // error instead of a silent null parse (extractJsonObject hard-fails on a truncated JSON).
    return { text, usage, stopReason: json.stop_reason ?? null };
  }
}

interface StreamBlock {
  block: ContentBlock;
  partialJson: string;
}

async function parseRunStream(res: Response, onTextDelta?: (text: string) => void): Promise<RunResult> {
  const reader = res.body?.getReader();
  if (!reader) throw new LlmError("Anthropic streaming response had no readable body.");
  const decoder = new TextDecoder();
  const blocks = new Map<number, StreamBlock>();
  let inputTokens: number | undefined;
  let outputTokens: number | undefined;
  let stopReason: string | null = null;
  let buffer = "";

  const handleEvent = (name: string, payload: unknown): void => {
    if (!payload || typeof payload !== "object") return;
    const data = payload as Record<string, unknown>;
    if (name === "error") {
      const err = data.error && typeof data.error === "object" ? data.error as Record<string, unknown> : data;
      const msg = typeof err.message === "string" ? err.message : "Anthropic streaming error.";
      throw new LlmError(msg);
    }
    if (name === "message_start") {
      const message = data.message && typeof data.message === "object" ? data.message as Record<string, unknown> : {};
      const usage = message.usage && typeof message.usage === "object" ? message.usage as Usage : {};
      inputTokens = usage.input_tokens ?? inputTokens;
      outputTokens = usage.output_tokens ?? outputTokens;
      return;
    }
    if (name === "content_block_start") {
      const index = typeof data.index === "number" ? data.index : -1;
      const contentBlock = data.content_block && typeof data.content_block === "object"
        ? data.content_block as ContentBlock
        : null;
      if (index >= 0 && contentBlock) blocks.set(index, { block: clonePlain(contentBlock), partialJson: "" });
      return;
    }
    if (name === "content_block_delta") {
      const index = typeof data.index === "number" ? data.index : -1;
      const entry = blocks.get(index);
      const delta = data.delta && typeof data.delta === "object" ? data.delta as Record<string, unknown> : {};
      if (!entry) return;
      if (delta.type === "text_delta" && typeof delta.text === "string") {
        const existing = typeof entry.block.text === "string" ? entry.block.text : "";
        entry.block.text = existing + delta.text;
        if (onTextDelta) {
          try {
            onTextDelta(delta.text);
          } catch {
            /* live text projection must not break the model loop */
          }
        }
      } else if (delta.type === "input_json_delta" && typeof delta.partial_json === "string") {
        entry.partialJson += delta.partial_json;
      }
      return;
    }
    if (name === "content_block_stop") {
      const index = typeof data.index === "number" ? data.index : -1;
      const entry = blocks.get(index);
      if (entry?.block.type === "tool_use" && entry.partialJson) {
        try {
          entry.block.input = JSON.parse(entry.partialJson);
        } catch {
          throw new LlmError("Anthropic stream ended with malformed tool input JSON.");
        }
      }
      return;
    }
    if (name === "message_delta") {
      const delta = data.delta && typeof data.delta === "object" ? data.delta as Record<string, unknown> : {};
      if (typeof delta.stop_reason === "string") stopReason = delta.stop_reason;
      const usage = data.usage && typeof data.usage === "object" ? data.usage as Usage : {};
      outputTokens = usage.output_tokens ?? outputTokens;
    }
  };

  const drainBuffer = (final: boolean): void => {
    while (true) {
      const sep = buffer.indexOf("\n\n");
      if (sep < 0) break;
      const chunk = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      parseSseChunk(chunk, handleEvent);
    }
    if (final && buffer.trim()) {
      parseSseChunk(buffer, handleEvent);
      buffer = "";
    }
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    drainBuffer(false);
  }
  buffer += decoder.decode();
  drainBuffer(true);

  return {
    content: [...blocks.entries()].sort((a, b) => a[0] - b[0]).map(([, v]) => v.block),
    stopReason,
    usage: { input_tokens: inputTokens, output_tokens: outputTokens },
  };
}

function parseSseChunk(chunk: string, onEvent: (name: string, data: unknown) => void): void {
  let event = "message";
  const dataLines: string[] = [];
  for (const rawLine of chunk.split(/\r?\n/)) {
    if (!rawLine || rawLine.startsWith(":")) continue;
    const colon = rawLine.indexOf(":");
    const field = colon >= 0 ? rawLine.slice(0, colon) : rawLine;
    const value = colon >= 0 ? rawLine.slice(colon + 1).replace(/^ /, "") : "";
    if (field === "event") event = value;
    else if (field === "data") dataLines.push(value);
  }
  if (!dataLines.length) return;
  const dataText = dataLines.join("\n");
  if (dataText === "[DONE]") return;
  onEvent(event, JSON.parse(dataText));
}

function clonePlain<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
