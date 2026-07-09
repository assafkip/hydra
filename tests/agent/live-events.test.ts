import { describe, expect, it } from "vitest";
import {
  createRunEventBus,
  summarizeRunEvents,
  type RunEvent,
} from "../../src/agent/live-events.js";

describe("live agent event bus", () => {
  it("publishes and replays events in append order", () => {
    const bus = createRunEventBus();
    const seen: string[] = [];
    const off = bus.subscribe((ev) => seen.push(ev.type));

    const runId = bus.start({ caseId: "case-a", mode: "objective", objective: "investigate evil.com" });
    bus.publish({ type: "agent_step", runId, step: { kind: "reasoning", text: "thinking" } });
    bus.publish({ type: "agent_observed", runId, observed: { tool: "dns_lookup", target: "evil.com", entities: [] } });
    bus.publish({
      type: "run_finalized",
      runId,
      stopReason: "end_turn",
      promoted: [],
      leads: [],
      relationships: [],
      usage: { input: 1, output: 2 },
      worked: true,
      objectiveKey: "investigate evil.com",
    });
    off();

    expect(seen).toEqual(["run_started", "agent_step", "agent_observed", "run_finalized"]);
    expect(bus.events().map((ev) => ev.type)).toEqual(seen);
    expect(bus.activeRunId()).toBeNull();
  });

  it("makes terminal events idempotent per run", () => {
    const bus = createRunEventBus();
    const runId = bus.start({ caseId: "case-a", mode: "objective", objective: "hang test" });

    bus.publish({ type: "run_aborted", runId, reason: "stop" });
    bus.publish({ type: "run_aborted", runId, reason: "stop" });
    bus.publish({ type: "run_error", runId, message: "late error" });

    expect(bus.events().map((ev) => ev.type)).toEqual(["run_started", "run_aborted"]);
    expect(bus.activeRunId()).toBeNull();
  });

  it("isolates throwing subscribers", () => {
    const bus = createRunEventBus();
    const seen: RunEvent["type"][] = [];
    bus.subscribe(() => {
      throw new Error("renderer exploded");
    });
    bus.subscribe((ev) => seen.push(ev.type));

    const runId = bus.start({ caseId: "case-a", mode: "objective", objective: "investigate evil.com" });
    bus.publish({ type: "run_aborted", runId, reason: "stop" });

    expect(seen).toEqual(["run_started", "run_aborted"]);
  });

  it("summarizes without raw tool text", () => {
    const bus = createRunEventBus();
    const runId = bus.start({ caseId: "case-a", mode: "objective", objective: "sk-ant-secret.example" });
    bus.publish({
      type: "agent_step",
      runId,
      step: {
        kind: "tool",
        tool: "dns_lookup",
        input: { domain: "sk-ant-secret.example" },
        result: "raw result with sk-ant-secret",
      },
    });
    bus.publish({ type: "run_aborted", runId, reason: "stop" });

    const summary = summarizeRunEvents(bus.events());
    expect(JSON.stringify(summary)).not.toContain("sk-ant-secret");
    expect(summary.types).toEqual(["run_started", "agent_step", "run_aborted"]);
    expect(summary.counts.agent_step).toBe(1);
    expect(summary.terminal).toBe("run_aborted");
  });

  it("counts streamed text deltas without exposing raw delta text in the public summary", () => {
    const bus = createRunEventBus();
    const runId = bus.start({ caseId: "case-a", mode: "objective", objective: "investigate evil.com" });
    bus.publish({ type: "agent_text_delta", runId, text: "thinking with sk-ant-secret inside" });
    bus.publish({ type: "run_aborted", runId, reason: "stop" });

    const summary = summarizeRunEvents(bus.events());
    expect(JSON.stringify(summary)).not.toContain("sk-ant-secret");
    expect(summary.types).toEqual(["run_started", "agent_text_delta", "run_aborted"]);
    expect(summary.counts.agent_text_delta).toBe(1);
  });
});
