import type { Finding, GateVerdict } from "./gate.js";
import type { AgentRelationship, ObservedEvent, Step, StopReason } from "./loop.js";

export type RunMode = "objective" | "case";
export type TerminalRunEventType = "run_finalized" | "run_aborted" | "run_error";

export interface RunStartedEvent {
  type: "run_started";
  runId: string;
  caseId: string;
  mode: RunMode;
  objective: string;
  seq: number;
}

export interface AgentStepEvent {
  type: "agent_step";
  runId: string;
  step: Step;
  seq?: number;
}

export interface AgentTextDeltaEvent {
  type: "agent_text_delta";
  runId: string;
  text: string;
  seq?: number;
}

export interface AgentObservedEvent {
  type: "agent_observed";
  runId: string;
  observed: ObservedEvent;
  seq?: number;
}

export interface AgentRelationshipEvent {
  type: "agent_relationship";
  runId: string;
  relationship: AgentRelationship;
  seq?: number;
}

export interface RunFinalizedEvent {
  type: "run_finalized";
  runId: string;
  stopReason: StopReason;
  promoted: Finding[];
  leads: { finding: Finding; verdict: GateVerdict }[];
  relationships: AgentRelationship[];
  usage: { input: number; output: number };
  worked: boolean;
  degradedReason?: string;
  objectiveKey: string;
  seq?: number;
}

export interface RunAbortedEvent {
  type: "run_aborted";
  runId: string;
  reason: "stop" | "case-switch" | "lock" | "reset" | "supersede" | "unknown";
  seq?: number;
}

export interface RunErrorEvent {
  type: "run_error";
  runId: string;
  message: string;
  seq?: number;
}

export type RunEvent =
  | RunStartedEvent
  | AgentStepEvent
  | AgentTextDeltaEvent
  | AgentObservedEvent
  | AgentRelationshipEvent
  | RunFinalizedEvent
  | RunAbortedEvent
  | RunErrorEvent;

export type RunEventInput = RunEvent extends infer E ? E extends RunEvent ? Omit<E, "seq"> & { seq?: number } : never : never;
export type RunEventSubscriber = (event: RunEvent) => void;

export interface RunEventSummary {
  runId: string | null;
  active: boolean;
  terminal: TerminalRunEventType | null;
  mode: RunMode | null;
  objective: string;
  types: RunEvent["type"][];
  counts: Record<RunEvent["type"], number>;
}

export interface RunEventBus {
  start(opts: { caseId: string; mode: RunMode; objective: string; runId?: string }): string;
  publish(event: RunEventInput): RunEvent | null;
  subscribe(fn: RunEventSubscriber): () => void;
  events(): RunEvent[];
  reset(): void;
  activeRunId(): string | null;
  summary(): RunEventSummary;
}

const EVENT_TYPES: RunEvent["type"][] = [
  "run_started",
  "agent_step",
  "agent_text_delta",
  "agent_observed",
  "agent_relationship",
  "run_finalized",
  "run_aborted",
  "run_error",
];

const TERMINAL = new Set<RunEvent["type"]>(["run_finalized", "run_aborted", "run_error"]);

function nextRunId(): string {
  const uuid = globalThis.crypto?.randomUUID?.();
  return uuid ? `run-${uuid}` : `run-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function cloneEvent<T extends RunEvent>(event: T): T {
  return typeof structuredClone === "function"
    ? structuredClone(event)
    : JSON.parse(JSON.stringify(event)) as T;
}

function notify(subscribers: Set<RunEventSubscriber>, event: RunEvent): void {
  for (const fn of subscribers) {
    try {
      fn(cloneEvent(event));
    } catch {
      /* a broken projection must not break the live run */
    }
  }
}

export function createRunEventBus(): RunEventBus {
  let items: RunEvent[] = [];
  let seq = 0;
  let active: string | null = null;
  let terminalRun: string | null = null;
  const subscribers = new Set<RunEventSubscriber>();

  const publish = (event: RunEventInput): RunEvent | null => {
    if (terminalRun === event.runId) return null;
    if (!active && !TERMINAL.has(event.type)) return null;
    const full = { ...event, seq: seq++ } as RunEvent;
    items.push(cloneEvent(full));
    if (TERMINAL.has(full.type)) {
      terminalRun = full.runId;
      if (active === full.runId) active = null;
    }
    notify(subscribers, full);
    return cloneEvent(full);
  };

  return {
    start(opts) {
      const runId = opts.runId ?? nextRunId();
      items = [];
      seq = 0;
      active = runId;
      terminalRun = null;
      const ev: RunStartedEvent = {
        type: "run_started",
        runId,
        caseId: opts.caseId,
        mode: opts.mode,
        objective: opts.objective,
        seq: seq++,
      };
      items.push(cloneEvent(ev));
      notify(subscribers, ev);
      return runId;
    },
    publish,
    subscribe(fn) {
      subscribers.add(fn);
      return () => subscribers.delete(fn);
    },
    events() {
      return items.map(cloneEvent);
    },
    reset() {
      items = [];
      seq = 0;
      active = null;
      terminalRun = null;
    },
    activeRunId() {
      return active;
    },
    summary() {
      return summarizeRunEvents(items);
    },
  };
}

function safeText(text: string): string {
  return text
    .replace(/sk-[A-Za-z0-9._:-]+/g, "[REDACTED]")
    .replace(/[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+/g, "[REDACTED]")
    .slice(0, 160);
}

export function summarizeRunEvents(events: RunEvent[]): RunEventSummary {
  const counts = Object.fromEntries(EVENT_TYPES.map((t) => [t, 0])) as Record<RunEvent["type"], number>;
  let runId: string | null = null;
  let mode: RunMode | null = null;
  let objective = "";
  let terminal: TerminalRunEventType | null = null;
  for (const ev of events) {
    counts[ev.type]++;
    runId = ev.runId;
    if (ev.type === "run_started") {
      mode = ev.mode;
      objective = safeText(ev.objective);
    }
    if (ev.type === "run_finalized" || ev.type === "run_aborted" || ev.type === "run_error") terminal = ev.type;
  }
  return {
    runId,
    active: !!runId && terminal === null,
    terminal,
    mode,
    objective,
    types: events.map((ev) => ev.type),
    counts,
  };
}
