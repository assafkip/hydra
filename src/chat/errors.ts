// clu-error-output: the ONE place error/output messages are mapped. The live repro (the chat-led error
// findings) showed runObjectiveMode swallowing every failure into one misleading sentence ("…no key. Add
// your key in the setup strip…") — wrong on two counts: a 401 is NOT "no key", and "setup strip" is a
// stale location (the key card moved to /account). These pure functions classify the cause and produce an
// HONEST message; the UI layers (dock, /enrich, doExpand) call them so wording never drifts again.

export interface MappedError {
  message: string;
  route?: string; // where to send the analyst to fix it (e.g. "/account" for a key problem)
}

function errText(e: unknown): string {
  if (e instanceof Error) return `${e.name}: ${e.message}`;
  if (typeof e === "string") return e;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/** True for an abort/cancel (a Stop press or a superseded run) — never an error to scold the user with. */
export function isAbortError(e: unknown): boolean {
  return e instanceof Error && (e.name === "AbortError" || /\babort/i.test(e.message) || /cancel/i.test(e.message));
}

function cleanMessage(t: string): string {
  const m = t.replace(/^[A-Za-z]*Error:\s*/, "").trim();
  return (m || "Something went wrong.").slice(0, 300);
}

/**
 * Map an investigator-run failure to an honest message (+ where to fix it). Order matters: abort first
 * (not an error), then NO-key (key absent) vs REJECTED-key (401) — they are different problems with
 * different fixes — then network, then a sanitized fallback.
 */
export function mapRunError(e: unknown): MappedError {
  const t = errText(e);
  if (isAbortError(e)) return { message: "Run stopped." };
  const rejected = /\b401\b|unauthor|invalid api key|invalid x-api-key|authentication_error|rejected/i.test(t);
  const noKey = /add your anthropic api key|no api key|api key (is )?not set|not configured|missing api key/i.test(t);
  if (noKey && !rejected) {
    return { message: "Add a key on the Account page to investigate.", route: "/account" };
  }
  if (rejected) {
    return { message: "Your Anthropic key was rejected (401). Check the key on the Account page.", route: "/account" };
  }
  if (e instanceof TypeError || /failed to fetch|networkerror|network request failed|load failed/i.test(t)) {
    return { message: "Couldn't reach the API — check your connection and try again." };
  }
  return { message: cleanMessage(t) };
}

/** Map an OSINT/enrichment provider failure to a guidance string (provider keys are user-owned). */
export function mapOsintError(e: unknown): string {
  const t = errText(e);
  if (/\b401\b|\b403\b|unauthor|forbidden|invalid.*key|rejected/i.test(t)) {
    return "This provider rejected your key — check it on the Account page.";
  }
  if (/notok/i.test(t)) {
    return "The provider returned an error (NOTOK) — check your key, your quota, or the target value.";
  }
  if (e instanceof TypeError || /failed to fetch|networkerror|load failed/i.test(t)) {
    return "Couldn't reach the provider — check your connection (some providers need your Worker proxy).";
  }
  return cleanMessage(t);
}

// clu-error-output: doExpand must SURFACE failures (the live finding: it was a silent no-op — a 401 or a
// network drop looked identical to "nothing found"). The outcome is explicit and the result line names
// which case it is, so the analyst always knows what happened.
export type ExpandOutcome = { ok: true; grew: boolean } | { ok: false; error: unknown };

export function expandResultLine(label: string, outcome: ExpandOutcome): string {
  if (outcome.ok) {
    return outcome.grew ? `Expanded ${label} — new connections added to the graph.` : `No new connections found for ${label}.`;
  }
  return `Couldn't expand ${label}: ${mapOsintError(outcome.error)}`;
}
