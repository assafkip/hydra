import { describe, it, expect } from "vitest";
import { mapRunError, mapOsintError, expandResultLine, isAbortError } from "../../src/chat/errors.js";

// clu-error-output: the message-mapping functions are the single source of error wording. These lock the
// honest behavior the live repro demanded (no "setup strip", a 401 is not "no key", failures are surfaced).

describe("mapRunError (clu-error-output)", () => {
  it("a 401 → mentions the key + Account, and is NOT 'setup strip' / NOT 'no key'", () => {
    const m = mapRunError(new Error("Anthropic API error: 401 unauthorized"));
    expect(m.message.toLowerCase()).toContain("key");
    expect(m.message).toContain("Account");
    expect(m.message.toLowerCase()).not.toContain("setup strip");
    expect(m.message.toLowerCase()).not.toContain("no key");
    expect(m.route).toBe("/account");
  });

  it("an AbortError → 'stopped' (a cancel, not an error to scold)", () => {
    const e = new Error("The user aborted a request.");
    e.name = "AbortError";
    expect(isAbortError(e)).toBe(true);
    expect(mapRunError(e).message.toLowerCase()).toContain("stopped");
  });

  it("a network TypeError → a connection message", () => {
    expect(mapRunError(new TypeError("Failed to fetch")).message.toLowerCase()).toContain("connection");
  });

  it("no key configured → 'add a key' + routes to /account", () => {
    const m = mapRunError(new Error("Add your Anthropic API key to investigate."));
    expect(m.message.toLowerCase()).toContain("add a key");
    expect(m.route).toBe("/account");
  });
});

describe("mapOsintError (clu-error-output)", () => {
  it("401 → key-rejected guidance", () => {
    expect(mapOsintError(new Error("HTTP 401")).toLowerCase()).toMatch(/key|account/);
  });
  it("'NOTOK' → provider-error guidance (names NOTOK)", () => {
    expect(mapOsintError(new Error("status: NOTOK")).toUpperCase()).toContain("NOTOK");
  });
  it("'Failed to fetch' → a connection/provider-reach message", () => {
    expect(mapOsintError(new TypeError("Failed to fetch")).toLowerCase()).toMatch(/reach|connection/);
  });
});

describe("expandResultLine — doExpand surfaces failures (clu-error-output)", () => {
  it("an error outcome is NOT a silent no-op — it names the failure", () => {
    const line = expandResultLine("acme.io", { ok: false, error: new Error("HTTP 401") });
    expect(line.toLowerCase()).toContain("couldn't expand");
    expect(line.toLowerCase()).toMatch(/key|account/);
  });
  it("grew → 'new connections'; no growth → 'no new connections'", () => {
    expect(expandResultLine("acme.io", { ok: true, grew: true }).toLowerCase()).toContain("new connections");
    expect(expandResultLine("acme.io", { ok: true, grew: false }).toLowerCase()).toContain("no new connections");
  });
});
