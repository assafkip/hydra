import { describe, it, expect } from "vitest";
import { buildFeedbackUrl, FEEDBACK_DISCLOSURE, buildBugReportUrl, BUG_DISCLOSURE } from "../src/feedback.js";

// rel-feedback: the feedback URL is a FIXED-host github.com/issues/new link with a STATIC template.
// It takes no arguments, so no case data can be interpolated. docs/17 §5.3: user-authored only, the
// founder's infra never receives it programmatically (the user reviews + submits the issue themselves).

describe("buildFeedbackUrl", () => {
  it("targets the fixed assafkip/kipi GitHub new-issue endpoint over https", () => {
    const u = new URL(buildFeedbackUrl());
    expect(u.protocol).toBe("https:");
    expect(u.hostname).toBe("github.com");
    expect(u.pathname).toBe("/assafkip/kipi/issues/new");
  });

  it("carries ONLY a static title + body template — no case-data field, no dynamic input", () => {
    // The builder takes no parameters at all, so nothing case-specific can reach the URL.
    expect(buildFeedbackUrl.length).toBe(0);
    const u = new URL(buildFeedbackUrl());
    const keys = [...u.searchParams.keys()].sort();
    expect(keys).toEqual(["body", "title"]);
    const body = u.searchParams.get("body")!;
    // the body is the human prompt template, not interpolated content
    expect(body).toContain("What happened");
    expect(body).toContain("What I expected");
    // it must NOT contain anything that looks like case/vault content
    for (const forbidden of ["run:", "secret:", "report:", "entity", "vault", "sk-ant"]) {
      expect(body.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
  });

  it("the disclosure states plainly that only typed text is sent", () => {
    expect(FEEDBACK_DISCLOSURE.toLowerCase()).toContain("never see your cases");
  });
});

// rel-bug: the bug-report URL is a FIXED mailto to the founder with a STATIC template. Like the
// feedback link it takes no arguments, so no case data can be interpolated — the user's own mail
// client sends it, nothing programmatic.
describe("buildBugReportUrl", () => {
  it("is a mailto to assaf@ktlystlabs.com", () => {
    const url = buildBugReportUrl();
    expect(url.startsWith("mailto:assaf@ktlystlabs.com?")).toBe(true);
  });

  it("carries ONLY a static subject + body template — no case-data field, no dynamic input", () => {
    // The builder takes no parameters at all, so nothing case-specific can reach the URL.
    expect(buildBugReportUrl.length).toBe(0);
    const query = new URLSearchParams(buildBugReportUrl().split("?")[1]);
    const keys = [...query.keys()].sort();
    expect(keys).toEqual(["body", "subject"]);
    expect(query.get("subject")).toBe("kipi bug report");
    const body = query.get("body")!;
    expect(body).toContain("What happened");
    expect(body).toContain("Steps to reproduce");
    // it must NOT contain anything that looks like case/vault content
    for (const forbidden of ["run:", "secret:", "report:", "entity", "vault", "sk-ant"]) {
      expect(body.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
  });

  it("encodes the body with %20 (not +) so mail clients render spaces, not plus signs", () => {
    expect(buildBugReportUrl()).not.toContain("+");
    expect(buildBugReportUrl()).toContain("%20");
  });

  it("the disclosure states plainly that only typed text is sent", () => {
    expect(BUG_DISCLOSURE.toLowerCase()).toContain("never see your cases");
  });
});
