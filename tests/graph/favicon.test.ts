import { describe, it, expect } from "vitest";
import { faviconHost, faviconUrl } from "../../src/graph/favicon.js";

// Domain-node favicons (founder decision 2026-06-24). faviconHost is the host rule (a verbatim port of the
// original webapp /api/favicon guard): strip scheme/www/path/query, sanitize, require a dot — else null.
describe("faviconHost — registrable host extraction", () => {
  it("strips scheme, www, path, query, and fragment", () => {
    expect(faviconHost("https://www.example.com/path?q=1#f")).toBe("example.com");
    expect(faviconHost("http://sub.example.com/a/b")).toBe("sub.example.com");
    expect(faviconHost("example.com")).toBe("example.com");
  });

  it("returns null for an unusable (dotless / empty) host — no favicon drawn", () => {
    expect(faviconHost("localhost")).toBeNull(); // no dot
    expect(faviconHost("")).toBeNull();
    expect(faviconHost(undefined)).toBeNull();
  });

  it("drops userinfo and port — credentials in a URL never reach gstatic (codex kweb-favicon-contract)", () => {
    expect(faviconHost("https://user:secret@example.com/path")).toBe("example.com");
    expect(faviconHost("user:secret@example.com")).toBe("example.com");
    expect(faviconHost("https://example.com:8443/x")).toBe("example.com");
    expect(faviconHost("https://www.example.com:8080")).toBe("example.com");
    expect(faviconHost("https://example.com\\secret.case-id")).toBe("example.com"); // \ is a WHATWG path separator
  });

  it("sanitizes hostile characters (a value is never trusted into the URL)", () => {
    // the @ and the query are stripped; what's left is sanitized to [a-z0-9.-]
    expect(faviconHost("evil.com/<script>")).toBe("evil.com");
    expect(faviconHost("a b.com")).toBe("ab.com"); // space removed by the sanitize pass
  });
});

describe("faviconUrl — the Google gstatic faviconV2 URL (the one deliberate egress)", () => {
  it("builds the direct gstatic URL for a usable host (no www.google.com redirect to chase)", () => {
    expect(faviconUrl("https://example.com")).toBe(
      "https://t0.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&size=64&url=http%3A%2F%2Fexample.com",
    );
  });
  it("returns null (no fetch) for a dotless host", () => {
    expect(faviconUrl("localhost")).toBeNull();
  });
});
