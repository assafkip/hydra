import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// clu-auth (founder 2026-06-20): the auth/storage UX must read as ONE plain password story — no
// "OPFS" jargon and no separate "vault password" concept in user-facing copy. We scan the source
// with comment lines dropped (OPFS legitimately stays in implementation comments + lowercase
// identifiers like opfsStorage, which the case-sensitive "OPFS" check ignores). Deterministic mirror
// of the usability rule so the jargon can never silently creep back into the rendered copy.

function userFacingText(path: string): string {
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => {
      const t = l.trim();
      return !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*");
    })
    .join("\n");
}

describe("auth/storage copy is one plain password story", () => {
  const text = userFacingText("src/app.ts") + "\n" + userFacingText("src/pages.ts");

  it("has no user-facing 'OPFS' jargon", () => {
    expect(text).not.toContain("OPFS");
  });

  it("has no separate 'vault password' concept", () => {
    expect(text.toLowerCase()).not.toContain("vault password");
  });
});
