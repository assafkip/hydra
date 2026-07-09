import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// clu-workspace-nav: ONE chat-led Investigation Workspace. The sidebar is collapsed to exactly
// Workspace + Enrich + Account; every other route STILL RESOLVES (app.ts ROUTES unchanged) but is no
// longer in the nav. These assertions read the shipped sources so a regression (a re-added nav link or
// a removed route) fails CI.

const indexHtml = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const appTs = readFileSync(new URL("../src/app.ts", import.meta.url), "utf8");

function sidebarNav(): string {
  const start = indexHtml.indexOf('<nav class="flex-1');
  const end = indexHtml.indexOf("</nav>", start);
  return indexHtml.slice(start, end);
}

describe("workspace nav collapsed (clu-workspace-nav)", () => {
  it("the sidebar contains EXACTLY the five workspace links", () => {
    // free/pro split (founder 2026-07-08): a 4th "Full tool" link was added — the upsell page listing what
    // the paid desktop/server tool (like four_points) does that this browser app can't. This supersedes the
    // 3-link collapse for the nav CHROME; every other route still resolves off-nav.
    const routes = [...sidebarNav().matchAll(/data-route="([^"]+)"/g)].map((m) => m[1]).sort();
    expect(routes).toEqual(["/", "/account", "/enrich", "/full-tool", "/tools"]);
  });

  it("the home link is clearly labeled 'Chat + graph'; the config + upsell screens are OSINT + Full tool + API", () => {
    // founder live-feedback 2026-06-21: "Workspace" didn't read as the chat; the home label stays
    // "Chat + graph" for discoverability. ccc-config-nav (founder decision 2026-06-25): the two config
    // screens are relabeled to the Chat Control Center names — Enrich→OSINT (the OSINT tools screen),
    // Account→API (the LLM API & account screen). data-route values are unchanged (asserted above).
    const nav = sidebarNav();
    expect(nav).toContain(">Chat + graph<");
    expect(nav).toContain(">OSINT<");
    expect(nav).toContain(">Full tool<");
    expect(nav).toContain(">Tools we use<");
    expect(nav).toContain(">API<");
  });

  it("every removed route STILL RESOLVES — the app.ts ROUTES set is unchanged (no 404)", () => {
    const removed = [
      "/entities", "/clusters", "/bridges", "/focus", "/runs", "/deliverables", "/briefs",
      "/cross-case", "/reports", "/inbox", "/cross-domain", "/corrections", "/activity",
      "/exports", "/report", "/cases", "/alerts",
    ];
    for (const r of removed) expect(appTs).toContain(`"${r}"`);
  });
});
