import { describe, it, expect } from "vitest";
import { extractDestination, resolveLink } from "../../src/osint/linkresolve.js";
import type { FetchLike } from "../../src/osint/types.js";

// hydra-see-sites (2026-07-08): the link-resolver reads a Pinterest pin's SERVER HTML (via the worker /page)
// and pulls the outbound destination `"link"` field. Fixture mirrors the LIVE shape verified 2026-07-08:
// pin 661677370297740779 → an Etsy listing, with the slashes JSON-escaped as Pinterest actually sends them.
const PIN = "https://www.pinterest.com/pin/661677370297740779/";
// In this JS string, `\\/` is a single backslash + slash — exactly what Pinterest emits ("https:\/\/...").
const HTML =
  `<html><head><meta property="og:url" content="https://www.pinterest.com/pin/661677370297740779/"></head>` +
  `<script>{"pin":{"link":"https:\\/\\/www.etsy.com\\/listing\\/4494709065\\/cat-face-orchid-seeds","id":"661677370297740779"}}` +
  `,{"url":"https://www.pinterest.com/qltliver"}</script>` +
  `<div>captcha https://iframe.arkoselabs.com/v2/</div></html>`;

describe("linkresolve.extractDestination", () => {
  it("pulls the outbound destination from a pin's server HTML (JSON-escaped), skipping self-links", () => {
    const ents = extractDestination(HTML, PIN);
    expect(ents.find((e) => e.type === "domain" && e.value === "etsy.com")).toBeTruthy();
    expect(ents.find((e) => e.type === "url" && e.value.includes("etsy.com/listing/4494709065"))).toBeTruthy();
    // the pin's OWN host is never surfaced as a destination
    expect(ents.some((e) => e.value.toLowerCase().includes("pinterest.com"))).toBe(false);
    // the destination is FIRST + noted distinctly (an analyst reads the pivot at the top)
    expect(ents[0].note).toContain("outbound destination");
    expect(ents[0].value).toContain("etsy.com");
  });

  it("returns nothing when there is no external link (only self/CDN hosts)", () => {
    const only = `{"link":"https://www.pinterest.com/pin/1/"} https://i.pinimg.com/236x/a.jpg`;
    expect(extractDestination(only, PIN)).toEqual([]);
  });
});

describe("linkresolve.resolveLink (via the worker /page)", () => {
  const WORKER = "https://mykipi.example.workers.dev";

  it("fetches the page through the worker /page endpoint and returns the destination as a T2 lead", async () => {
    const log: string[] = [];
    const fetchImpl = (async (url: string) => {
      log.push(String(url));
      return { ok: true, status: 200, json: async () => ({ status: 200, finalUrl: PIN, text: HTML }) };
    }) as unknown as FetchLike;
    const r = await resolveLink(PIN, WORKER, { fetchImpl, retries: 0 });
    expect(r.tier).toBe("T2");
    expect(r.provider).toBe("resolve:www.pinterest.com");
    expect(r.query).toContain("etsy.com");
    expect(r.entities.some((e) => e.type === "domain" && e.value === "etsy.com")).toBe(true);
    expect(log[0]).toBe(`${WORKER}/page?u=${encodeURIComponent(PIN)}`); // went through the worker, keyless
  });

  it("throws sanitized (no worker url in the message) on an invalid worker", async () => {
    await expect(resolveLink(PIN, "https://evil.com", { retries: 0 })).rejects.toThrow(/invalid worker url/);
    await resolveLink(PIN, "https://evil.com", { retries: 0 }).catch((e) => expect(String(e)).not.toContain("evil.com"));
  });
});
