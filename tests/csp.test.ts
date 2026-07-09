import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

// PRD-5a (codex finding-2): the egress wall is declared in THREE places that must
// stay byte-identical — vercel.json (response header), index.html (<meta>), and
// _headers (Cloudflare). The leak gate only scans src/dist origins, so it cannot
// catch a divergence between these three. This test does, and also proves the
// connect-src host set equals the leakgate ALLOW set (so the gate and the wall agree).

function cspFromVercel(): string {
  const json = JSON.parse(readFileSync("vercel.json", "utf8")) as {
    headers: { headers: { key: string; value: string }[] }[];
  };
  const h = json.headers.flatMap((b) => b.headers).find((x) => x.key === "Content-Security-Policy");
  return h!.value;
}
function cspFromIndex(): string {
  const html = readFileSync("index.html", "utf8");
  return /content="(default-src[^"]+)"/.exec(html)![1];
}
function cspFromHeaders(): string {
  const txt = readFileSync("_headers", "utf8");
  return /Content-Security-Policy:\s*(.+)/.exec(txt)![1].trim();
}

function connectSrcHosts(csp: string): Set<string> {
  const seg = /connect-src ([^;]+)/.exec(csp)![1];
  return new Set(
    seg
      .split(/\s+/)
      .filter((t) => t.startsWith("https://"))
      .map((t) => new URL(t).hostname),
  );
}

function directive(csp: string, name: string): string[] {
  const hit = csp.split(";").map((s) => s.trim()).find((s) => s.startsWith(`${name} `));
  return hit ? hit.split(/\s+/).slice(1) : [];
}

function leakgateAllow(): Set<string> {
  const mjs = readFileSync("scripts/leakgate.mjs", "utf8");
  const block = /const ALLOW = new Set\(\[([\s\S]*?)\]\)/.exec(mjs)![1];
  return new Set([...block.matchAll(/"([^"]+)"/g)].map((m) => m[1]));
}

describe("CSP egress wall integrity", () => {
  it("vercel.json, index.html, and _headers carry a BYTE-IDENTICAL CSP", () => {
    const v = cspFromVercel();
    expect(cspFromIndex()).toBe(v);
    expect(cspFromHeaders()).toBe(v);
  });

  it("includes the mempool.space on-chain origin", () => {
    expect(cspFromVercel()).toContain("https://mempool.space");
  });

  it("blocks eval-capable script execution", () => {
    const scriptSrc = directive(cspFromVercel(), "script-src");
    expect(scriptSrc).toEqual(["'self'", "'wasm-unsafe-eval'"]);
    expect(scriptSrc).not.toContain("'unsafe-eval'");
    expect(scriptSrc).not.toContain("'unsafe-inline'");
  });

  it("keeps style elements strict while allowing only style attributes for app-owned dynamic sizing", () => {
    const csp = cspFromVercel();
    expect(directive(csp, "style-src")).toEqual(["'self'"]);
    expect(directive(csp, "style-src-elem")).toEqual(["'self'"]);
    expect(directive(csp, "style-src-attr")).toEqual(["'unsafe-inline'"]);
  });

  it("includes the four keyless cross-chain origins (PRD-onchain: tron/solana/ton/ens)", () => {
    const v = cspFromVercel();
    for (const origin of [
      "https://api.trongrid.io",
      "https://solana-rpc.publicnode.com",
      "https://toncenter.com",
      "https://api.ensideas.com",
    ]) {
      expect(v).toContain(origin);
    }
  });

  it("includes the six CORS-open enrich provider origins (chunk 5)", () => {
    const v = cspFromVercel();
    for (const origin of [
      "https://api.shodan.io",
      "https://search.censys.io",
      "https://otx.alienvault.com",
      "https://api.etherscan.io",
      "https://urlscan.io",
      "https://ipinfo.io",
    ]) {
      expect(v).toContain(origin);
    }
  });

  it("includes the Supabase auth origin — the only founder-OWNED origin (chunk 6)", () => {
    expect(cspFromVercel()).toContain("https://yvermtklysygaeetxcyb.supabase.co");
  });

  it("includes the user-proxy *.workers.dev origin (PRD-5b — the user's own platform, not the founder's)", () => {
    expect(cspFromVercel()).toContain("https://*.workers.dev");
  });

  it("the connect-src host set equals the leakgate ALLOW set (wall and gate agree)", () => {
    const hosts = connectSrcHosts(cspFromVercel());
    const allow = leakgateAllow();
    expect([...hosts].sort()).toEqual([...allow].sort());
  });
});
