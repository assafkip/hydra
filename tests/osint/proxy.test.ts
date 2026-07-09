import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import type { FetchLike } from "../../src/osint/types.js";
import { isValidWorkerUrl, probeWorker, proxyFetch, proxyPost, resolvePageViaProxy, runProxiedProvider } from "../../src/osint/proxy.js";
import { SessionError, setWorkerUrl, getWorkerUrl, enrichViaProxy } from "../../src/agent/session.js";

// pb-proxy: the user-owned Cloudflare-Worker proxy tier for the CORS-blocked providers. The worker holds
// the user's keys; the client stores only the worker URL + routes the blocked-provider request through it.

const WORKER = "https://mykipi.example.workers.dev";
const VT_BODY = { data: { attributes: { last_dns_records: [{ type: "A", value: "9.9.9.9" }] } } };

function cannedFetch(body: unknown, log: { urls: string[]; bodies: string[] }): FetchLike {
  return (async (url: string, init?: RequestInit) => {
    log.urls.push(String(url));
    log.bodies.push(init?.body ? String(init.body) : "");
    return { ok: true, status: 200, json: async () => body } as Response;
  }) as unknown as FetchLike;
}

describe("pb-proxy — worker URL + proxy fetch + proxied providers", () => {
  it("isValidWorkerUrl accepts only https://<sub>.workers.dev (no host/scheme/path/cred injection)", () => {
    expect(isValidWorkerUrl("https://mykipi.example.workers.dev")).toBe(true);
    expect(isValidWorkerUrl("https://mykipi.workers.dev")).toBe(true);
    expect(isValidWorkerUrl("https://workers.dev")).toBe(false); // no subdomain
    expect(isValidWorkerUrl("http://x.workers.dev")).toBe(false); // not https
    expect(isValidWorkerUrl("https://x.workers.dev.evil.com")).toBe(false); // suffix attack
    expect(isValidWorkerUrl("https://x.workers.dev/exfil")).toBe(false); // path injection
    expect(isValidWorkerUrl("https://x.workers.dev?u=evil")).toBe(false); // query injection
    expect(isValidWorkerUrl("https://user:pass@x.workers.dev")).toBe(false); // credentials
    expect(isValidWorkerUrl("javascript:alert(1)//x.workers.dev")).toBe(false);
    expect(isValidWorkerUrl("not a url")).toBe(false);
  });

  it("proxyFetch targets the worker with ?u=<encoded target> and sends NO provider key", async () => {
    const log = { urls: [] as string[], bodies: [] as string[] };
    await proxyFetch(WORKER, "https://www.virustotal.com/api/v3/domains/example.com", { fetchImpl: cannedFetch({}, log) });
    expect(log.urls[0]).toBe(`${WORKER}?u=${encodeURIComponent("https://www.virustotal.com/api/v3/domains/example.com")}`);
    expect(log.bodies[0]).toBe(""); // the worker holds the key; the client sends none
  });

  it("runProxiedProvider parses a VirusTotal response into typed entities", async () => {
    const log = { urls: [] as string[], bodies: [] as string[] };
    const r = await runProxiedProvider("virustotal", "example.com", WORKER, { fetchImpl: cannedFetch(VT_BODY, log) });
    expect(r.tier).toBe("T2");
    expect(r.entities.some((e) => e.type === "ip" && e.value === "9.9.9.9")).toBe(true);
    expect(log.urls[0]).toContain(WORKER); // went through the worker, not virustotal.com directly
  });

  it("proxyPost targets the worker with ?u= and forwards the JSON body (client sends NO key)", async () => {
    const log = { urls: [] as string[], bodies: [] as string[] };
    await proxyPost(WORKER, "https://api.exa.ai/search", { query: "scam.test" }, { fetchImpl: cannedFetch({}, log) });
    expect(log.urls[0]).toBe(`${WORKER}?u=${encodeURIComponent("https://api.exa.ai/search")}`);
    expect(JSON.parse(log.bodies[0])).toEqual({ query: "scam.test" }); // the query rides the body, never a provider key
  });

  it("runProxiedProvider POSTs Exa's body through the worker + parses result URLs into domain leads", async () => {
    const log = { urls: [] as string[], bodies: [] as string[] };
    const EXA_BODY = { results: [{ url: "https://www.badkit.io/a" }, { url: "https://payout.example/b" }] };
    const r = await runProxiedProvider("exa", "who is behind scam.test", WORKER, { fetchImpl: cannedFetch(EXA_BODY, log) });
    expect(r.tier).toBe("T2");
    expect(r.entities.some((e) => e.type === "domain" && e.value === "badkit.io")).toBe(true); // www. stripped
    expect(r.entities.some((e) => e.type === "domain" && e.value === "payout.example")).toBe(true);
    expect(log.urls[0]).toContain(WORKER); // went through the worker, not api.exa.ai directly
    expect(JSON.parse(log.bodies[0]).query).toBe("who is behind scam.test"); // the search query rode the POST body
  });

  it("resolvePageViaProxy hits the worker /page endpoint and returns the server HTML text (keyless, no key)", async () => {
    const log = { urls: [] as string[], bodies: [] as string[] };
    const PAGE = { status: 200, finalUrl: "https://www.pinterest.com/pin/1/", text: "<html>hi</html>" };
    const page = await resolvePageViaProxy(WORKER, "https://www.pinterest.com/pin/1/", { fetchImpl: cannedFetch(PAGE, log) });
    expect(page.text).toBe("<html>hi</html>");
    expect(log.urls[0]).toBe(`${WORKER}/page?u=${encodeURIComponent("https://www.pinterest.com/pin/1/")}`);
    expect(log.bodies[0]).toBe(""); // keyless GET — no key, no body
  });

  it("resolvePageViaProxy rejects an invalid worker + a non-http target", async () => {
    await expect(resolvePageViaProxy("https://evil.com", "https://www.pinterest.com/pin/1/")).rejects.toThrow(/invalid worker url/);
    await expect(resolvePageViaProxy(WORKER, "javascript:alert(1)")).rejects.toThrow();
  });

  it("probeWorker classifies unset / render-ready / proxy-only / unreachable", async () => {
    expect(await probeWorker("https://evil.com")).toBe("unset"); // not a workers.dev url
    const ok = (async () => ({ ok: true, status: 200, json: async () => ({}) })) as unknown as FetchLike;
    expect(await probeWorker(WORKER, { fetchImpl: ok })).toBe("render-ready");
    const five01 = (async () => ({ ok: false, status: 501, json: async () => ({}) })) as unknown as FetchLike;
    expect(await probeWorker(WORKER, { fetchImpl: five01 })).toBe("proxy-only");
    const boom = (async () => { throw new Error("no answer"); }) as unknown as FetchLike;
    expect(await probeWorker(WORKER, { fetchImpl: boom })).toBe("unreachable");
  });

  it("setWorkerUrl validates + persists; enrichViaProxy requires a configured worker", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const v = await Vault.unlock(storage, "pw");
    await expect(setWorkerUrl(v, "https://evil.com")).rejects.toBeInstanceOf(SessionError); // not workers.dev
    expect(getWorkerUrl(v)).toBeNull();
    await expect(enrichViaProxy(v, "virustotal", "example.com")).rejects.toBeInstanceOf(SessionError); // no worker
    await setWorkerUrl(v, WORKER);
    expect(getWorkerUrl(v)).toBe(WORKER);
    const log = { urls: [] as string[], bodies: [] as string[] };
    const res = await enrichViaProxy(v, "virustotal", "example.com", { fetchImpl: cannedFetch(VT_BODY, log) });
    expect(res.provider).toBe("virustotal");
    expect(res.count).toBeGreaterThanOrEqual(1); // a gated entity landed + persisted
    expect(v.keys().some((k) => k.startsWith("run:enrich:"))).toBe(true);
  });
});
