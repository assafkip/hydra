#!/usr/bin/env node
// Re-probe each net-new OSINT origin's LIVE CORS from the real hydra origin before wiring it (PRD
// prd-hydra-free-osint-providers finding-2). A provider that no longer returns Access-Control-Allow-Origin
// for our origin would be blocked by the browser at runtime, so it must not be added to the free tier.
//
// Usage: node scripts/probe-cors.mjs            # probe the built-in infra/IP set
//        node scripts/probe-cors.mjs <url>...   # probe explicit sample URLs
// Exit 0 iff every probed origin returned an ACAO that admits the hydra origin (`*` or an exact echo).

const HYDRA_ORIGIN = "https://hydra.ktlystlabs.com";

// One representative live URL per origin. The query value is a well-known public IP (Google DNS), never PII.
const DEFAULT_TARGETS = [
  "https://internetdb.shodan.io/8.8.8.8",
  "https://stat.ripe.net/data/network-info/data.json?resource=8.8.8.8",
  "https://ip.guide/8.8.8.8",
  "https://ipwho.is/8.8.8.8",
  "https://api.stopforumspam.org/api?ip=8.8.8.8&json",
  "https://isc.sans.edu/api/ip/8.8.8.8?json",
];

function admitsHydra(acao) {
  if (!acao) return false;
  return acao === "*" || acao === HYDRA_ORIGIN;
}

async function probe(url) {
  try {
    const res = await fetch(url, { headers: { Origin: HYDRA_ORIGIN }, redirect: "follow" });
    const acao = res.headers.get("access-control-allow-origin");
    return { url, status: res.status, acao, ok: admitsHydra(acao) };
  } catch (err) {
    return { url, status: 0, acao: null, ok: false, error: String(err?.message ?? err) };
  }
}

async function main() {
  const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_TARGETS;
  const results = await Promise.all(targets.map(probe));
  let failed = 0;
  for (const r of results) {
    const mark = r.ok ? "OK " : "XX ";
    if (!r.ok) failed += 1;
    console.log(`${mark} ${r.status} acao=${r.acao ?? "(none)"} ${r.url}${r.error ? ` err=${r.error}` : ""}`);
  }
  console.log(`\n${results.length - failed}/${results.length} origins admit ${HYDRA_ORIGIN}`);
  process.exit(failed ? 1 : 0);
}

main();
