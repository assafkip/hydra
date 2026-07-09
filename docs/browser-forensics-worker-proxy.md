# Hydra browser forensics — why there is no Playwright, and the one blocker

Canonical reference. Written 2026-07-08 after a live case (whole-case #75c1a3c0,
a Pinterest fraud-network pin) stalled on `page_navigate` failing.

## The confusion this file settles

There are TWO different environments. Don't conflate them.

| Environment | Has Playwright? | Rendered-browser mechanism |
|---|---|---|
| A Claude Code dev session (the engineer's terminal) | Yes (Playwright MCP) | Playwright MCP tools |
| The **hydra investigator agent** (kipi-web, in the browser tab) | **No, by design** | The **user's Cloudflare Worker `/render`** endpoint |

Hydra is the 100%-client app (`docs/17-client-side-architecture.md`). A browser
tab cannot run a headless browser, so hydra ships NO bundled engine. Its
equivalent of Playwright is the user's own Cloudflare Worker running Cloudflare
Browser Rendering. "Use Playwright" is not a lever the agent is declining — the
rendered-browser path exists, it just needs the Worker configured.

## The exact code path (grounded, not from memory)

The three browser-forensics tools all go through the Worker:

- `src/agent/tools.ts` — `pageNavigate` / `pageNetworkRequests` / `evaluateScript`
  each call `renderViaProxy(requireWorker(opts, "browser forensics"), value, opts)`.
- `requireWorker()` (`tools.ts:40`) throws BEFORE any fetch when no worker URL is
  set: `"browser forensics needs your Worker proxy URL — deploy the Worker + set it
  in Enrich"`. **That is the error the case hit.** It means the Worker URL is not
  set in that vault's Enrich → User proxy field.
- `renderViaProxy()` (`src/osint/proxy.ts`) POSTs to `<worker>/render`.
- The Worker's `/render` (`docs/cloudflare-worker-template.js`) returns **501**
  unless the Worker has a **BROWSER binding** (Cloudflare Browser Rendering).

So there are two distinct failure modes:
1. **No worker URL in Enrich** → `requireWorker` throws "needs your Worker proxy URL". ← the case's state.
2. **Worker set but no BROWSER binding** → client gets "Render HTTP 501".

## The fix (three steps)

1. Deploy `kipi-web/docs/cloudflare-worker-template.js` to your Cloudflare account.
2. In the Worker: Settings → Bindings → add a **Browser Rendering** binding named
   `BROWSER`. (This is the EXTRA step beyond the provider-proxy secrets — without
   it `/render` 501s and only the HTTP-fetch tools run.)
3. In hydra: Enrich → **User proxy** → paste `https://<name>.workers.dev` → Save.

After that, `page_navigate` / `network_requests` / `evaluate_script` execute and
capture the outbound redirect / payout wallet / kit fingerprint a static fetch misses.

## Out-of-band fallback when the Worker can't be fixed

- **Wayback is DEAD in kipi** (removed 2026-06-02, doesn't work via the agent's
  fetch path). Do NOT use it as a fallback.
- **Pinterest oEmbed** returns the pin's description + destination as JSON with no
  JS rendering: `https://www.pinterest.com/oembed.json?url=<pin-url>`. Feed the
  outbound domain it returns back in as the real seed.
- **Jina reader** (the HTTP-fetch fallback that DID run) only returns Pinterest's
  own nav chrome — it can't get past the JS/login wall to the pin's outbound link.
  That is expected; a JS-rendered destination needs the Worker `/render`, not a
  static read.

## Related: OSINT provider-inputs work (2026-07-08) — deploy still pending

Separate but same-day work (plan: `q-system/output/plans/hydra-osint-provider-
inputs-2026-07-08.md`):
- Committed (branch `feat/hydra-light-table-redesign`): Tavily direct adapter
  (commit `ecabd752`), Exa via a new POST-capable proxy tier + honest backend-token
  labeling for Apify/Bright Data (commit `18004303`). Pushed.
- **`vercel --prod` NOT run.** This branch carries unfinished light-table-redesign
  WIP (5 red tests: workspace-nav, edge-card, routes, icon-svg) that a prod deploy
  would also ship live. Deploy decision is the founder's: merge the OSINT work to a
  clean branch and deploy that, or deploy the branch as-is, or hold.
