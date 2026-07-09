# PRD-2 agent loop — what is proven offline, and the live boundary

The browser agent is the Anthropic Messages API **manual tool-use loop** running in the
user's tab on the user's key (`src/agent/loop.ts`). It replaces the server's `claude` CLI
investigator. Design: `../docs/17-client-side-architecture.md` section 4.

## What the automated suite proves (offline, deterministic)

Against a **scripted Anthropic wire** + **canned/real OSINT adapters** (no network, no key):

- **Loop mechanics** — a `tool_use` turn dispatches the tool, the result is fed back as a
  `tool_result` matched by `tool_use_id`, and the loop continues to `end_turn`
  (`loop.test.ts`, `agent-smoke.test.ts`).
- **Exact transcript ordering** — the assistant turn is appended with its `tool_use` blocks
  unchanged, then one user turn carries all `tool_result` blocks (multi-tool turn covered).
- **stop_reason branches** — `tool_use` / `end_turn` / `pause_turn` (resend) / `max_tokens`
  (NOT parsed as findings) / `refusal` / API error.
- **Gate fidelity** — every finding is attributed from the REAL tool results (a forged
  `source_count` is scrubbed) and run through the promotion gate: an infra-confirmed IP
  promotes; a name-only person is held as a LEAD (`agent-smoke.test.ts`, `gate.test.ts`).
- **Strict findings extraction** — only the trailing fenced/`{"findings"...}` JSON is taken.
  A `max_tokens` final answer is continued across model calls so a split findings JSON can finish;
  incomplete JSON after the continuation budget still saves nothing and reports an honest cutoff.
- **Bounded + cancellable** — `maxTurns` + `maxOutputTokens` halt with `stopReason:'budget'`;
  an `AbortSignal` stops the loop (and an in-flight tool fetch / retry backoff) cleanly.
- **Key hygiene** — the key is only ever in the `x-api-key` header (`llm.test.ts`).

## On-chain tools (PRD-5a)

The agent can pivot on a **BTC address** via `btc_address` (mempool.space, keyless, CORS-open). It
returns a `wallet` entity with the address's total received, balance, and tx count — the crypto-fraud
wedge's primary seed (a scam payout address). An on-chain record is T1 (non-fakeable), so a wallet
confirmed by one on-chain lookup PROMOTES; attributing it to a person still needs the person floor.
Adding the provider widened the CSP `connect-src` to include `https://mempool.space` (in all three
byte-identical copies — vercel.json, index.html, _headers — guarded by `tests/csp.test.ts`) and the
leakgate ALLOW set. Other chains (ETH/Tron/Solana/TON, keyed providers) are PRD-5b+. Proven offline
against a canned mempool fixture (`tests/osint/onchain.test.ts`, `tests/agent/onchain-smoke.test.ts`);
the live lookup is the user's.

## History + brief export (PRD-6)

Past investigations and briefs are listed in a **History** card (`session.listRuns` / `listBriefs`
over the new read-only `Vault.keys()`), and a brief downloads as a `.md` file. Secret-safety is
enforced at the data layer, not just the UI: the helpers drop any objective in the reserved
`secret:` namespace (incl. an adversarial `run:secret:anthropic_key`), drop any objective containing
the live key value, redact the key from a brief body, and `getBrief` returns null for a malformed
record; the render + download are capped at 256 KB. Proven in `tests/agent/history.test.ts` +
`tests/smoke/history.spec.ts` (which captures the `.md` download and asserts no key/secret leaks).

## The live boundary (the user's to run)

What a mock CANNOT prove: that Claude *chooses* good tools and *pivots* well on real data.
That is a prompt-quality property, validated **live by the user with their own key** — the
same boundary the spine drew for its client. To run it live:

1. Enter your Anthropic API key (stored only in the encrypted vault).
2. Give an objective (e.g. "Investigate example.com").
3. The loop streams its step trail; findings land gated (promoted vs leads) per the floors above.

Recommended: enable Zero Data Retention on your Anthropic account so even inference retains
nothing (Opus 4.8 supports ZDR; it is the default model — Fable 5 is opt-in because its cyber
classifiers false-positive on security work and it forbids ZDR).

## PRD-3 wiring (the agent is now reachable in the app)

The loop is wired into the app via `src/agent/session.ts` (pure, node-tested):

- **Key entry** — paste your Anthropic key; it is stored in the encrypted vault under the reserved
  `secret:anthropic_key` namespace. The `__kipi.getCase/putCase` debug hooks REFUSE `secret:` keys, so
  the key cannot be read back out through them (`getCase("secret:anthropic_key")` throws).
- **Investigate surface** — an objective input + Run + Stop. The step trail renders live (each
  reasoning/tool step), fenced by a per-run id so a stale or stopped run never pollutes a newer one.
  Promoted findings and held leads (with the gate's reason) render on completion, and a sanitized run
  record (never the key) is saved to the vault.
- **What is proven** — `tests/agent/session*.test.ts` (key get/set, run, live `onStep`, sanitized
  persistence, key never leaks) + `tests/smoke/agent.spec.ts` (real-browser render of the trail /
  findings / leads / key chip + a deterministic Stop → aborted). The live model run remains the
  user's, on their key.

## PRD-4: the brief (the deliverable)

After a run, **Generate brief** turns the gated findings into a written brief via
`src/agent/synthesize.ts` (`synthesizeBrief`, ported from `investigations/synthesize.py`):

- **Leads with the live threat** — `buildDigest` tags each promoted finding's operational status
  (infra-confirmed → live infrastructure; else unconfirmed/unknown) and the persona is instructed to
  headline what is operating now, never a dormant seed. Sections: Executive summary, Key judgments,
  Operational picture, Evidence (graded), Open questions (from the held leads), Where to look next.
- **Bounded + cancellable** — a no-tools `client.run` with a capped `maxTokens`; a `max_tokens`
  truncation is a clean non-persisted failure; an internal timeout retries once (a second billable
  request), while pressing Stop never retries.
- **Key hygiene (defense in depth)** — `session.generateBrief` redacts the exact vault key from the
  loaded run BEFORE it reaches the model AND from the markdown BEFORE persisting `brief:<objective>`.
  An empty run (no findings, no leads) returns a deterministic no-evidence brief with NO model call.
- **What is proven** — `tests/agent/synthesize.test.ts` (digest live/dead order, no-tools bounded
  request, persona placement, abort-not-retried, timeout-retries-once), `session-brief.test.ts`
  (errors, empty short-circuit, key redaction in+out), `brief-smoke.test.ts` (investigate→brief
  chain), and `tests/smoke/brief.spec.ts` (real-browser render). The live brief is the user's.

## PRD-7: the findings graph (kipi's signature surface)

> **Update (cleanup chunk):** the own-SVG renderer (`src/graph/render.ts`) and its force layout
> (`src/graph/layout-force.ts`) described in this section and the next were **DELETED** — the Cytoscape
> clone (see "The Cytoscape graph", below) is now the sole renderer. The gate-faithful model
> (`src/graph/model.ts`) + `mergeGraphModel` stay (they feed `cy-adapter.ts`); the leakgate
> `www.w3.org` SVG-namespace src exemption is now unused-but-harmless (the dist pdfjs worker still uses
> it). In the two sections below, the SVG-RENDERER pieces (the `render.ts` renderer, `layout-force.ts`, `layoutRadial()`, `#nodedetail`, drag/zoom on the `viewBox`) are HISTORICAL — that code is deleted and described for context only. The gate-faithful model pieces (`src/graph/model.ts`: `buildGraphModel`/`mergeGraphModel`, the re-gating, occurrence-indexed ids) remain LIVE — they feed `cy-adapter.ts` today.

A run's promoted findings + held leads + the seed objective render as a node-link GRAPH beside the
trail/findings/leads/brief, fed from the same `InvestigateResult`. Zero third-party runtime deps — our
own SVG via `createElementNS` (no Cytoscape, no d3 — leak F1). Static radial layout for the slice
(physics is a follow-up).

- **Gate-faithful model** — `src/graph/model.ts` (pure, node-tested): `buildGraphModel(objective,
  result)` puts the objective at the centre and one node per finding/lead radiating out. It does NOT
  trust the lists: it re-runs `isAdmissible()` on every entity (junk the gate rejected never becomes a
  node) and re-runs `promotionGate()` on every promoted finding (a forged/adversarial "promoted" that
  no longer promotes is demoted to a lead). Node ids are occurrence-indexed, so duplicate entities are
  distinct nodes. `layoutRadial()` is deterministic (no `Math.random`, no `Date`): objective centred,
  promoted on the inner ring, leads on the dimmed outer ring.
- **Zero-dep SVG renderer** — `src/graph/render.ts`: `<line>` edges (dashed for leads) + `<g><circle>
  <text></g>` nodes built with `createElementNS`; every label is set via `textContent` (never
  `innerHTML`), so a hostile entity (`<img onerror>`, `<svg><script>`) renders as literal text. Clicking
  a node opens `#nodedetail` (built with `createElement` + `textContent`) showing entity/type/grade/
  source counts and, for a lead, the gate's held reason.
- **Key hygiene** — `session.graphModelForRun` redacts the live key and drops `secret:` content BEFORE
  the pure model is built, so the model and the `__kipi.graphModel()` debug hook only ever see redacted
  text (the pure `model.ts` is vault-unaware).
- **No new origin** — the graph is inline SVG with no fetch; the CSP `connect-src` is unchanged. The
  one leakgate adjustment is to exempt the W3C XML namespace URI (`http://www.w3.org/2000/svg`) that
  `createElementNS` requires — a spec identifier the browser never fetches, NOT a CSP origin; any other
  `www.w3.org` URL still trips the gate.
- **What is proven** — `tests/graph/model.test.ts` (gate-faithful model + deterministic layout, incl.
  negative self-tests: empty/malformed input, inadmissible-lead omission, forged-promoted demotion,
  duplicate-entity distinctness), `tests/agent/graph-redact.test.ts` (key redacted out of the model),
  and `tests/smoke/graph.spec.ts` (real-browser render: node/edge counts, click-to-detail, no
  unexpected network, no key in body/graph/hook, XSS-safe HTML + SVG labels). The live graph is the
  user's run.

## PRD-8: the interactive graph (grow, don't re-pop)

The static graph becomes explorable. Click a node's **Dig one hop** to run the agent on that node's
entity and MERGE the result into the current graph; the graph grows in place, it does not re-pop.

- **Grow, no re-pop** — `mergeGraphModel` (pure, `src/graph/model.ts`) adds an addition's findings as
  nodes connected to the dug node. It is gate-faithful (re-runs `isAdmissible` + `promotionGate` on
  EVERY candidate; never trusts a supplied verdict). Dedup is alias-aware (`ip_address`≡`ip`,
  `crypto_wallet`≡`wallet`): an entity already on the graph gets a CROSS-EDGE to every matching node
  (the shared-infra / shared-wallet link), not a duplicate; a held lead that the hop promotes is
  upgraded in place. A missing parent id is a no-op (no dangling edge).
- **Deterministic force layout** — `src/graph/layout-force.ts` seeds from the radial layout then runs a
  fixed iteration count (no `Math.random`/`Date`); NaN-hardened against zero/tiny dims and coincident
  nodes. Used for the initial layout; merges keep existing positions and place only new nodes near their
  parent. The renderer (`src/graph/render.ts`) preserves positions + the viewBox across re-renders.
- **Drag / zoom / pan** — pointer-drag a node (pointer capture + a movement threshold; a real drag
  SUPPRESSES the trailing click so it never opens the detail panel); wheel zoom + background-drag pan on
  the `viewBox`. DOM-only, no new deps.
- **Key safety on the expand path** — `session.expandFromNode` runs the agent NO-PERSIST (no
  `run:<entity>` vault record the key could be read back from) and redacts the live key BEFORE the
  merge, so the merged model and `__kipi.graphModel()` never see it. A graph generation fence discards a
  stale expand (a new top-level run, or a vanished parent); a node is dug at most once.
- **What is proven** — `tests/graph/merge.test.ts` (grow, alias-dedup→cross-edge, lead→finding upgrade,
  forged-verdict re-gate, missing-parent no-op, idempotent edges, no mutation), `layout-force.test.ts`
  (deterministic + NaN-hardened), `tests/agent/expand-redact.test.ts` (key redacted + no run record),
  and `tests/smoke/graph-interactive.spec.ts` (real browser: grow with DOM transforms + viewBox
  unchanged, cross-edge not duplicate, drag-without-select, wheel zoom, no network, no key in
  body/graph/getCase, XSS-safe). The live expand is the user's run, on the user's key.

## The Cytoscape graph (exact clone of the webapp, BUNDLED — supersedes the own-SVG)

The signature surface is now the REAL Cytoscape graph from `investigations/webapp/templates/graph.html`,
cloned into kipi-web and **bundled** (no CDN — the webapp loaded cytoscape + dagre + expand-collapse +
fcose from unpkg, which is leak F1). The own-SVG renderer (`src/graph/render.ts`) and its force layout were DELETED from the tree
(cleanup chunk — see the update note under PRD-7; there is no on-disk rollback path); the gate-faithful
data feed (`src/graph/model.ts`: `buildGraphModel` + `mergeGraphModel`) is unchanged and still the source of truth.

- **Bundled stack, zero new egress** — `cytoscape`, `cytoscape-dagre`, `dagre`,
  `cytoscape-expand-collapse`, `cytoscape-fcose`, `layout-base`, `cose-base` are Vite-bundled
  dependencies. The CSP `connect-src` is UNCHANGED (the graph fetches nothing). `scripts/leakgate.mjs`
  exempts the benign license/attribution/doc-URL strings baked into the vendored bundles
  (`engelschall.com`, `jquery.org`, `tldrlegal.com`, `en.wikipedia.org`, `opensource.org`, `github.com`,
  `alpinejs.dev`) — **dist-scoped only**, so a first-party `src/` file naming one of those still trips
  the gate (proven by `tests/leakgate.test.ts`). `tests/deps.test.ts` proves every graph import is a
  declared dependency.
- **The adapter is the seam** — `src/graph/cy-adapter.ts` (pure, node-tested) maps the run-centric
  client model (objective / finding / lead) to Cytoscape elements in graph.html's exact data vocabulary:
  `role`+`shape` (entityType→operator·ellipse / channel·diamond / ioc·octagon / infra·rectangle /
  source·triangle, via the model's type aliases so `ip_address`≡`ip`, `crypto_wallet`≡`wallet`,
  `hash_*`≡`hash`), role-color border, slate cluster fill (no client clusters yet — honest, not faked),
  dashed `osint` border (agent-discovered), grade→score sizing, and a DETERMINISTIC stable edge id
  (`e:<from>__<to>__<kind>`) so a grow dedups/updates instead of duplicating. `thumbnail` is emitted only
  for confirmed/promoted or intake web-host nodes. That is the 2026-06-24 scoped favicon exception:
  the browser loads `t0.gstatic.com/faviconV2` directly for the bare domain; unconfirmed OSINT lead
  domains get no favicon.
- **The wrapper is the render** — `src/graph/cy-graph.ts` holds the cytoscape instance with graph.html's
  VERBATIM `style()` stylesheet + `_layoutOpts()` (cose / fcose / dagre / concentric / circle, each
  feature-checked so a missing extension hides its option without blanking the canvas), expand-collapse
  collection folding, the dot-grid blueprint background, the tap/box-select/spotlight/search/path-mode
  interactions, and `showDirection` computed from cytoscape topology (not a server detail layer).
- **Grow, don't re-pop (preserved)** — `CyGraph.grow(model, fromId)` ADDs new nodes at a free slot near
  their anchor (the `freeSpot`/`_anchorFor` placement ported from `growGraph`) AND refreshes the `data()`
  of any existing element whose model fields changed (an upgraded lead→finding restyles in place), with
  NO relayout and NO refit — existing positions + viewport are preserved.
- **The entity DB is now real (ed-wire)** — the chat node/edge cards (`.node-card` in `src/chat/dock.ts`; the floating drawer is gone) render REAL **typed
  connections**, a **derived dossier**, **co-occurrence**, and **edge evidence** from the client entity
  DB (`src/entity/db.ts` via `session.entityDbFor`) — a PURE, gate-faithful PROJECTION over the vault's
  `run:` records + the current graph model (no new write path; `createWritable` stays in
  `src/vault/store.ts`). The port-pending notice is NARROWED to only the still-server-coupled sections
  (clusters, properties, enrich/pivot links, the LLM dossier, semantic typed relations, the OSINT
  transform menu; the style-rules editor + manual-node form disabled). The chat edge card resolves
  evidence by the cytoscape source/target **node id** (ed-wire D1), not an ambiguous display value.
- **Key safety + XSS** — `session.graphModelForRun`/`expandFromNode` redaction is unchanged, so the live
  key never reaches the model, the cytoscape elements, or the `__kipi` hook. Every entity value reaches
  the DOM (drawer / search message / context menu / selected-set chip) via `textContent` — a hostile
  entity is literal text; canvas labels are not DOM at all.
- **What is proven** — `tests/graph/cy-adapter.test.ts` (the mapping + alias canonicalization +
  deterministic edge id + degenerate cases + no-thumbnail), and the migrated Playwright proofs
  `tests/smoke/graph.spec.ts` + `graph-interactive.spec.ts` on the cytoscape surface: a **non-blank
  canvas** (container sized, a cytoscape `<canvas>` exists, painted pixels — the §6 "actually renders"
  gate), node/edge counts via `__kipi.cyCounts()`, click→drawer, grow-with-refresh-not-repop (existing
  positions + viewport unchanged), a real-mouse node drag (moves only the dragged node, no drawer) +
  wheel zoom, a no-network listener attached BEFORE navigation, no key leak into body/graph/getCase, and
  XSS-safe values across every `#graph` DOM surface. The live graph is the user's run, on the user's key.

## The AI dossier + semantic typed relations (adr — port-pending narrowed)

The node drawer + the Entities-page detail now render two REAL on-demand LLM passes ALONGSIDE the
derived entity-DB data, ported from the server's `profile.py` (the written dossier) and `analyze.py`
(the typed-relations pass + `gate_attribution`). They are GATE-FAITHFUL by construction — the model
can only INTERPRET (dossier) or RE-LABEL an existing gated connection (relations); it can never add an
entity, an edge, or a source.

- **Pure passes** — `src/entity/dossier.ts` (`AI_DOSSIER_PERSONA` + `buildDossierPrompt` grounded ONLY
  on the entity's gated store facts + connections + a structured grounding block of allowed sources;
  `parseDossier` strips any fabricated `Source:`/URL the model invents) and `src/entity/relations.ts`
  (`REL_TYPES` a HARD allowlist; `canonRelType` folds synonyms then normalizes the unknown to `linked`;
  `gateAttribution` is the 1:1 port of `analyze.py` — strong-attribution `low`→drop / `medium`→`co_listed`
  / `high`→keep; `connId` is a STABLE per-connection id, not a list index; `parseSemanticRelations`
  validates each proposal's cid against the live connection set + gates the canonical label).
- **Read-only session accessors** — `session.aiDossierFor` / `session.semanticRelationsFor`: a no-tools
  `client.complete` (Opus 4.8), the live key redacted from the prompt IN and the output OUT (the
  `generateBrief` pattern), an unknown/zero-connection entity short-circuits with NO model call, and NO
  vault write (the single-writer `createWritable` stays in `src/vault/store.ts`). `complete()` now
  honors an `AbortSignal`.
- **Wiring** — the drawer (`app.ts`) + the Entities detail (`pages.ts`, via async `PageDeps` accessors
  supplied by `app.ts` so `pages.ts` never builds a client or reads the key) gain an "AI dossier" button
  (the model-written dossier rendered beside the "Derived" one, each labeled) and a "Type relations"
  button (a separate "Model-typed relations" block, never conflated with the renamed "Derived
  connections" rows). Buttons disable while in flight (no double-spend). `__kipi.aiDossier(nodeId)` /
  `semanticRelations(nodeId)` resolve via the redacted `lastGraphModel`, reject objective/unknown nodes,
  and return only the session-redacted output. The drawer port-pending block is narrowed to clusters /
  enrich-pivot / properties / the OSINT transform menu (the AI dossier + semantic relations are now real).
- **What is proven** — `tests/entity/dossier.test.ts` + `relations.test.ts` (the gate + canon + stable
  id + fabricated-source strip), `tests/agent/ai-dossier-session.test.ts` (key absent from the whole
  request body, redact-out, the gate through the accessor, read-only), `tests/llm/complete-signal.test.ts`
  (the AbortSignal), and `tests/smoke/ai-dossier.spec.ts` (the live browser proof: scripted dossier +
  relations render alongside derived, the low-confidence attribution + the unknown cid are both dropped,
  no key leak, no egress). The live passes are the user's, on the user's key.

## Clusters (cl — deterministic connected components)

The node drawer + a new `/clusters` page now render real CLUSTERS — entities grouped by the entity
DB's connections. They are DETERMINISTIC connected components (no LLM, gate-faithful), the strongest
answer to a fabricated cluster: components are computed mechanically from edges the gate already
admitted.

- **Pure pass** — `src/entity/clusters.ts` `buildClusters(store)`: UNDIRECTED connected components over
  the `co_occurs` + `linked` edges (a `surfaced_in` edge points at the objective endpoint, not an
  entity, so it never merges — and adjacency unions only when the other endpoint is a real entity in
  `store.entities`). A component of size >= 2 is a cluster; a singleton is unclustered. Identity is the
  exact db.ts `entityKey` (exported); the representative member + the cluster/member ordering are a TOTAL
  order, so the ids are stable regardless of insertion order. `clusterFor(clusters, type, value)`
  resolves an entity.
- **Read-only accessor** — `session.clustersFor(vault, current?)` = `buildClusters(entityDbFor(vault,
  current))`: reads the already-key-redacted entity DB, NO LLM, NO fetch, NO vault write.
- **Wiring** — the drawer shows the selected entity's cluster (label + size + co-members); the
  `/clusters` left-nav page lists every cluster; `__kipi.clusters()` exposes the serializable,
  key-redacted clusters. "Clusters" is removed from the drawer port-pending. The graph cluster-FILL
  (coloring cytoscape nodes by cluster) is the explicit next sub-step — the cytoscape render path is
  untouched here so its proofs cannot regress.
- **What is proven** — `tests/entity/clusters.test.ts` (undirected components, surfaced_in excluded,
  determinism + ties, hostile-delimiter distinctness, dominant-role label), `tests/agent/
  clusters-session.test.ts` (read-only + key-taint redaction), and `tests/smoke/clusters.spec.ts` (the
  live browser proof: 3 co-occurring entities cluster, a surfaced_in-only singleton is excluded, the
  drawer + Clusters page render, taint-redacted, no egress).

## Investigation-type detection + Cross-domain (td)

Each run now carries a DETECTED investigation TYPE (crypto-fraud / disinfo / hacktivist /
financial-fraud / intrusion-apt / person-of-interest, else "general"), and the Cross-domain page is
real: it lists entities that bridge two or more investigation TYPES. Detection is a verbatim,
DETERMINISTIC port of `investigations/intake/types.py` (the keyword + entity-histogram scorer) — the
server's LLM tiebreak is a later opt-in.

- **Pure pass** — `src/entity/typedetect.ts`: `TAXONOMY` (verbatim keyword weights; entity weights keyed
  to canonical types via the shared `canonType`, hash aliases merged), `scoreSignals` (per-keyword 4x +
  per-bucket 20x caps), `FLOOR=4.0` / `MARGIN=1.25`, `detectRunType(objective, entities)` ranked by
  (score desc, `TAXONOMY_ORDER` asc — stable ties), thin → "general".
- **Read-only accessor** — `session.crossDomainEntities(vault)`: detects each run's type over the
  key-redacted objective + gated entities (the run→type map keyed by the REDACTED objective), then keeps
  entities whose runs span >= 2 distinct SPECIFIC types (general excluded); total-sorted; NO LLM, NO
  fetch, NO vault write.
- **Wiring** — `renderCrossDomainPage` is REPLACED with the real cross-type list (entity + the type chips
  it bridges + the runs) via the new `PageDeps.crossDomain()` dep; `__kipi.crossDomain()` exposes the
  serializable, key-redacted result. The old port-pending info card is gone.
- **What is proven** — `tests/entity/typedetect.test.ts` (the 6 types + caps + canonical remap +
  TAXONOMY_ORDER ties), `tests/agent/crossdomain-session.test.ts` (cross-type bridge, same-type/general
  exclusion, entity-value key-taint redaction, read-only), and `tests/smoke/cross-domain.spec.ts` (two
  differently-typed runs share an entity → it surfaces on Cross-domain with both labels, no leak, no egress).

## File ingestion — text / PDF / CSV / XLSX (ig)

Reports & intake + Inbox are now REAL: upload a PDF / CSV / XLSX / text file (or paste text) and gated
entities land in the case, extracted 100% in the browser. A faithful port of
`investigations/ingest/extractor.py`. (Tesseract.js OCR for images + scanned PDFs is its own chunk —
the WASM + 10MB language model + no-CDN bundling is materially heavier.)

- **Pure extractor** — `src/ingest/extract.ts`: the regex set + the exact DOMAIN_TLDS frozenset (with the
  deliberate `.md/.py/.rs` omissions), `_scan_gated` (GATE_WINDOW=60), start-offset cross-type precedence,
  and prevalidated labeled-phone; every candidate runs the EXISTING `isAdmissible` gate (`gate.ts` gained
  a `prevalidated` param). Ships the high-confidence infra/ioc/contact subset (person/tech_stack/registrar
  are a later chunk).
- **Bundled file→text** — `src/ingest/files.ts`: PDF.js text-layer (the worker is a BUNDLED same-origin
  Vite asset via `new URL(..., import.meta.url)`, served from `'self'` per the existing CSP `worker-src
  'self'` — NEVER a CDN), SheetJS for XLSX + CSV/TSV, plain text, and `unsupported` for binary. `pdfjs-dist`
  + `xlsx` are bundled deps; leakgate dist-scoped-exempts the OOXML/XFA/XMP XML-namespace identifiers + the
  license strings baked into those bundles (none are fetch targets; the CSP blocks any fetch).
- **Ingest write path** — `session.ingestText`: extract → `promotionGate` findings (source_count 1, mostly
  leads — no overclaim) → a sanitized `run:file:…` record with a non-forgeable `sourceKind` + a
  collision-safe key, through the EXISTING `vault.put` (single writer). The key is redacted from the doc
  text + the record. Ingested entities flow into the entity DB / clusters / cross-domain as LEADS —
  the GRAPH gets none of them at ingest (discovery-grow: `graphModelForCase` drops intake leads; a
  dig promotes entities onto the graph, enforced by `d2-clump-repro.test.ts`).
- **UI** — `renderReportsPage` (file picker + paste + Process) + `renderInboxPage` (the ingested docs +
  counts, filtered by `sourceKind`) replace the port-pending cards. `__kipi.ingestText` returns only the
  redacted `{count, objective}`.
- **What is proven** — `tests/ingest/extract.test.ts` + `tests/ingest/files-deps.test.ts` (extraction +
  DOMAIN_TLDS + gated patterns + the generic dep manifest), `tests/agent/ingest-session.test.ts` (the
  write path + key-redaction + sourceKind), and `tests/smoke/ingestion.spec.ts` (the live proof: paste a
  doc → gated entities land, junk dropped; a tiny PDF + XLSX fixture process with zero egress).
