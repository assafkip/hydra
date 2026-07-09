# Hydra issues log

Running list of bugs the founder is calling out live. Tracking only — no fixes until the founder says go.

Branch: `feat/hydra-light-table-redesign`
Started: 2026-07-07

---

## ISSUE-1 — Graph resets to "Start here" mid-run (on abort)

**Status:** open · tracking
**Reported:** 2026-07-07 (screenshot: "Done (aborted). 0 promoted, 0 leads" + blank "Start here", but the Investigator trail clearly found entities — empresas.com, GoDaddy registrar, nameservers)

**Symptom:** Mid-run the graph snaps back to the empty "Start here" state and stops populating. Entities the run already found disappear.

**Root cause (from static analysis):**
- Live nodes are grown into in-memory `lastGraphModel` only (leads, uncorroborated).
- The run aborted. Abort skips finalize, so nothing is written to the vault.
- The `preferInMemory` branch in `hydrateCaseGraph` (`app.ts:1851`) retains the in-memory model only while `status === "running"`. The code comment there assumes any terminal status means the run is already persisted — true for `done` (awaited persist), false for `aborted`.
- Status flips `running → aborted` → next re-hydrate cold-reads the empty vault → renders blank "Start here."

**Proposed fix (not applied):** widen the `keepInMemory` condition so it also holds when `status === "aborted"`. Blast radius = mount path only; `done` still cold-reads.

**Open sub-question:** WHY did the run abort on its own? No evidence from the code yet. Tool errors (RDAP 404) don't abort a run. A spurious re-mount (`app.ts:2700/2791`) could. Needs its own dig.

---

## ISSUE-2 — Scope never gets pulled into the chat / investigation

**Status:** open · tracking
**Reported:** 2026-07-07

**Symptom:** Clicked **Scope**, then clicked **Start investigation** — it errored that the scope (gscope) was not populated. The scope chip selection does not actually feed the scope into the chat / run.

**CORRECTION (founder, 2026-07-07):** The first read (from a subagent) — "the pill only opens the form, you never clicked Save" — was WRONG. The founder DID click "Save scope" inside the form and it still didn't save. Root-caused first-hand below with a reproducer.

**Root cause (CONFIRMED with a reproducer — `tests/chat/scope-persist.repro.test.ts`):** the durable write is FIRE-AND-FORGET. `saveScope` → `deps.recordScope` → `recordScope` → `putTradecraft` (`session.ts:4687`) calls `vault.put(...)` **without `await`ing or returning the promise** (`putTradecraft` is `: void`). `vault.put` is async (`await this.commit()` → `await this.persist()`, `vault.ts:198-201`). So:
- The in-memory `doc` is updated synchronously → the CURRENT session reads scope fine (the auto-started run gets it).
- The DURABLE write races and is not awaited by anyone → on a reload / re-mount that reads from storage, **scope is gone.**

Reproducer output (real):
- Fire-and-forget (as the app calls it): `reopened scope = null` → **LOST on reload. FAILS.**
- The same write AWAITED: `awaited survives` → round-trips. **PASSES.**

So the fix is: `putTradecraft` must `return vault.put(...)`, `recordScope` must `await` it, `deps.recordScope` + `saveScope` must `await` it before proceeding.

**Blast radius:** `putTradecraft` has exactly two callers — `recordScope` (scope, 4701) AND the gate writer (Challenge/Premortem results, 4787). So gate results ALSO don't survive a reload (their ✓ done-state vanishes). This is the whole radius of THIS defect.

**Same family as ISSUE-1 / ISSUE-5 — see "Unified root cause X" below.**

**Secondary (still real):** the `busy` guard in `saveScope` (`dock.ts:335`) silently no-ops the Save if a run is in flight — no error, nothing happens. `saveScope` also conflates persist + run (auto-starts on save). Typed-but-unsaved form text is discarded on any other click. No "frame scope first" precondition. There is no hard "scope not populated" error — scope is optional in `composeCaseTask` (`session.ts:590-591`); the message the founder saw was the empty-roster / degraded-run branch (`dock.ts:602-608`).

---

## ISSUE-3 — Run/chat log overlaps the chat and can't be dismissed

**Status:** open · tracking
**Reported:** 2026-07-07 (screenshot: the Investigator step log fills the panel, chat input barely reachable)

**Symptom:** The log portion of the chat takes over most of the Investigator panel and completely overlaps the chat. No way to get the chat back.

**Ask (UX):** Make the log toggleable — a button to OPEN it and a button to CLOSE it, so the chat is reachable again. It should not permanently overlap the chat.

**Root cause (confirmed):** NOT a z-index / absolute overlap. It's vertical flex-space domination with no dismiss:
- `#trail.livetrail` is the FIRST child of `.chatdock` (`dock.ts:239,375`), a fixed top block capped at `max-height: 40vh` (`app.css:451`), permanently open for the whole run. Once steps stream it fills ~40% of the panel and stays.
- `#chat-scroll` (the conversation) is `flex:1; min-height:0` (`app.css:414`) → it only gets leftover height and is ALLOWED to collapse to a sliver.
- `.tc-bar` (7 pills, wraps to 2-3 rows, `app.css:466`) + the optional scope form + the input row each reserve space below, squeezing the scroller toward zero. The input survives (`flex-shrink:0`) but the conversation above it vanishes.
- There is NO collapse/toggle control anywhere (grep-confirmed). The only auto-hide is `#trail:empty { display:none }` — applies only before any steps exist.

**Fix (not applied):** add an open/close toggle on the trail (header caret, class `.livetrail.collapsed { max-height:0 }`, persisted in sessionStorage like `kipiDockOpen`); add a `min-height` floor to `.chat-scroll` so the conversation can't collapse to zero. Precedent: the dock's own collapsible header at `app.ts:1959-1994`.

**Adjacent issues found:** `.tc-bar` wrap eats vertical space with no shrink; the inline `.tc-scope` form expands between the bar and composer (further compresses chat); `#chat-scroll` has no min floor.

---

## ISSUE-4 — Dark mode: chat log text unreadable (no contrast)

**Status:** open · tracking
**Reported:** 2026-07-07

**Symptom:** In dark mode, the words inside the chat log are invisible — the panel background is black but the text color is also dark, so there is no contrast.

**Root cause (confirmed):** `.livetrail` (the run trail container, `app.css:451`) has its background pinned to a hardcoded light literal `rgba(244,244,243,0.5)` that never flips for dark mode. The step TEXT correctly flips to light (`var(--muted)`/`var(--ink)`), so light text composites over a washed near-white panel → no contrast. The defect is solely this container literal; the text tokens are fine.

**Same element as ISSUE-3.** Both defects live on `.livetrail` / `app.css:451`, introduced by today's "scope-scroll-fix." One change carried both a bad `max-height:40vh` (layout) and a hardcoded light bg (theme).

**Fix (not applied):** `app.css:451` → `background: rgb(var(--c-bg-soft) / 0.5)` (or the semantic `--bg-soft`). Secondary: `.trail-tool.err` (`app.css:857`) uses light-amber `#92400E` — low contrast in dark; route to `--err`/`--c-sev-med`.

---

## ISSUE-5 — Page refresh wipes the graph and stops the chat

**Status:** open · tracking
**Reported:** 2026-07-07

**Symptom:** Refreshing the page refreshes (resets) the graph and the chat stops.

**Notes:** Same structural root as ISSUE-1. See "Common root cause A" below.

---

# ROOT-CAUSE ANALYSIS (2026-07-07)

## Common root cause A — the live run is ephemeral tab state with ONE durable checkpoint at finalize (ISSUE-1 + ISSUE-5)

**Confirmed from code:**
- The investigation runs as a browser-side agent loop in the tab. There is no server, no resume.
- The graph a user watches build is grown into an **in-memory** `lastGraphModel` from streamed `agent_observed` events (`liveGrowObserved`, `app.ts:2939`). These live nodes are LEADS (uncorroborated).
- The ONLY durable write is `vault.put("run:<objective>", …)` at the END of `runInvestigation` (`agent/session.ts:447`), after the whole loop returns. Mid-run: nothing is persisted.
- The durable read on mount/reload, `graphModelForCase` (`agent/session.ts:1508`), rebuilds the graph from **finalized run records only.**

**So any interruption before finalize loses everything since the last finalized run:**
- **ISSUE-1 (abort):** abort skips finalize → nothing persisted. `hydrateCaseGraph`'s in-memory retention only holds for `status === "running"` (`app.ts:1851`); the status flips to `aborted`, so the next re-hydrate cold-reads the empty vault → renders blank "Start here." The live leads are gone. Even if we persisted the aborted record, its `promoted`/`leads` are empty, so the discovered entities (empresas.com, GoDaddy, etc.) are lost regardless — they lived only as live leads.
- **ISSUE-5 (reload):** a page reload destroys the JS context → the agent loop dies (fetch cancelled), the chat stream ends ("chat stops"), and the graph rebuilds from finalized runs only (empty for an in-flight run) → "graph refreshed."

**Structural fix class:** incremental durable journal of the run (append each `agent_observed` + step to the vault as it happens) so the graph + trail rehydrate from the journal on mount/reload, independent of finalize. This is the event-log/projection direction already in the open-loops backlog. The `preferInMemory`-widening (keep in-memory on `aborted`) is only a same-session band-aid; it does NOT fix reload.

**Still open — the trigger:** WHY the run aborted with the user "just watching." The screenshot's "Done (aborted)" flash means it went through the normal terminal-event handler (`app.ts:2574/2593`), NOT a hard `clearCaseDerivedState` wipe (which silently resets the store). Candidates: the agent loop returned `stopReason:"aborted"` (a fetch/proxy/key failure surfaced as abort), or a superseding run/Stop fired. Needs a live repro with the network log. Navigation is ruled out — `app.ts:1125` deliberately keeps the run alive across nav.

## Common root cause B — the Light Table redesign shipped without the dark-mode / layout gate (ISSUE-3 + ISSUE-4)

Both ISSUE-3 and ISSUE-4 live on the SAME element — `.livetrail` at `app.css:451`, added by today's "scope-scroll-fix." That one change carried two defects: a fixed `max-height:40vh` open-forever block (layout) and a hardcoded light background (theme). Neither was caught because the redesign was not run through the repo's own gates in dark mode:
- The **dogfood-gate / design-room** rule exists but design-room was evidently not run in DARK mode — see the audit below (~27 unthemed color literals slipped through, incl. an invisible white-on-white PWA banner and a fully-broken graph legend).
- No reload / abort smoke test exists for the graph, so common cause A shipped too.

The pattern: the token migration was done by hand ("theme the last on-screen light literals") with no deterministic contrast check, so coverage is partial. This is a process gap, not just a set of typos.

## Common root cause C — the action a user reaches for is not the action that persists (ISSUE-2)

The Scope pill (the obvious control) only opens a form; a SEPARATE "Save scope" button is the real writer, and it also force-starts a run. There's no precondition/guard warning that scope is empty. Decoupled effect + no validation gate = the user's intent silently drops.

---

# WHAT ELSE IS BROKEN (staff-eng audit — not yet reported by the founder)

## Persistence (generalizes common cause A)
1. **All partial run output is lost on any interruption**, not just the graph: the findings, the brief, the step trail, and the token spend are only durable at finalize. A long run that errors near the end loses everything AND the tokens already spent are uncounted (real cost leak).
2. **A mid-run case switch or vault re-apply hard-wipes the run** (`clearCaseDerivedState`, `app.ts:233-241`) — aborts + clears `lastGraphModel` + resets the run store. The code itself flags a cross-case trail-replay confidentiality concern here. Any auto re-apply of the vault mid-run = silent kill + wipe.
3. **No test covers** abort→graph-preserved or reload→rehydrate. The one graph-hydration smoke only checks the running-mount precedence.

## Dark mode (generalizes common cause B) — ~27 hardcoded color spots
Highest value first:
- **PWA update banner** (`app.css:347,349`) — `background:var(--ink); color:#fff`. In dark, `--ink` is near-white → white-on-white, invisible.
- **Graph legend strip** (`app.ts:3893,3899,3937-3960`) — hardcoded light-theme text `#57534E` + swatch/dot colors `#1A1A19`/etc. The graph itself re-styles on theme toggle but this legend does NOT → invisible AND mismatched with the graph it labels.
- **Status/badge colors dark-on-dark** (~15 spots): finding-state on-graph green `#15803D` (`app.css:880,889`), brief badges (`app.css:916-918`), process errors (`app.css:951,955`), alert severities (`app.css:596`), gap chips (`app.css:804,805`), stale-deliverable (`app.css:751,752`). Each has a matching dark token (`--c-sev-*`, `--err`) that's being ignored.
- **Bright "light islands" in dark** (`app.css:655,799,800,892,712`) — warn chips / gap panels with fixed `#FEF6EC` backgrounds.

## Light mode also has holes
- The process-progress popover (`app.ts:1890-1899`) and the toast (`app.ts:446-449`) are forced-dark (`#16202e`/`#e8eef6`) → off-theme dark islands in LIGHT mode.

## NOT bugs (confirmed, leave alone)
- `.report-doc` / print deliverable is deliberately always-white (documented).
- `.chat-stop` red button — conventional in both themes.
- `cy-graph.ts` / `surface.ts` hex are `var(--token, fallback)` fallbacks; the graph re-reads tokens on the `kipi-theme` event, so they ARE theme-aware.

## Scope subsystem (generalizes common cause C)
- `saveScope` conflates persist + run — no way to just set scope and stop.
- Typed-but-unsaved scope form text is silently discarded if you click anything but "Save scope" (data loss).
- The typed `scope <q>` command also only opens the form; never persists.

## Cross-cutting / not yet investigated
- **Multi-tab:** single-writer vault + two tabs on the same case = write race / clobber risk. Unverified.
- **The abort trigger itself** (common cause A "still open") — the actual reason the watched run aborted is unproven; needs a live repro with the network tab.

---

# UNIFIED RCA (2026-07-07, after the scope reproducer)

The five issues are TWO root causes, not five bugs.

## Unified root cause X — durability is never confirmed at the moment state is created (ISSUE-1, ISSUE-2, ISSUE-5)

Every piece of state Hydra shows as "saved" is written to the in-memory doc first and made durable LATER, unconfirmed. Two mechanisms, one failure mode:
- **Fire-and-forget write** (`putTradecraft`, `session.ts:4687`): scope + gate results. The async `vault.put` is not awaited → the durable write races a reload and loses. **Reproduced: `null` on reload.** (ISSUE-2.)
- **Deferred-to-finalize write** (`runInvestigation`, `session.ts:447`): the whole run — graph, findings, brief — is written only at the END. The live graph is grown in memory and never persisted incrementally → abort/reload before finalize loses it. (ISSUE-1, ISSUE-5.)

In BOTH, the in-session experience looks correct (in-memory reads succeed), so the bug is invisible until a reload or interruption. That's why the founder sees "it didn't save" and "it reset to the start" — same underlying defect, different surface.

The deep fix is one principle: **a write is not done until its durable put is awaited; and long-lived work (a run) must journal incrementally, not checkpoint once at the end.**

## Unified root cause Y — the Light Table redesign shipped render-layer gaps past its own gate (ISSUE-3, ISSUE-4)

Both live on `.livetrail` / `app.css:451` (today's scope-scroll-fix): a 40vh open-forever block with no collapse (layout) AND a hardcoded light background (theme). Plus ~27 unthemed color literals across the app. Cause: the token migration was hand-done with no deterministic contrast check and design-room was not run in dark mode.

---

# HOLISTIC FIX PLAN

## Fix X (durability) — do these together
1. **Await the fire-and-forget write.** `putTradecraft` → `return vault.put(...)`; make it `async`. `recordScope` and the gate writer → `await putTradecraft(...)`. `deps.recordScope` (`app.ts:2172`) → `async`, await it. `saveScope` (`dock.ts:334`) → `await deps.recordScope(...)` BEFORE `pushAside`/`runCaseMode`. (Reproducer already proves the awaited write survives.)
2. **Incrementally journal the run.** Persist each `agent_observed` (and step) to the vault as it streams — an append-only `run-journal:<id>` — so the graph + trail rehydrate from the journal on mount/reload independent of finalize. On abort, the journal is the durable record. This is the event-log direction already in the open-loops backlog. Fixes ISSUE-1 + ISSUE-5 properly (the `preferInMemory`-on-aborted patch is only a same-session band-aid; drop it in favor of the journal).
3. **Persist partial run output on abort/error**, not just finalize (findings, brief, spent tokens).
4. **Harden the `busy` no-ops:** `saveScope` should surface "a run is in progress — stopped it / try again" instead of silently returning; decouple Save from auto-run.
5. **Regression tests:** the scope reproducer (keep it, flip to assert survival after the fix); a run-abort → graph-preserved smoke; a reload → rehydrate smoke.

## Fix Y (render layer)
1. `.livetrail` (`app.css:451`): background → `rgb(var(--c-bg-soft) / 0.5)`; add a collapse toggle + `.livetrail.collapsed { max-height:0 }`; add a `min-height` floor to `.chat-scroll`.
2. Sweep the ~27 hardcoded color literals (see the dark-mode audit above) onto theme tokens — start with the PWA update banner + graph legend (both fully broken in dark).
3. **Process gate:** run design-room in BOTH themes on the workspace before shipping; add a deterministic dark-mode contrast check so this can't silently regress.

## Sequencing
Y1 (one CSS line + toggle) is the fast visible win. Then Fix X items 1+4 (small, high-impact: scope/gates actually save). Then X2/X3 (the journal — the real structural fix, needs a short design). Y2 sweep and the tests land alongside.
