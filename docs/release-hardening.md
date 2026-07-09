# kipi-web Release Hardening

The release-hardening posture for the 100% client-side app (PRD-10). Three founder-bound
concerns from docs/17 §5 ("push updates, change things, get feedback"):

## 1. Get feedback (rel-feedback) — SHIPPED

The ONLY founder-bound channel, and it carries ZERO case data. A "Send feedback" anchor
(`src/feedback.ts`) opens a pre-filled GitHub issue (`github.com/assafkip/kipi/issues/new`)
that the user reviews and submits themselves. It is a navigation target, not a fetch:
github.com is NOT in the CSP `connect-src`, so nothing is sent programmatically. The URL
builder takes no arguments, so no case/vault content can be interpolated. Disclosure on the
control: "We never see your cases. This opens a GitHub issue with only the text you type."
(docs/17 §5.3.)

## 2. Push updates + version pinning (rel-pwa) — SHIPPED

An installable PWA: `public/manifest.webmanifest` + maskable 192/512 icons + a
**network-first** service worker (`public/sw.js`). Fresh code online (no stale-serve);
the cache is a pure offline fallback restricted to an explicit allowlist of immutable,
query-less, same-origin static assets + the app shell — never the vault (OPFS/IndexedDB
never pass through `fetch`). **Opt-in version pinning:** a new SW installs and WAITS; the
app surfaces "A new version is ready — reload to update" and only the user's click adopts
it (`SKIP_WAITING` → controllerchange → one reload). The founder pushes to the code plane;
the user decides when to run it. (docs/17 §5.1.)

## 3. SRI / reproducible / signed build (rel-integrity) — DECISIONS

### D3: SRI subresource-integrity attributes are NOT added (OUT-redundant)

SRI defends against a **tampered third-party / CDN subresource**. That threat does not
exist here:

- **Zero CDN.** Every asset (Cytoscape, PDF.js, SheetJS, Tesseract, fonts) is bundled and
  served same-origin. `npm run leakgate` proves no off-allowlist origin in `src` or `dist`.
- **CSP `script-src 'self'` / `style-src 'self'`.** The browser will not load a script or
  style from any other origin, with or without an integrity hash.
- **Immutable content-hashed filenames.** Vite emits `index-<hash>.js`; any byte change
  changes the hash and therefore the URL — tamper is self-evident at the filename level.

Adding SRI would be belt-on-belt over a same-origin-only, CSP-locked, content-hashed
bundle. It is intentionally out of scope. The runtime-integrity guarantee is the egress
wall (CSP + leakgate + the spine CSP smoke `tests/smoke/spine.spec.ts`), which is the
all-directives self-test the PRD references.

### D4: build provenance = signed git tags on the public OSS repo

kipi ships public (Elastic License 2.0) at `github.com/assafkip/kipi` (the
public-oss-release record). Release provenance is a **signed git tag** per release on that
repo — the auditable, reproducible source for any deployed bundle. A binary code-signing
pipeline is not applicable to a static SPA (there is no installer/binary to sign; the PWA
is plain static bytes whose integrity is already covered by D3).
