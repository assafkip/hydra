# PRD-11 disk storage — manual verification + the persistent-permission path

The File System Access API needs a real user gesture and a real OS folder dialog.
**Playwright cannot drive the native picker**, so the automated suite injects a fake
`DirectoryHandle` (`tests/vault/fake-fs.ts`) and proves the full lifecycle, the
divergence guard, the OPFS-mirror fallback, and the export/import path against it
(`disk-backend.test.ts`, `location.test.ts`, `safety.test.ts`, `disk-smoke.test.ts`).
The one thing those cannot prove — that the *real* `showDirectoryPicker` round-trips a
*real* folder — is this manual check. State the gap; do not hide it.

## Manual: real folder round-trip (Chrome / Edge / Opera, desktop)

1. `npm run build && npm run preview`, open the served URL in Chrome 122+.
2. Create a vault (any password). It is in browser storage (OPFS) — the banner says so.
3. Click **Save to a folder…**. In the dialog, pick (or make) an empty folder.
4. At the "Let site edit files?" prompt, choose **Allow on every visit**.
5. Confirm: the banner now reads *Saving to your folder: <name>*, and a `vault.json`
   file is visible in that folder in your file manager. Open it — it is sealed
   (base64 ciphertext + non-secret envelope metadata), unreadable without the password.
6. Run an OSINT pivot (saves to the vault), then **fully quit and reopen the browser**.
   Reopen the app: it should restore the folder with **no prompt** and unlock the same
   data. (If you picked "Allow on every visit" / installed the PWA, no prompt appears.)
7. Wipe test: with the browser closed, copy the folder elsewhere. Clear browsing data.
   Reopen the app, **Save to a folder…** → pick the copied folder → unlock. The cases
   survive a browser wipe. This is the whole point of PRD-11.

## Manual: portability fallback (Firefox / Safari)

1. Open the app in Firefox or Safari. The banner says *Using browser storage* and there
   is no **Save to a folder…** button (feature-detected; no disk picker on these).
2. **Export vault** downloads `vault.json`. In another Firefox/Safari profile (or after
   clearing data), **Import vault** the file, then unlock — same cases. No capability is
   lost, it is just manual rather than automatic.

## The persistent-permission path (why the re-prompt is not a recurring tax)

The make-or-break for a non-technical user is *not being re-prompted every visit*.
Two paths remove the prompt after the first grant (researched, docs/17 section 8.1):

- **Chrome 122+ "Allow on every visit."** The permission prompt has three options; the
  third grants indefinitely. After picking it once, launch restores the folder with a
  silent `queryPermission` (our `queryGranted`) — no prompt. We never call
  `requestPermission` at launch (that would prompt); it is gesture-only.
- **Installed PWA (PRD-9).** An installed PWA **auto-persists** the permission with NO
  prompt at all. PRD-11 is built to benefit from this; the PWA install itself is PRD-9.
- **Three-strikes caveat (Chrome):** deny/dismiss the prompt more than three times and
  the prompt stops appearing for the origin. The app degrades to OPFS + a re-grant
  button; the OPFS mirror means no data is lost in the meantime.

## What is covered where (no silent gaps)

| Claim | Covered by |
|---|---|
| diskStorage read/write/remove, atomic, name-agnostic | `disk-backend.test.ts` (fake handle) |
| mirror writes both, reads disk-then-OPFS, divergence guard | `disk-backend.test.ts`, `safety.test.ts` |
| IndexedDB handle persist + IDB-failure degrade | `disk-backend.test.ts` (fake + throwing store) |
| query-only at launch, gesture-only request | `disk-backend.test.ts`, `location.test.ts` |
| selector: feature-detect, no silent downgrade, conflict | `location.test.ts` |
| export/import portability + zero-knowledge byte assertion | `safety.test.ts` |
| full lifecycle create→reload→restore→read + fallback | `disk-smoke.test.ts` |
| OPFS default path + the 3 spine proofs do not regress | `npm run smoke` (Playwright, real Chromium) |
| **real OS folder pick + persistent permission** | **this doc (manual)** |
