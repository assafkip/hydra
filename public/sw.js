// rel-pwa: the kipi-web service worker. NETWORK-FIRST so the app is always fresh online (no stale-code
// serving — the stale-code scar); the cache is a pure OFFLINE fallback. It does NOT skipWaiting on its
// own (a new version WAITS until the user reloads = opt-in version pinning); it skips only when the page
// posts SKIP_WAITING (the user clicks "Update ready — reload").
//
// SECURITY (codex): the cache is restricted to an EXPLICIT allowlist of immutable, query-LESS,
// same-origin static assets + the app shell — NEVER an arbitrary same-origin predicate. A request with
// any query string is never cached (a cache key must never carry case/search/key material). Vault data
// lives in OPFS/IndexedDB and never passes through fetch(), so the SW never sees it; this allowlist is
// defense-in-depth so a future same-origin export/report/debug route can't be persisted either.

const VERSION = "kipi-cache-v1";
const SHELL = ["/", "/index.html", "/manifest.webmanifest", "/icon-192.png", "/icon-512.png"];

// A request is cacheable iff: GET, same-origin, NO query string, and its path is the app shell OR an
// immutable build asset (/assets/*) OR a bundled engine asset (/tesseract/*). Everything else passes
// through to the network and is NEVER written to the cache.
function isCacheable(request) {
  if (request.method !== "GET") return false;
  let url;
  try {
    url = new URL(request.url);
  } catch {
    return false;
  }
  if (url.origin !== self.location.origin) return false;
  if (url.search) return false; // never key a cache entry on a query string
  if (url.pathname === "/sw.js") return false; // never cache the worker itself
  return (
    SHELL.includes(url.pathname) ||
    url.pathname.startsWith("/assets/") ||
    url.pathname.startsWith("/tesseract/")
  );
}

self.addEventListener("install", (event) => {
  // precache the shell so the app opens offline; do NOT skipWaiting (version pinning)
  event.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).catch(() => {}));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // drop any older-version caches, then control existing tabs
      const keys = await caches.keys();
      await Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)));
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("message", (event) => {
  // the user approved an update ("reload"): adopt the waiting worker now
  if (event.data && event.data.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", (event) => {
  const { request } = event;

  // Navigations: network-first (fresh app online), fall back to the cached shell offline.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(() => caches.match("/").then((r) => r || caches.match("/index.html"))),
    );
    return;
  }

  // Allowlisted static assets: network-first, cache the fresh copy, fall back to cache offline.
  if (isCacheable(request)) {
    event.respondWith(
      (async () => {
        try {
          const res = await fetch(request);
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(VERSION).then((c) => c.put(request, copy)).catch(() => {});
          }
          return res;
        } catch {
          const cached = await caches.match(request);
          if (cached) return cached;
          throw new Error("offline and not cached");
        }
      })(),
    );
    return;
  }

  // Everything else (cross-origin API/OSINT calls, query'd or non-GET requests): pass through to the
  // network untouched and NEVER cache. The CSP connect-src wall still governs these at runtime.
});
