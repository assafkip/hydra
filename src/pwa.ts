// rel-pwa: register the service worker (PROD only) and surface an OPT-IN "Update ready — reload" bar.
// Version pinning: a new SW installs and WAITS; the app never auto-adopts it. The bar lets the user
// approve the update, which posts SKIP_WAITING to the waiting worker and reloads once it takes control.
// Dev keeps no SW (registration is gated on import.meta.env.PROD) so the dev loop is never cached.

// Only a USER-APPROVED update reloads the page. The initial clients.claim() also fires controllerchange
// (first install), and that must NOT reload — so the reload is gated on this flag, set only when the
// user clicks "Reload to update".
let userApprovedUpdate = false;

function showUpdateBar(waiting: ServiceWorker): void {
  if (document.getElementById("pwa-update")) return; // one bar at a time
  const bar = document.createElement("div");
  bar.id = "pwa-update";
  bar.className = "pwa-update";
  bar.setAttribute("role", "status");

  const msg = document.createElement("span");
  msg.textContent = "A new version of kipi is ready.";

  const reload = document.createElement("button");
  reload.textContent = "Reload to update";
  reload.addEventListener("click", () => {
    // adopt the waiting worker, then reload once it controls the page (a single, user-approved swap)
    userApprovedUpdate = true;
    waiting.postMessage({ type: "SKIP_WAITING" });
  });

  const dismiss = document.createElement("button");
  dismiss.className = "ghost";
  dismiss.textContent = "Later";
  dismiss.addEventListener("click", () => bar.remove());

  bar.append(msg, reload, dismiss);
  document.body.appendChild(bar);
}

/** Register the SW and wire the opt-in update prompt. No-ops in dev or when SW is unavailable. */
export function registerServiceWorker(): void {
  if (!import.meta.env.PROD) return; // dev: never cache the live loop
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;

  window.addEventListener("load", () => {
    void navigator.serviceWorker.register("/sw.js").then((reg) => {
      // a worker already waiting (installed on a previous load) → offer the update now
      if (reg.waiting && navigator.serviceWorker.controller) showUpdateBar(reg.waiting);

      reg.addEventListener("updatefound", () => {
        const installing = reg.installing;
        if (!installing) return;
        installing.addEventListener("statechange", () => {
          // "installed" while a controller exists = an UPDATE (not the first install) → offer it
          if (installing.state === "installed" && navigator.serviceWorker.controller) {
            showUpdateBar(installing);
          }
        });
      });
    }).catch(() => {
      /* registration failed (private mode / unsupported) — the app still works, just no offline/install */
    });
  });

  // controllerchange fires both on the FIRST install (clients.claim) and on a user-approved update.
  // Reload ONLY for the latter — the initial claim must not bounce the page the user is using.
  let reloaded = false;
  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (!userApprovedUpdate || reloaded) return;
    reloaded = true;
    window.location.reload();
  });
}
