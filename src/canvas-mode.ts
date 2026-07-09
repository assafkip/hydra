// ccc-hybrid-routes (PRD prd-chat-control-center, issue 4): the canvas-mode controller. In the Chat
// Control Center, detail routes no longer REPLACE the app with a full page — they surface OVER the
// persistent workspace (graph + chat):
//   - NARRATIVE routes (a story/summary the analyst reads in the conversation: runs, briefs, alerts,
//     activity, a single report, deliverables) post as a chat card in the dock.
//   - DENSE / tabular routes (entities, exports, corrections, cross-case, the graph-analysis lists) take
//     over the graph canvas as an ANIMATED overlay with a "close → graph" control. The graph stays
//     mounted underneath; closing just removes the overlay, and a row-click (handled by the page itself)
//     navigates + refocuses the graph beneath.
// This module is PURE DOM — no app.ts/vault/cytoscape imports — so it can't drift into the spine. app.ts
// hands it the already-rendered page content (the same renderXPage output, so the parity rows stay green)
// plus the close/navigate callback.

export type RouteKind = "narrative" | "dense";

// Every detail route is classified explicitly — no silent fallthrough. (Home "/", and the config screens
// "/account" + "/enrich" + "/capabilities", are handled by app.ts's render() and never reach here.)
const NARRATIVE = new Set(["/runs", "/deliverables", "/briefs", "/alerts", "/activity", "/report"]);
const DENSE = new Set([
  "/entities", "/clusters", "/bridges", "/focus", "/cross-case", "/cross-domain",
  "/corrections", "/exports", "/reports", "/inbox", "/cases",
]);

/** True for the 17 detail routes that surface over the workspace (vs home / the config screens). */
export function isDetailRoute(route: string): boolean {
  return NARRATIVE.has(route) || DENSE.has(route);
}

/** dense (tabular → canvas takeover) vs narrative (story → chat card). Dense is the explicit set; every
 *  other detail route reads as narrative (the non-destructive surfacing — a card never hides the graph). */
export function routeKind(route: string): RouteKind {
  return DENSE.has(route) ? "dense" : "narrative";
}

/** Friendly title for the takeover bar / narrative card header. */
export function detailRouteLabel(route: string): string {
  const map: Record<string, string> = {
    "/entities": "Entities",
    "/clusters": "Clusters",
    "/bridges": "Bridges",
    "/focus": "Focus",
    "/runs": "Runs",
    "/deliverables": "Deliverables",
    "/briefs": "Briefs",
    "/cross-case": "Cross-case",
    "/cross-domain": "Cross-domain",
    "/corrections": "Corrections",
    "/exports": "Exports",
    "/reports": "Reports & intake",
    "/inbox": "Inbox",
    "/cases": "Cases",
    "/activity": "Activity",
    "/report": "Report",
    "/alerts": "Alerts",
  };
  return map[route] ?? route.replace(/^\//, "");
}

/**
 * Mount `content` as an animated takeover over `graphPane`, with a "close → graph" control wired to
 * `onClose`. The graph stays mounted underneath. Inline-styled (app.css is out of this issue's scope);
 * the panel fades + slides in on the next frame. Returns the overlay element.
 */
export function mountCanvasTakeover(
  graphPane: HTMLElement,
  title: string,
  content: HTMLElement,
  onClose: () => void,
): HTMLElement {
  const overlay = document.createElement("div");
  overlay.className = "canvas-takeover";
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-label", title);
  Object.assign(overlay.style, {
    position: "absolute", inset: "0", zIndex: "30", display: "flex", flexDirection: "column",
    background: "var(--bg)", opacity: "0", transform: "translateY(8px)",
    transition: "opacity .18s ease, transform .18s ease", overflow: "hidden",
  });

  const bar = document.createElement("div");
  Object.assign(bar.style, {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "8px 14px", borderBottom: "1px solid var(--border)", background: "var(--card)", flex: "0 0 auto",
  });
  const label = document.createElement("span");
  label.textContent = title; // textContent — never markup
  Object.assign(label.style, { fontWeight: "600", fontSize: "13px", color: "var(--ink)" });
  const close = document.createElement("button");
  close.type = "button";
  close.className = "ghost";
  close.textContent = "✕ close → graph";
  close.title = "Close and return to the graph";
  Object.assign(close.style, { margin: "0", fontSize: "12px" });
  close.addEventListener("click", onClose);
  bar.append(label, close);

  const body = document.createElement("div");
  Object.assign(body.style, { flex: "1", minHeight: "0", overflow: "auto", padding: "0 4px" });
  body.appendChild(content);

  overlay.append(bar, body);
  graphPane.appendChild(overlay);
  // animate in on the next frame (the initial opacity/transform are painted first, then transitioned)
  requestAnimationFrame(() => {
    overlay.style.opacity = "1";
    overlay.style.transform = "translateY(0)";
  });
  return overlay;
}
