// LIGHT TABLE theme control (Hydra redesign 2026-07-06). Light + dark on one token palette
// (src/styles/app.css). The theme is a single [data-theme] attribute on <html>; every surface —
// the Tailwind shell utilities and the custom CSS layer — re-derives from it, and cy-graph.ts
// re-styles the bench on toggle.
//
// Default is LIGHT (the "Light Table" first impression + deterministic for the smoke screenshots).
// Dark is opt-in and persisted; we do NOT auto-follow prefers-color-scheme so CI renders stay stable.
// No network, no new origin — pure localStorage + a DOM attribute (leakgate-neutral).

export type Theme = "light" | "dark";
const KEY = "kipiTheme";

/** The saved theme, or "light" when nothing is stored / storage is unavailable. */
export function resolvedTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

/** The theme currently painted on <html> (falls back to the resolved default). */
export function currentTheme(): Theme {
  const t = document.documentElement.dataset.theme;
  return t === "dark" ? "dark" : t === "light" ? "light" : resolvedTheme();
}

/** Paint a theme onto <html> and notify listeners (cy-graph re-styles on this event). */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    window.dispatchEvent(new CustomEvent("kipi-theme", { detail: theme }));
  } catch {
    /* CustomEvent unavailable in some hardened contexts — the attribute is still set */
  }
}

/** Set the theme on <html> AND persist it. */
export function setTheme(theme: Theme): void {
  applyTheme(theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* localStorage can be unavailable in hardened/private contexts */
  }
}

/** Flip light↔dark, persist, and return the new theme. */
export function toggleTheme(): Theme {
  const next: Theme = currentTheme() === "dark" ? "light" : "dark";
  setTheme(next);
  return next;
}

/** Paint the resolved theme before first render (called at module load, pre-Alpine). */
export function bootstrapTheme(): void {
  applyTheme(resolvedTheme());
}
