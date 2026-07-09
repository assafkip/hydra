// Entry point. Self-hosted fonts + Tailwind CSS + Alpine's CSP build are BUNDLED here (no CDN — the
// webapp loaded these from unpkg/jsdelivr/Google Fonts, which is leak F1/F2; bundling them
// into the signed app reproduces the exact UI while keeping script-src/font-src 'self').
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/space-grotesk/500.css";
import "@fontsource/space-grotesk/600.css";
import "@fontsource/space-grotesk/700.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./styles/app.css";

import Alpine from "@alpinejs/csp";
import { bootstrapTheme, currentTheme, toggleTheme, type Theme } from "./theme.js";

// Paint the saved LIGHT TABLE theme onto <html> before Alpine renders (minimal FOUC).
bootstrapTheme();

declare global {
  interface Window {
    Alpine: typeof Alpine;
  }
}
window.Alpine = Alpine;

interface ShellState {
  searchOpen: boolean;
  sidebarOpen: boolean;
  caseMenuOpen: boolean;
  sidebarHidden: boolean;
  navOpen: Record<string, boolean>;
  theme: Theme;
  init(): void;
  toggleSidebar(v: boolean): void;
  toggleTheme(): void;
  navSectionOf(): string | null;
  expandActiveSection(): void;
}
type ShellThis = ShellState & {
  $watch(key: string, cb: (value: Record<string, boolean>) => void): void;
};

Alpine.data("shell", (): ShellState => ({
  searchOpen: false,
  sidebarOpen: false,
  caseMenuOpen: false,
  sidebarHidden: false,
  navOpen: {} as Record<string, boolean>,
  theme: currentTheme(),
  init(this: ShellThis) {
    try {
      this.sidebarHidden = localStorage.getItem("kipiSidebarHidden") === "1";
    } catch {
      this.sidebarHidden = false;
    }
    try {
      const parsed = JSON.parse(localStorage.getItem("kipiNavOpen") || "{}");
      this.navOpen = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
    } catch {
      this.navOpen = {};
    }
    this.expandActiveSection();
    this.$watch("navOpen", (v: Record<string, boolean>) => {
      try {
        localStorage.setItem("kipiNavOpen", JSON.stringify(v));
      } catch {
        /* localStorage can be unavailable in hardened/private contexts */
      }
    });
  },
  toggleSidebar(this: ShellState, v: boolean) {
    this.sidebarHidden = v;
    try {
      localStorage.setItem("kipiSidebarHidden", v ? "1" : "0");
    } catch {
      /* localStorage can be unavailable in hardened/private contexts */
    }
  },
  toggleTheme(this: ShellState) {
    // Flip light↔dark, persist, and mirror into reactive state so the toggle icon updates.
    this.theme = toggleTheme();
  },
  navSectionOf() {
    const r = location.hash.replace(/^#/, "");
    if (["/entities", "/clusters", "/bridges", "/focus", "/cross-case", "/cross-domain", "/alerts"].includes(r)) return "analysis";
    if (["/deliverables", "/exports", "/report"].includes(r)) return "deliver";
    if (["/inbox", "/corrections", "/activity", "/cases", "/account"].includes(r)) return "admin";
    return null;
  },
  expandActiveSection(this: ShellState) {
    const s = this.navSectionOf();
    if (s) this.navOpen[s] = true;
  },
}));

Alpine.start();

// App logic + the smoke debug API. Imported after Alpine so the shell is reactive first.
import "./app.js";
