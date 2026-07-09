// Tailwind config — LIGHT TABLE redesign (Hydra 2026-07-06). Compiled at BUILD time (no
// cdn.tailwindcss.com runtime — leak F1); the shipped bundle is plain CSS, leakgate stays green.
//
// Colors are now backed by the CSS-variable triplet palette defined in src/styles/app.css
// (:root = light bench, :root[data-theme="dark"] = bench at night). rgb(var(--c-x) / <alpha-value>)
// keeps Tailwind's opacity modifiers (bg-ink/30, bg-bg/85) working while making every utility
// theme-aware. darkMode is driven by the same [data-theme="dark"] attribute the toggle sets.
/** @type {import('tailwindcss').Config} */
const c = (v) => `rgb(var(${v}) / <alpha-value>)`;
export default {
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./index.html", "./src/**/*.{ts,js,html}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        display: ["Space Grotesk", "Inter", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      colors: {
        bg: {
          DEFAULT: c("--c-bg"),
          soft: c("--c-bg-soft"),
          card: c("--c-card"),
          border: c("--c-border"),
          line: c("--c-line"),
        },
        ink: { DEFAULT: c("--c-ink"), muted: c("--c-ink-muted"), faint: c("--c-ink-faint") },
        accent: { DEFAULT: c("--c-accent"), hover: c("--c-accent-hover"), ink: c("--c-accent-ink") },
        role: {
          operator: c("--c-role-operator"),
          channel: c("--c-role-channel"),
          ioc: c("--c-role-ioc"),
          infra: c("--c-role-infra"),
          source: c("--c-role-source"),
        },
        conf: { high: c("--c-conf-high"), medium: c("--c-conf-medium"), low: c("--c-conf-low") },
        sev: { high: c("--c-sev-high"), med: c("--c-sev-med"), low: c("--c-sev-low") },
        status: { new: c("--c-status-new"), up: c("--c-status-up"), down: c("--c-status-down") },
        seed: c("--c-seed"),
      },
      boxShadow: {
        card: "0 1px 2px rgba(28,25,23,0.04), 0 1px 3px rgba(28,25,23,0.06)",
        pop: "0 8px 24px rgba(28,25,23,0.10), 0 2px 6px rgba(28,25,23,0.06)",
      },
    },
  },
};
