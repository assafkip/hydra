import { defineConfig } from "vitest/config";

// kipi-web is a static SPA. No third-party runtime deps: the shipped bundle must
// contain only first-party code (audit finding F1 — a CDN/third-party script in
// the vault context can read the vault). The leak gate (scripts/leakgate.mjs)
// enforces that no external origin appears in dist.
export default defineConfig({
  build: { target: "es2022", sourcemap: false },
  // The dep pre-bundler (esbuild) defaulted to a target without top-level await, so `vite` (dev) crashed on
  // mupdf's TLA even though `vite build` (es2022) was fine. Pin the dev optimizer to es2022 too so the dev
  // server actually starts. Dev-only — does not touch the shipped bundle or the leak gate. (founder 2026-07-08)
  optimizeDeps: { esbuildOptions: { target: "es2022" } },
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/smoke/**"],
    // The Argon2id KDF (vault create/unlock/recover) is deliberately slow; under parallel CPU
    // contention (e.g. the full `gates run` driving many suites at once) it exceeded the 5s default and
    // flaked the vault/bridges suites — a non-deterministic gate. Generous timeouts keep parallelism
    // (fast normal runs) while giving the KDF headroom so the gate is reliable, not flaky.
    // Bumped 20s -> 30s (2026-07-08): a signUp-twice test (two memory-hard hashes) still hit ~22s under
    // full-suite load. Isolated it runs in <4s; the ceiling is contention headroom, not a code cost.
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
