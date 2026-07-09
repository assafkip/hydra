import { defineConfig, devices } from "@playwright/test";

// Browser smoke: builds the app and serves the real dist via `vite preview`, then
// drives Chromium. Proves the three spine claims in a real browser (PRD I5).
export default defineConfig({
  testDir: "tests/smoke",
  timeout: 60_000,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: "http://localhost:4174", trace: "off" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // sec: VITE_KIPI_DEBUG=1 keeps window.__kipi in THIS (smoke) build; a prod build omits it (stripped).
    // sp-b8e84e28: clear any stale listener on 4174 before binding. `prd_runner gates run` executes
    // gates SERIALLY (no concurrency), but three playwright gates share this hardcoded --strictPort 4174
    // with reuseExistingServer:false — so if a PRIOR gate's `vite preview` child orphans and still holds
    // 4174, this gate's strictPort bind fails hard (RED in the full sweep, green standalone). The
    // pre-clear makes the bind deterministic. Verified: occupied-port bind FAILS; the kill-prefix frees
    // it and the bind SUCCEEDS. (The earlier "concurrent port race" hypothesis was wrong — gates are serial.)
    command: "PIDS=$(lsof -ti tcp:4174 2>/dev/null); [ -n \"$PIDS\" ] && kill -9 $PIDS 2>/dev/null; VITE_KIPI_DEBUG=1 npm run build && npx vite preview --port 4174 --strictPort",
    url: "http://localhost:4174",
    reuseExistingServer: false,
    // cg-network: the cold build (tsc + vite build of the ~2MB pdf.worker + ~1.5MB app chunk) runs
    // ~90s and overran the old 120s cap whenever the machine was loaded, failing every smoke with a
    // webServer timeout (not a test failure). 300s gives the build headroom under load.
    timeout: 300_000,
  },
});
