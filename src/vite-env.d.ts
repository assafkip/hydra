// rel-pwa: minimal ambient typing for the Vite build-env flags this app reads. Vite statically
// replaces `import.meta.env.PROD` at build time (true for `vite build`, false for `vite dev`), so the
// service-worker registration is a no-op in the dev loop. Kept minimal (not the full vite/client) to
// respect the tsconfig `types` allowlist.
interface ImportMetaEnv {
  readonly PROD: boolean;
  readonly DEV: boolean;
  readonly MODE: string;
  // sec: gates the window.__kipi debug bridge. Set (VITE_KIPI_DEBUG=1) only by the smoke build
  // (playwright.config); a prod build omits it so the bridge is stripped from the shipped bundle.
  readonly VITE_KIPI_DEBUG?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}
