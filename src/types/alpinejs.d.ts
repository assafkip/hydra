// Alpine.js ships no bundled type declarations; we use only Alpine.start(). A minimal
// ambient module keeps tsc --noEmit (strict) green without pulling another dependency.
declare module "@alpinejs/csp" {
  const Alpine: { start(): void; data(name: string, cb: () => unknown): void; [k: string]: unknown };
  export default Alpine;
}
