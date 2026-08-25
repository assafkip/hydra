# Hydra

A 100% client-side OSINT investigation tool. Bring your own keys, zero data collection.

Live at **[hydra.ktlystlabs.com](https://hydra.ktlystlabs.com)**.

Hydra runs entirely in your browser. Your cases, your keys, and your evidence never leave your device un-encrypted, and never reach us. There is no server that sees your data.

## What it does

- **Browser-native OSINT** — DNS-over-HTTPS, RDAP (whois), certificate transparency, reverse-IP, on-chain wallet lookups, identity and breach checks, and more, run live from the browser with no proxy and no key.
- **Bring your own keys** — add your own Anthropic and OSINT provider keys; they live in an encrypted local vault and are called directly from your browser.
- **Zero-knowledge vault** — your master password derives a local key that never leaves the browser. Cases are AES-GCM encrypted at rest. We cannot decrypt your vault.
- **Egress wall** — an all-directives Content-Security-Policy allowlist blocks any request to an origin the app doesn't explicitly use. A build-time leak gate proves the bundle fetches nothing off the allowlist.
- **Investigation graph + agent** — a live entity graph, structured analytic tradecraft, and a browser-side agent loop that runs the OSINT tools for you.

## Who it is for

- OSINT and threat-intelligence investigators who cannot push case data through
  someone else's server
- Journalists and due-diligence researchers who need defensible, local-only
  evidence trails
- Security teams that want AI-assisted lookups without pasting case details
  into a chat window

## Trust model

Three properties, each enforced rather than promised:

1. **No collection.** There is no backend. The deployed site is static files;
   your queries go from your browser directly to the data sources.
2. **Encryption you control.** AES-GCM cases under a key derived from your
   master password. Losing the password loses the vault; we never held it.
3. **A provable egress wall.** A build-time gate fails the bundle if it can
   fetch anything outside the explicit allowlist.

## Run it locally

```bash
npm install
npm run dev      # local dev server
npm run build    # production build to dist/
npm test         # unit + integration tests
```

Node 20+ recommended.

## Privacy model

Every OSINT lookup goes directly from your browser to that provider — so the provider sees the single target you query (and your IP, as with any web request), never your case data, your keys, or anything else, and nothing goes to us. Keyed providers use keys you supply, stored only in your encrypted local vault.

## License

[MIT](./LICENSE) © Assaf Kipnis
