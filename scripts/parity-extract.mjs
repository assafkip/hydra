// parity-extract — kipi-side text entity extraction for the B1 boundary (issue prd-pv3-boundary-b1).
// PURE stdin-text -> stdout-JSON over the REAL extractor (src/ingest/extract.ts extractEntities,
// a verbatim port of investigations/ingest/extractor.py). No new logic; the Python b1_extraction
// diffs this against the original extract_all on the same text.
import { extractEntities } from "../src/ingest/extract.ts";

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (buf += d));
process.stdin.on("end", () => {
  try {
    const entities = extractEntities(buf);
    process.stdout.write(JSON.stringify({ entities }));
  } catch (e) {
    process.stderr.write(`parity-extract: ${e?.stack || e}\n`);
    process.exit(1);
  }
});
process.stdin.on("error", (e) => {
  process.stderr.write(`parity-extract: ${e}\n`);
  process.exit(1);
});
