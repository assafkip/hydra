import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = "dist";
const failures = [];

function fail(msg) {
  failures.push(msg);
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const rel = relative(ROOT, path);
    if (statSync(path).isDirectory()) walk(path, out);
    else out.push(rel);
  }
  return out;
}

if (!statSync(ROOT, { throwIfNoEntry: false })?.isDirectory()) {
  fail("dist/ is missing. Run npm run build first.");
} else {
  const files = walk(ROOT);
  const names = new Set(files);
  if (!names.has("_headers")) fail("dist/_headers is missing, so Cloudflare Pages would miss the CSP header.");

  for (const rel of files) {
    if (/^(\.env|q-system\/|\.claude\/|\.prd-os\/|plugins\/|\.agents\/|investigations\/|inbox\/|vault\/)/.test(rel)) {
      fail(`forbidden release path in dist: ${rel}`);
    }
    if (/\.(db|sqlite|sqlite3|db-wal|db-shm|pem|key)$/i.test(rel)) {
      fail(`sensitive file extension in dist: ${rel}`);
    }
    const path = join(ROOT, rel);
    const size = statSync(path).size;
    if (size <= 2_000_000) {
      const text = readFileSync(path, "utf8");
      if (/sk-ant-[A-Za-z0-9_-]{20,}/.test(text)) fail(`Anthropic-looking key in dist file: ${rel}`);
      if (/AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}/.test(text)) fail(`credential-looking token in dist file: ${rel}`);
    }
  }

  const csp = names.has("_headers") ? readFileSync(join(ROOT, "_headers"), "utf8") : "";
  if (csp.includes("'unsafe-eval'")) fail("dist CSP contains general unsafe-eval.");
  if (!csp.includes("'wasm-unsafe-eval'")) fail("dist CSP is missing wasm-unsafe-eval needed by bundled MuPDF WASM.");
}

if (failures.length) {
  console.error("release dist audit failed:");
  for (const f of failures) console.error(`- ${f}`);
  process.exit(1);
}

console.log("release dist audit clean");
