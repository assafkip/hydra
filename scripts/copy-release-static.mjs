import { copyFileSync, existsSync } from "node:fs";

if (!existsSync("dist")) {
  throw new Error("dist/ does not exist. Run vite build before copying release static files.");
}

copyFileSync("_headers", "dist/_headers");
console.log("Release static files copied: _headers -> dist/_headers");
