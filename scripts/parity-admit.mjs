// parity-admit — kipi-side admission gate for the reversed-noise-FLOOR boundary (issue
// prd-pv3-noise-floor-reverse). PURE stdin-JSON -> stdout-JSON over the REAL gate (agent/gate.ts
// isAdmissible, the verbatim port of investigations/admission.py). No new logic.
//
// stdin: a JSON array of {type, value, prevalidated?}. stdout: the same items with
// {admitted: boolean, reason: string}. The Python noise_floor diffs this against the original.
import { isAdmissible } from "../src/agent/gate.ts";

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => (buf += d));
process.stdin.on("end", () => {
  try {
    const probes = JSON.parse(buf);
    const out = probes.map((p) => {
      const [admitted, reason] = isAdmissible(p.type, p.value, !!p.prevalidated);
      return { type: p.type, value: p.value, admitted, reason };
    });
    process.stdout.write(JSON.stringify(out));
  } catch (e) {
    process.stderr.write(`parity-admit: ${e?.stack || e}\n`);
    process.exit(1);
  }
});
process.stdin.on("error", (e) => {
  process.stderr.write(`parity-admit: ${e}\n`);
  process.exit(1);
});
