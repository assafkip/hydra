import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Vault } from "../../src/vault/vault";
import { memoryStorage } from "../../src/vault/store";

// bypass_check for kweb-vault (PRD finding-14): the OPFS write primitive
// (createWritable) must appear in EXACTLY ONE file — the single-writer
// chokepoint src/vault/store.ts. Any other caller is a bypass and fails here.
function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

describe("single-writer chokepoint", () => {
  it("createWritable() appears only in src/vault/store.ts", () => {
    const files = walk("src");
    const writers = files.filter((f) => readFileSync(f, "utf8").includes("createWritable("));
    expect(writers).toEqual([join("src", "vault", "store.ts")]);
  });
});

describe("concurrent writes don't lose updates (kweb-chat-persist regression)", () => {
  // clu-chat-persist added a NEW concurrent writer: saveChat fires an un-awaited vault.put DURING an
  // intake/run write. The old put() (mutate doc → await seal → assign this.file.payload) could let the
  // later-started seal's payload be overwritten by the earlier one, dropping a key (a run record — and
  // thus a real OCR'd entity — vanished from the graph). The serialized commit() makes both survive.
  it("two un-awaited puts of distinct keys both survive a reopen", async () => {
    const storage = memoryStorage();
    const { vault } = await Vault.create(storage, "pw");
    await Promise.all([
      vault.put("run:scan.png", { entity: "8.8.8.8" }), // the intake/run write
      vault.put("chat", [{ role: "agent", text: "Intake complete" }]), // the concurrent chat write
    ]);
    const reopened = await Vault.unlock(storage, "pw"); // real persistence round-trip
    expect(reopened.get("run:scan.png")).toEqual({ entity: "8.8.8.8" }); // NEITHER write was clobbered
    expect(reopened.get("chat")).toEqual([{ role: "agent", text: "Intake complete" }]);
  });
});
