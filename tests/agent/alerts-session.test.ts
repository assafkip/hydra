import { describe, it, expect } from "vitest";
import { Vault } from "../../src/vault/vault.js";
import { memoryStorage } from "../../src/vault/store.js";
import { setApiKey, alertsFor, ackAlert, ackAllAlerts, getAlertAck } from "../../src/agent/session.js";

// sf-alerts: alertsFor surfaces HIGH (watchlist / grade-A) + MEDIUM (cross-run) priority actors, each with a
// stable id + ack state; ackAlert / ackAllAlerts persist the analyst acknowledgement (alert:<id>:ack). The
// original alerts.py cross_case (MEDIUM) is single-vault-impossible until sf-cases — cross-RUN is its analog.

const LEAK_KEY = "sk-ant-ALERTS-secret-3434";

async function seededVault(): Promise<Vault> {
  const storage = memoryStorage();
  await Vault.create(storage, "pw");
  const vault = await Vault.unlock(storage, "pw");
  await setApiKey(vault, LEAK_KEY);
  // r1: acme.io (grade A → HIGH/watchlist) + evil.com (grade B, promoted).
  await vault.put("run:r1", {
    objective: "r1",
    steps: [],
    promoted: [
      { entity: "acme.io", entity_type: "domain", grade: "A", source_count: 3, infra_source_count: 3 },
      { entity: "evil.com", entity_type: "domain", grade: "B", source_count: 2, infra_source_count: 1 },
    ],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  // r2: evil.com again → promoted across 2 runs → MEDIUM/cross-run.
  await vault.put("run:r2", {
    objective: "r2",
    steps: [],
    promoted: [{ entity: "evil.com", entity_type: "domain", grade: "B", source_count: 2, infra_source_count: 1 }],
    leads: [],
    usage: { input: 0, output: 0 },
    stopReason: "end_turn",
  });
  return vault;
}

describe("sf-alerts — alertsFor tiers + ids", () => {
  it("emits a HIGH watchlist (grade-A) and a MEDIUM cross-run alert with stable ids", async () => {
    const vault = await seededVault();
    const alerts = alertsFor(vault);
    const watch = alerts.find((a) => a.label === "acme.io")!;
    expect(watch.severity).toBe("high");
    expect(watch.alertType).toBe("watchlist");
    expect(watch.id).toContain("watchlist|");
    expect(watch.acknowledged).toBe(false);
    const cross = alerts.find((a) => a.label === "evil.com")!;
    expect(cross.severity).toBe("medium");
    expect(cross.alertType).toBe("cross_run");
    expect(cross.runs).toBe(2);
    // HIGH sorts before MEDIUM
    expect(alerts[0].severity).toBe("high");
  });
});

describe("sf-alerts — acknowledge write-path", () => {
  it("ackAlert flips the alert to acknowledged on the next read (round-trip)", async () => {
    const vault = await seededVault();
    const watch = alertsFor(vault).find((a) => a.label === "acme.io")!;
    expect(getAlertAck(vault, watch.id)).toBe(false);
    await ackAlert(vault, watch.id);
    expect(getAlertAck(vault, watch.id)).toBe(true);
    expect(alertsFor(vault).find((a) => a.label === "acme.io")!.acknowledged).toBe(true);
  });

  it("ackAllAlerts acknowledges every open alert", async () => {
    const vault = await seededVault();
    const ids = alertsFor(vault).map((a) => a.id);
    const n = await ackAllAlerts(vault, ids);
    expect(n).toBe(ids.length);
    expect(alertsFor(vault).every((a) => a.acknowledged)).toBe(true);
  });

  it("rejects a secret-tainted alert id (never writes it) and never leaks the key", async () => {
    const vault = await seededVault();
    await expect(ackAlert(vault, `watchlist|["domain","${LEAK_KEY}.evil"]`)).rejects.toThrow();
    expect(getAlertAck(vault, `watchlist|["domain","${LEAK_KEY}.evil"]`)).toBe(false);
    // the live key never appears in any alert projection
    expect(JSON.stringify(alertsFor(vault))).not.toContain(LEAK_KEY);
  });

  // codex impl-review belt: the canonKey-lowercased [redacted] marker must be rejected case-insensitively.
  it("rejects a LOWERCASED [redacted] id (the canonKey D5 trap)", async () => {
    const vault = await seededVault();
    await expect(ackAlert(vault, `watchlist|["domain","[redacted]"]`)).rejects.toThrow();
    expect(getAlertAck(vault, `watchlist|["domain","[redacted]"]`)).toBe(false);
  });

  // codex impl-review: a secret-tainted entity produces NO alert (so no ack, no id collision).
  it("drops a secret-tainted entity from the alert list entirely", async () => {
    const storage = memoryStorage();
    await Vault.create(storage, "pw");
    const vault = await Vault.unlock(storage, "pw");
    await setApiKey(vault, LEAK_KEY);
    await vault.put("run:r1", {
      objective: "r1", steps: [],
      promoted: [{ entity: `${LEAK_KEY}.evil.com`, entity_type: "domain", grade: "A", source_count: 3, infra_source_count: 3 }],
      leads: [], usage: { input: 0, output: 0 }, stopReason: "end_turn",
    });
    const alerts = alertsFor(vault);
    expect(alerts).toHaveLength(0); // the tainted grade-A entity is not an alert
    expect(JSON.stringify(alerts)).not.toContain(LEAK_KEY);
  });
});
