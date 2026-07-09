import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";

// prd-run-survives-navigation: the live, deterministic proof suite. It drives the REAL run path
// (__kipi.runScriptedInvestigation, the same code the chat Run uses) and the REAL case-switch / nav
// paths, then asserts the run store behaves. Built up across the serial issues:
//   - rsn-case-switch-wipe (this file, test 1): a case switch wipes the run store (no cross-case leak).
//   - rsn-reattach + rsn-run-chip add the mid-run-nav reattach + off-Workspace chip tests.

const TURNS = [
  {
    content: [
      { type: "text", text: "Resolving evil.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "evil.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  {
    content: [
      {
        type: "text",
        text:
          'Done.\n```json\n{"findings":[' +
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"}]}\n```',
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

// rsn-reattach: a run that streams a real tool step, THEN hangs in-flight (turn 2 = __waitForStop) until
// the AbortSignal fires — so the smoke can navigate AWAY while the run is still live, then return.
const TURNS_HANG = [
  {
    content: [
      { type: "text", text: "Resolving evil.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "evil.com" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 10 },
  },
  { __waitForStop: true },
];

async function freshVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
}

// kick off a hanging run and wait until it is streaming (status set + ≥1 trail step rendered).
async function startHangingRun(page: Page): Promise<number> {
  await page.evaluate((turns) => {
    (window as any)._runP = (window as any).__kipi.runScriptedInvestigation("investigate evil.com", turns);
  }, TURNS_HANG);
  // Poll via locators, NOT page.waitForFunction: the latter injects a string-eval poller that the strict
  // CSP (no 'unsafe-eval') intermittently refuses once the service worker is controlling — a real
  // ordering flake (SW poison scar). expect(locator) uses Playwright's out-of-page retry, so it is
  // deterministic under the CSP (kweb-run-chip-control-contract).
  await expect(page.locator("#status")).toContainText("Investigating");
  await expect(page.locator("#trail .step").first()).toBeVisible();
  return page.locator("#trail .step").count();
}

test("rsn-case-switch-wipe: switching cases wipes the run store (no cross-case leak)", async ({ page }) => {
  await freshVault(page); // starter case "Test case" is active
  await expect(page.locator("#case-chip")).toHaveText("Test case");

  // run a scripted investigation in case A → the store accumulates steps + a finding
  const res = await page.evaluate((turns) => (window as any).__kipi.runScriptedInvestigation("investigate evil.com", turns), TURNS);
  expect(res.promoted).toContain("93.184.216.34"); // the entity name (from the run result, not the store summary)
  const inA = await page.evaluate(() => (window as any).__kipi.runStore());
  expect(inA.steps).toBeGreaterThan(0); // the store summary is counts only (no entity strings — secret-safe)
  expect(inA.findings).toBeGreaterThan(0);

  // create + switch to case B via /cases (createCase → switchCase → clearCaseDerivedState)
  await gotoRoute(page, "/cases");
  await page.locator(".case-name-input").fill("Case Bravo");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Case Bravo", { timeout: 10_000 });

  // the run store is EMPTY for case B — case A's trail/findings can never replay here (confidentiality)
  const inB = await page.evaluate(() => (window as any).__kipi.runStore());
  expect(inB.steps).toBe(0);
  expect(inB.findings).toBe(0);
  expect(inB.leads).toBe(0);
  expect(inB.status).toBe("idle");
});

test("rsn-reattach: a run survives nav to OSINT (full page-view teardown) and reattaches on return", async ({ page }) => {
  await freshVault(page);
  const stepsBefore = await startHangingRun(page);
  expect(stepsBefore).toBeGreaterThan(0);
  const before = await page.evaluate(() => (window as any).__kipi.runStore());
  expect(before.status).toBe("running");

  // nav to OSINT (/enrich) — the FULL page-view teardown the founder hit: root().innerHTML="" + unmountChatDock
  await gotoRoute(page, "/enrich");
  await expect(page.locator("#trail")).toHaveCount(0); // the dock (and #trail) is gone on the config page
  // the run SURVIVED the nav — NOT aborted (no clearCaseDerivedState), the store is intact
  const onEnrich = await page.evaluate(() => (window as any).__kipi.runStore());
  expect(onEnrich.status).toBe("running");
  expect(onEnrich.steps).toBe(before.steps);

  // return to the Workspace — renderSplitView re-mounts the dock and reattachRunIntoDock replays the store
  await page.click('a[data-route="/"]');
  await expect(page.locator("#trail .step")).toHaveCount(stepsBefore); // the trail replayed, step-for-step
  await expect(page.locator("#stopBtn")).toBeVisible(); // a still-live run keeps Stop reachable
  expect(await page.evaluate(() => (window as any).__kipi.runStore())).toMatchObject({ status: "running" });

  // Stop cleans up the still-hanging run (and proves Stop works after a reattach)
  await page.click("#stopBtn");
  expect(await page.evaluate(() => (window as any)._runP)).toMatchObject({ stopReason: "aborted" });
});

test("rsn-reattach: a run survives nav to a detail route (renderSplitView re-mount) and reattaches", async ({ page }) => {
  await freshVault(page);
  const stepsBefore = await startHangingRun(page);

  // nav to a DENSE detail route (/entities) — the ccc-hybrid-routes path: renderSplitView RE-MOUNTS the dock
  // (a canvas takeover over the graph), so reattach fires on the re-mount itself, not only on return to "/".
  await gotoRoute(page, "/entities");
  await expect(page.locator("#trail .step")).toHaveCount(stepsBefore); // reattached on the detail-route re-mount
  await expect(page.locator("#stopBtn")).toBeVisible();
  expect(await page.evaluate(() => (window as any).__kipi.runStore())).toMatchObject({ status: "running" });

  // back to the Workspace, Stop cleans up
  await page.click('a[data-route="/"]');
  await page.click("#stopBtn");
  expect(await page.evaluate(() => (window as any)._runP)).toMatchObject({ stopReason: "aborted" });
});

test("rsn-graph-model-precedence: in-flight graph nodes survive nav (no revert)", async ({ page }) => {
  await freshVault(page);
  await startHangingRun(page); // turn 1's dns_lookup grows the graph LIVE with the IP, then the run hangs

  // the live-grown IP node is on the in-memory graph model BEFORE any nav (kweb-live-graph)
  await page.waitForFunction(() => {
    const m = (window as any).__kipi.graphModel();
    return !!m && m.nodes.some((n: any) => n.label === "93.184.216.34");
  });

  // nav to OSINT (cyGraph is DESTROYED, the durable run: record is NOT persisted yet — the run is hanging),
  // then return. Without the precedence gate, hydrateCaseGraph would cold-read graphModelForCase(vault),
  // which predates the in-flight node → the graph reverts. With the gate, the in-memory model wins.
  await gotoRoute(page, "/enrich");
  await page.click('a[data-route="/"]');

  // the in-flight IP node SURVIVED the round-trip — both in the model AND rendered into the fresh cytoscape
  const labels = await page.evaluate(() => ((window as any).__kipi.graphModel()?.nodes ?? []).map((n: any) => n.label));
  expect(labels).toContain("93.184.216.34");
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes)).toBeGreaterThan(0);

  // cleanup
  await page.click("#stopBtn");
  await page.evaluate(() => (window as any)._runP);
});

// hydra ISSUE-1 + ISSUE-5 (run journal, founder 2026-07-07): a full page RELOAD kills the JS context (the
// nav test above keeps it alive). Before the journal, the in-flight graph was durable ONLY at finalize, so a
// reload mid-run cold-read graphModelForCase → empty "Start here" (ISSUE-5), and a hard abort (which skips
// finalize) lost the discovered entities (ISSUE-1). The journal persists the live model to a durable key as
// it grows; hydrateCaseGraph reads it back on the fresh mount. This proves the round-trip survives a reload.
test("rsn-journal-rehydrate: an in-flight graph survives a full page RELOAD (ISSUE-1/5)", async ({ page }) => {
  await freshVault(page);
  await startHangingRun(page); // grows the graph LIVE with the IP, then hangs (no finalize)

  // the live-grown IP node is on the graph model before the reload
  await page.waitForFunction(() => {
    const m = (window as any).__kipi.graphModel();
    return !!m && m.nodes.some((n: any) => n.label === "93.184.216.34");
  });
  // let the throttled journal write flush (LIVE_RUN_PERSIST_MS = 1000ms trailing debounce)
  await page.waitForTimeout(1400);

  // RELOAD: the JS context dies (agent loop + run store + in-memory lastGraphModel all gone). The OPFS/IndexedDB
  // storage survives, so the durable journal is the ONLY record of the in-flight graph.
  await page.reload();
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.unlock("pw"));

  // the IP node REHYDRATED from the journal onto the fresh mount — not a blank "Start here" (ISSUE-5 fixed).
  await expect
    .poll(() => page.evaluate(() => ((window as any).__kipi.graphModel()?.nodes ?? []).map((n: any) => n.label)))
    .toContain("93.184.216.34");
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes)).toBeGreaterThan(0);
});

test("rsn-run-chip: off-Workspace, a 'run in progress' chip is shown and its Stop aborts the run", async ({ page }) => {
  await freshVault(page);
  await startHangingRun(page);

  // ch-prominent-stop (controls-honesty): the chip is now shown on EVERY route while a run is live —
  // including home — so Stop is unmistakable everywhere (was suppressed on home; the in-dock Stop read as
  // undiscoverable). See tests/smoke/prominent-stop.spec.ts for the home-chip + halt proof.
  await expect(page.locator("#run-chip")).toBeVisible();

  // nav to OSINT (page-view, no dock) — the run survives and the chip stays reachable
  await gotoRoute(page, "/enrich");
  await expect(page.locator("#run-chip")).toBeVisible();
  await expect(page.locator("#run-chip")).toContainText("Investigating");

  // the chip's Stop aborts the still-live run (closes the "no silent failure" goal: reachable off-Workspace)
  await page.click("#run-chip-stop");
  expect(await page.evaluate(() => (window as any)._runP)).toMatchObject({ stopReason: "aborted" });
  // the run is no longer live, and the chip shows a short terminal stopped flash instead of vanishing.
  await expect(page.locator("#run-chip")).toContainText("Run stopped");
  await expect(page.locator("#run-chip-stop")).toBeHidden();
  expect(await page.evaluate(() => (window as any).__kipi.runStore().status)).toBe("aborted");
});

test("rsn-run-chip: a case switch while the chip is visible off-Workspace hides it + aborts the run", async ({ page }) => {
  await freshVault(page); // "Test case" active
  // a 2nd case so the header dropdown can switch
  await gotoRoute(page, "/cases");
  await page.locator(".case-name-input").fill("Case Bravo");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Case Bravo", { timeout: 10_000 });
  await page.click('a[data-route="/"]');

  await startHangingRun(page);
  await gotoRoute(page, "/enrich");
  await expect(page.locator("#run-chip")).toBeVisible();

  // switch cases from the header dropdown WHILE the chip is up. clearCaseDerivedState aborts the run + resets
  // the store + hides the chip SYNCHRONOUSLY (not waiting for the trailing render), so no stale chip survives.
  await page.click("#caseChipBtn");
  await page.locator(".case-menu-item", { hasText: "Test case" }).click();
  await expect(page.locator("#run-chip")).toBeHidden();
  expect(await page.evaluate(() => (window as any)._runP)).toMatchObject({ stopReason: "aborted" });
  expect(await page.evaluate(() => (window as any).__kipi.runStore().status)).toBe("idle"); // wiped to the new case
});

test("rsn-run-chip: a case switch DURING the terminal flash window hides the chip (no case-A label in case B)", async ({ page }) => {
  await freshVault(page); // "Test case" active
  await gotoRoute(page, "/cases");
  await page.locator(".case-name-input").fill("Case Bravo");
  await page.getByRole("button", { name: "Create case" }).click();
  await expect(page.locator("#case-chip")).toHaveText("Case Bravo", { timeout: 10_000 });
  await page.click('a[data-route="/"]');

  // end a run so the chip is in its ~5s terminal flash ("Run stopped"), Stop hidden, chip still visible
  await startHangingRun(page);
  await gotoRoute(page, "/enrich");
  await page.click("#run-chip-stop");
  await expect(page.locator("#run-chip")).toContainText("Run stopped");
  await expect(page.locator("#run-chip")).toBeVisible();

  // switch cases INSIDE the flash window. updateRunChip's flash hold must be cancelled by the case
  // switch, or case A's terminal label lingers into case B (codex blocker, kweb-run-chip-control-contract).
  await page.click("#caseChipBtn");
  await page.locator(".case-menu-item", { hasText: "Test case" }).click();
  await expect(page.locator("#run-chip")).toBeHidden();
  expect(await page.evaluate(() => (window as any).__kipi.runStore().status)).toBe("idle");
});
