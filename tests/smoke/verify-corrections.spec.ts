import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// sf-corrections parity verification (PRD prd-kipi-web-corrections-2026-06-18).
// ANALYST IS THE TOP AUTHORITY. This proves an analyst correction PROPAGATES — live, end to end — across
// three independent projections, and that REVERT undoes it everywhere. RCA #2: a code read is not
// acceptance; the flip to `faithful` requires this seen, not asserted in prose. Offline-safe: it drives
// reset -> createVault -> runScriptedInvestigation (a dummy key + scripted fetch, zero egress) and applies
// the correction via __kipi.applyCorrection — the SAME validated, redacted, single-writer top-authority
// path the UI uses (NOT a forged store record; correction keys are protected from raw writes, D6/D2).
// The TYPE -> brief leg of analyst authority is proven deterministically in tests/agent/session-brief.test.ts
// (a type correction re-labels the finding entity_type in the digest the model sees); this smoke is the
// visible role -> graph/entity-DB/audit propagation + revert.

const ENTITY = "login.acme-pay.example";

const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving acme-pay.example and pivoting on its infra." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "acme-pay.example" } },
    ],
    stop_reason: "tool_use",
    usage: { output_tokens: 12 },
  },
  {
    content: [
      {
        type: "text",
        text:
          "Done.\n```json\n{\"findings\":[" +
          `{\"entity\":\"${ENTITY}\",\"entity_type\":\"domain\",\"confidence\":\"high\"}` +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 18 },
  },
];

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

function roleOnGraph(page: Page): Promise<string | undefined> {
  return page.evaluate(
    (label) =>
      (window as unknown as { __kipi: { graphModel(): { nodes: { label: string; role?: string }[] } | null } })
        .__kipi.graphModel()
        ?.nodes.find((n) => n.label === label)?.role,
    ENTITY,
  );
}

function nodePresent(page: Page): Promise<boolean> {
  return page.evaluate(
    (label) =>
      !!(window as unknown as { __kipi: { graphModel(): { nodes: { label: string }[] } | null } })
        .__kipi.graphModel()
        ?.nodes.some((n) => n.label === label),
    ENTITY,
  );
}

function activeCorrections(page: Page): Promise<{ predicate: string; value: string; author: string; active: boolean }[]> {
  return page.evaluate(
    () =>
      (window as unknown as { __kipi: { corrections(): { predicate: string; value: string; author: string; active: boolean }[] } })
        .__kipi.corrections()
        .filter((c) => c.active),
  );
}

test.use({ viewport: { width: 1440, height: 900 } });

test("an analyst role correction propagates to the graph + entity DB + audit; revert undoes it everywhere; no egress", async ({ page }) => {
  const external: string[] = [];
  page.on("request", (r) => {
    if (isExternal(r.url())) external.push(r.url());
  });

  // seed a domain node on the home graph (offline: dummy key + scripted fetch)
  await page.goto("/");
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { reset(): Promise<void> } }).__kipi.reset());
  await page.reload();
  await page.waitForFunction(() => !!(window as unknown as { __kipi?: unknown }).__kipi);
  await page.evaluate(() => (window as unknown as { __kipi: { createVault(pw: string): Promise<unknown> } }).__kipi.createVault("pw"));
  await page.evaluate(
    ([turns]) =>
      (window as unknown as { __kipi: { runScriptedInvestigation(o: string, t: unknown[]): Promise<unknown> } }).__kipi.runScriptedInvestigation(
        "investigate acme-pay.example",
        turns,
      ),
    [RUN_TURNS] as const,
  );
  await page.click('a[data-route="/"]');
  await page.waitForSelector("#cy", { timeout: 15_000 });

  // the uncorrected node has no EXPLICIT role (the renderer derives one); capture it for the revert assert
  const originalRole = await roleOnGraph(page);
  expect(originalRole, "the seeded node has no analyst role override yet").not.toBe("operator");

  // APPLY the correction via the validated top-authority seam (the path the UI Set-role button calls)
  await page.evaluate(
    (label) =>
      (window as unknown as { __kipi: { applyCorrection(t: string, v: string, p: string, n: string): Promise<unknown> } }).__kipi.applyCorrection(
        "domain",
        label,
        "role",
        "operator",
      ),
    ENTITY,
  );

  // (1) GRAPH: the home graph re-projects with the override applied
  await page.click('a[data-route="/"]');
  await expect.poll(() => roleOnGraph(page), { timeout: 5_000, message: "the graph node carries the corrected role" }).toBe("operator");

  // (2) AUDIT/STORE: /corrections renders a card with the entity, the role, and the analyst; the store records it active
  await gotoRoute(page, "/corrections");
  const card = page.locator(".corr-card", { hasText: ENTITY });
  await expect(card).toContainText("operator");
  await expect(card).toContainText("by analyst");
  const recorded = await activeCorrections(page);
  expect(recorded).toHaveLength(1);
  expect(recorded[0]).toMatchObject({ predicate: "role", value: "operator", author: "analyst", active: true });
  await page.screenshot({ path: "test-results/verify-corrections-audit.png", fullPage: true });

  // (3) ENTITY DB: the /entities surface shows the corrected role on the entity's detail
  await gotoRoute(page, "/entities");
  const entRow = page.locator(".ent-row", { hasText: ENTITY });
  await entRow.locator(".ent-top").click();
  await expect(entRow.locator(".ent-assert-current"), "the entity detail reflects the corrected role").toContainText("operator");
  await page.screenshot({ path: "test-results/verify-corrections-entity.png", fullPage: true });

  // (4) REVERT propagates: clearing the correction on /corrections removes it from the store AND the graph
  await gotoRoute(page, "/corrections");
  await page.locator(".corr-card", { hasText: ENTITY }).getByRole("button", { name: "Revert" }).first().click();
  await expect.poll(() => activeCorrections(page), { timeout: 5_000, message: "revert clears the active correction" }).toEqual([]);
  await page.click('a[data-route="/"]');
  // codex MINOR: roleOnGraph() returns undefined for BOTH "node has no role" and "node missing", so a
  // vanished node would falsely satisfy the role-restored check. Assert the node still EXISTS first, so
  // role===originalRole genuinely means "the override was cleared", not "the node disappeared".
  await expect.poll(() => nodePresent(page), { timeout: 5_000, message: "the node survives revert" }).toBe(true);
  await expect.poll(() => roleOnGraph(page), { timeout: 5_000, message: "revert restores the graph node role" }).toBe(originalRole);

  // no key on the page; no off-allowlist egress (the correction is local + redacted)
  expect(external, "zero external egress for a local analyst correction").toEqual([]);
});
