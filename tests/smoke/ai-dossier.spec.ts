import { test, expect, type Page } from "@playwright/test";
import { gotoRoute } from "./_nav";
// adr-smoke (the live proof): a REAL scripted run lands gated entities, then the on-demand AI
// dossier + semantic typed relations render in the chat node card ALONGSIDE the derived data (NOT
// "port pending"). The gate is proven live: a low-confidence same_operator and an unknown cid are
// BOTH dropped (only a high-confidence hosts survives). A key echoed into the model dossier OUTPUT
// is redacted out. No off-allowlist egress; the saved key never leaks; the secret hook is refused.

const KEY = "sk-ant-ADR-secret-9090"; // distinctive saved key for the no-leak sweep

// ip (promotes via canned dns) + two domains (held leads). All three co-occur, so the IP has TWO
// relatable connections — enough for the relations wire to KEEP one (hosts/high) and DROP one
// (same_operator/low). No key in the model output, so the live #trail stays clean.
const RUN_TURNS = [
  {
    content: [
      { type: "text", text: "Resolving probe.example.com." },
      { type: "tool_use", id: "t1", name: "dns_lookup", input: { domain: "probe.example.com" } },
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
          '{"entity":"93.184.216.34","entity_type":"ip","confidence":"high"},' +
          '{"entity":"co.example.com","entity_type":"domain","confidence":"low"},' +
          '{"entity":"co2.example.com","entity_type":"domain","confidence":"low"}' +
          "]}\n```",
      },
    ],
    stop_reason: "end_turn",
    usage: { output_tokens: 20 },
  },
];

// The scripted dossier OUTPUT echoes the saved key — to prove the session layer redacts it OUT.
const DOSSIER_MD =
  "## Summary\nThis host is live infrastructure. Leak attempt " + KEY + " here.\n" +
  "## Threat assessment\nAssessed medium — single run.\n## Key connections\nco.example.com.\n## Open questions\nRegistrant unattributed.";

function isExternal(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol.startsWith("http") && u.hostname !== "localhost" && u.hostname !== "127.0.0.1";
  } catch {
    return false;
  }
}

async function freshKeyedVault(page: Page) {
  await page.goto("/");
  await page.waitForFunction(() => !!(window as any).__kipi);
  await page.evaluate(() => (window as any).__kipi.reset());
  await page.evaluate(() => (window as any).__kipi.createVault("pw"));
  await gotoRoute(page, "/account"); // ac-ui: the key card moved off home to /account
  await page.fill("#apikey", KEY);
  await page.click("#saveKeyBtn");
  await expect(page.locator("#keychip")).toContainText("configured");
  await page.click('a[data-route="/"]'); // kf-fix: back to the graph home for the run
}

let external: string[] = [];
test.beforeEach(async ({ page }) => {
  external = [];
  page.on("request", (req) => { if (isExternal(req.url())) external.push(req.url()); });
  await freshKeyedVault(page);
});

test("AI dossier + semantic relations render alongside derived; gate drops low-confidence + unknown cid; no key leak; no egress", async ({ page }) => {
  await expect(page.locator("#chat-input")).toBeVisible();

  // (1) install the scripted wires (run turns + the key-echoing dossier + the smart relations wire)
  await page.evaluate(([turns, dossierText]) => (window as any).__kipi.installChatWire({ turns, dossierText, relationsSmart: true }), [RUN_TURNS, DOSSIER_MD] as const);

  // (2) drive the REAL chat run path; the IP + two domains land
  await page.fill("#chat-input", "investigate probe.example.com");
  await page.click("#chat-send");
  // remove-chat-findings (2026-07-08): the #findings chip column is gone — the run's findings prove via the
  // GRAPH growing (objective + ip + 2 domains = 4 nodes), not a chat column.
  await expect.poll(() => page.evaluate(() => (window as any).__kipi.cyCounts().nodes), { timeout: 10_000 }).toBe(4);

  const ids = await page.evaluate(() => {
    const m = (window as any).__kipi.graphModel();
    return {
      ip: m.nodes.find((n: any) => n.entityType === "ip")?.id,
      obj: m.nodes.find((n: any) => n.kind === "objective")?.id,
    };
  });
  expect(ids.ip).toBeTruthy();

  // (3) the GATE, live: semanticRelations keeps the high-confidence hosts, DROPS the low-confidence
  // same_operator AND the unknown (bogus) cid — exactly one relation survives.
  const rels = (await page.evaluate((id) => (window as any).__kipi.semanticRelations(id), ids.ip)).relations;
  expect(rels).toHaveLength(1);
  expect(rels[0].relType).toBe("hosts");
  const relTypes = rels.map((r: any) => r.relType);
  expect(relTypes).not.toContain("same_operator");
  expect(relTypes).not.toContain("owns"); // the bogus cid never resolved

  // (4) the AI dossier via the hook: redact-OUT works (the echoed key is gone, [REDACTED] present)
  const dossier = (await page.evaluate((id) => (window as any).__kipi.aiDossier(id), ids.ip)).dossier;
  expect(dossier).toContain("live infrastructure");
  expect(dossier).not.toContain(KEY);
  expect(dossier).toContain("[REDACTED]");

  // (5) the hooks REJECT the objective + an unknown node (D5)
  expect((await page.evaluate((id) => (window as any).__kipi.aiDossier(id), ids.obj)).dossier).toBeNull();
  expect((await page.evaluate(() => (window as any).__kipi.aiDossier("no-such-node"))).dossier).toBeNull();
  expect((await page.evaluate((id) => (window as any).__kipi.semanticRelations(id), ids.obj)).relations).toEqual([]);

  // (6) remove-cards (founder 2026-07-03): the AI-dossier + type-relations BUTTONS lived only in the node
  // card, which is gone; selecting a node renders NO card. The LLM passes themselves (aiDossier /
  // semanticRelations, incl. the gate + redaction) are verified via the hooks above — the conversational
  // surface for them is now "What is this?" (Q&A) and "Show its connections". (The dedicated runAiDossier /
  // runSemanticRelations passes are unwired from the UI — spillover sp-53cf0d6b tracks re-surfacing
  // them as a right-click menu item vs. retiring them.)
  await page.evaluate((id) => (window as any).__kipi.selectNode(id), ids.ip);
  await expect(page.locator(".node-card")).toHaveCount(0);

  // (7) no key on the page; the secret hook is refused; no off-allowlist egress (D5/D7)
  expect(await page.evaluate(() => document.body.innerText)).not.toContain(KEY);
  const secretThrows = await page.evaluate(() => {
    try { (window as any).__kipi.getCase("secret:anthropic_key"); return false; } catch { return true; }
  });
  expect(secretThrows).toBe(true);
  expect(external, `unexpected egress: ${external.join(", ")}`).toHaveLength(0);

  await page.screenshot({ path: "test-results/kipi-ai-dossier.png", fullPage: true });
});
