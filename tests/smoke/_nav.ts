import { type Page } from "@playwright/test";

// Shared nav helper. clu-workspace-nav (2026-06-20): the sidebar is collapsed to EXACTLY Workspace (/),
// Enrich (/enrich), and Account (/account). Every OTHER route still RESOLVES (app.ts ROUTES unchanged)
// but is no longer in the sidebar — it is reached by hash (the same in-app nav the lifecycle rail and
// the entity-row "open in graph" links use). gotoRoute() clicks the real sidebar link when the route is
// one of the three, and hash-navigates otherwise — so every smoke that drives a now-off-nav route keeps
// working against the still-resolving route.

export async function gotoRoute(page: Page, route: string): Promise<void> {
  const link = page.locator(`a[data-route="${route}"]`);
  if (await link.count()) {
    await link.click();
    return;
  }
  // Off-nav route: navigate by hash (resolves via the unchanged ROUTES set; hashchange → render).
  await page.evaluate((r) => { location.hash = "#" + r; }, route);
}
