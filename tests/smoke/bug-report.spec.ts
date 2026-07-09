import { test, expect } from "@playwright/test";

// rel-bug (live proof): the "Report a bug" link sits in the static sidebar footer (beside Contact /
// Support), present on every screen incl. the login gate. app.ts upgrades its href to the templated
// mailto. It must render, be a mailto to the founder, and carry only the static template (no case data
// can exist here, but we assert the shape regardless).

test("the bug-report link renders and is a mailto to the founder", async ({ page }) => {
  await page.goto("/");
  const btn = page.locator("#bug-report-link");
  await expect(btn).toBeVisible();
  await expect(btn).toContainText("Report a bug");

  const href = await btn.getAttribute("href");
  expect(href).not.toBeNull();
  expect(href!.startsWith("mailto:assaf@ktlystlabs.com?")).toBe(true);

  const query = new URLSearchParams(href!.split("?")[1]);
  expect(query.get("subject")).toBe("kipi bug report");
  expect(query.get("body")).toContain("What happened");

  // the hover disclosure states the zero-data guarantee
  const title = await btn.getAttribute("title");
  expect((title || "").toLowerCase()).toContain("never see your cases");
});
