import type { Locator, Page } from "@playwright/test";

import type { Investigation, Overview } from "../src/types/intel";
import { fetchIndicator, fetchIndicators, fetchOverview, fresh } from "./api";
import { expect, test } from "./fixtures";
import { openOverview } from "./open";
import { expectDossier, expectFound, listFilters, panel } from "./pages";
import { must, sum } from "./text";

// Numbers appear at once instead of counting up, so the page can be compared with the API.
test.use({ reducedMotion: "reduce" });

const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;
const SAVED = "This result is saved. You can return to it from the Indicators page.";

/** A headline tile, found by what it says and the number it shows. */
function tile(page: Page, label: string, count: number): Locator {
  return page
    .getByRole("region", { name: "Key figures" })
    .getByRole("link", { name: new RegExp(`^${label} ${count.toLocaleString("en-US")}(?![\\d,])`) });
}

/** The shortcut for a page: G, then a letter. */
async function goTo(page: Page, letter: string): Promise<void> {
  await page.keyboard.press("g");
  await page.keyboard.press(letter);
}

test("one investigation, followed from the form to the record, the list, the overview and the totals", async ({
  page,
  request,
}) => {
  const value = fresh.ipv6();
  const before = await fetchOverview(request);

  // Start where a person starts: the overview, with the figures the API holds.
  await openOverview(page);
  await expect(tile(page, "Indicators tracked", before.kpis.total_indicators)).toBeVisible();
  await expect(tile(page, "Lookups, last 24 hours", before.kpis.lookups_24h)).toBeVisible();

  // Investigate something new.
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Investigate" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator" })).toBeVisible();
  await page.getByRole("textbox", { name: /^Indicator/ }).fill(value);
  const answered = page.waitForResponse((response) => response.request().method() === "POST" && INVESTIGATE.test(response.url()));
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  const answer = (await (await answered).json()) as Investigation;
  await expect(page.getByText(SAVED)).toBeVisible();
  await expectDossier(page, answer);

  // The saved record shows what the lookup showed.
  const id = answer.indicator.indicator_id;
  await page.getByRole("link", { name: "Open the saved record" }).click();
  await expect(page).toHaveURL(new RegExp(`/indicators/${id}$`));
  await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
  await expectDossier(page, await fetchIndicator(request, id));

  // Asking the providers again updates it.
  await page.getByRole("button", { name: "Re-check with providers" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Re-check complete. The record was updated." })).toBeAttached();
  await expect(page.getByRole("button", { name: "Re-check with providers" })).toBeEnabled();

  // The Indicators list finds it, and only it.
  await goTo(page, "l");
  await expect(page.getByRole("heading", { level: 1, name: "Indicators", exact: true })).toBeVisible();
  const { search, searchButton } = listFilters(page);
  await search.fill(value);
  await searchButton.click();
  await expectFound(page, 1);
  expect((await fetchIndicators(request, { q: value })).items.map((item) => item.indicator_id)).toEqual([id]);
  await page.getByRole("table").getByRole("link", { name: value }).click();
  await expect(page).toHaveURL(new RegExp(`/indicators/${id}$`));
  await expect(panel(page, "CipherForge assessment")).toContainText(value);

  // Back on the overview, the totals have moved by exactly what was done: one new indicator,
  // and two lookups (the investigation and the re-check).
  await goTo(page, "o");
  await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
  const after = await fetchOverview(request);
  expect(after.kpis.total_indicators, "indicators tracked").toBe(before.kpis.total_indicators + 1);
  const startDay = must(before.series.at(-1)).day;
  const lookupsSince = (overview: Overview): number =>
    sum(overview.series.filter((point) => point.day >= startDay).map((point) => point.lookups));
  expect(lookupsSince(after) - lookupsSince(before), "lookups since the start").toBe(2);
  await expect(tile(page, "Indicators tracked", after.kpis.total_indicators)).toBeVisible();
  await expect(tile(page, "Lookups, last 24 hours", after.kpis.lookups_24h)).toBeVisible();

  // It is the newest thing in "Latest investigations", and the link leads to its record.
  const latest = page.getByRole("list", { name: "Latest investigations" }).getByRole("listitem").first();
  await expect(latest).toContainText(value);
  await expect(latest.getByRole("link")).toHaveAttribute("href", `/indicators/${id}`);

  // Nothing about all this has upset the platform.
  await goTo(page, "s");
  await expect(page.getByRole("heading", { level: 1, name: "System status" })).toBeVisible();
  await expect(page.getByText("Operational", { exact: true })).toBeVisible();
});
