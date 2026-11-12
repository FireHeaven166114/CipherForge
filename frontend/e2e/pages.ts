import type { Locator, Page } from "@playwright/test";

import type { Investigation } from "../src/types/intel";
import { CLASSIFICATION_LABELS, PROVIDER_STATUS_LABELS, TYPE_LABELS, countOf } from "./api";
import { expect } from "./fixtures";
import { escapeRegExp } from "./text";

/** The controls above the indicators list. */
export function listFilters(page: Page): {
  search: Locator;
  searchButton: Locator;
  type: Locator;
  classification: Locator;
  sort: Locator;
  reset: Locator;
} {
  return {
    search: page.getByRole("searchbox", { name: "Search", exact: true }),
    searchButton: page.getByRole("search").getByRole("button", { name: "Search", exact: true }),
    type: page.getByLabel("Type", { exact: true }),
    classification: page.getByLabel("Classification", { exact: true }),
    sort: page.getByLabel("Sort by", { exact: true }),
    reset: page.getByRole("button", { name: "Reset filters" }),
  };
}

/** The option the indicators list's Classification filter shows as chosen. */
export function chosenClassification(page: Page): Locator {
  return listFilters(page).classification.locator("option:checked");
}

/** Passes when the indicators list says it found exactly this many. */
export async function expectFound(page: Page, count: number): Promise<void> {
  await expect(
    page.getByRole("status").filter({ hasText: new RegExp(`^${escapeRegExp(countOf(count))} found\\.$`) }),
  ).toBeVisible();
}

/** The titled panel with this h2. */
export function panel(page: Page, title: string): Locator {
  return page
    .locator("section")
    .filter({ has: page.getByRole("heading", { level: 2, name: title, exact: true }) });
}

/** One provider's card on a dossier: the panel whose own header carries this h3. */
export function providerCard(page: Page, name: string): Locator {
  return page
    .locator("section:has(> header > h3)")
    .filter({ has: page.getByRole("heading", { level: 3, name, exact: true }) });
}

/**
 * Passes when the page shows this dossier: the verdict, each provider's answer and the score
 * table. Run the test with reduced motion so numbers are written out instead of counting up.
 */
export async function expectDossier(page: Page, dossier: Investigation): Promise<void> {
  const { indicator, providers, score } = dossier;
  const verdict = panel(page, "CipherForge assessment");
  const built = panel(page, "How the score was built");
  await expect(verdict).toContainText(indicator.indicator_value);
  await expect(verdict).toContainText(TYPE_LABELS[indicator.indicator_type]);

  if (score.answered_sources > 0) {
    await expect(verdict).toContainText(`Risk score${score.score}`);
    await expect(verdict).toContainText(CLASSIFICATION_LABELS[score.classification]);
    await expect(verdict).toContainText(`Confidence${score.confidence}/ 100`);
    const factors = built.getByRole("table", { name: "Points that make up the score" });
    await expect(factors.locator("tbody tr")).toHaveCount(score.factors.length);
    await expect(factors.locator("tfoot td")).toHaveText(String(score.score));
  } else {
    await expect(verdict).toContainText("Not assessed");
    await expect(verdict).toContainText("No provider answered, so CipherForge has no evidence about this indicator.");
    await expect(built).toContainText("No provider answered, so there is no score to break down.");
  }

  for (const provider of providers) {
    await expect(providerCard(page, provider.display_name).locator("header")).toContainText(
      PROVIDER_STATUS_LABELS[provider.status],
    );
  }
}

/** The command palette dialog, its search box and its options. */
export function palette(page: Page): { dialog: Locator; box: Locator; options: Locator } {
  const dialog = page.getByRole("dialog", { name: "Command palette" });
  return {
    dialog,
    box: dialog.getByRole("combobox", { name: "Search commands or enter an indicator" }),
    options: dialog.getByRole("option"),
  };
}

/** Holds a response back, to show what the page does while it waits. */
export function pause(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
