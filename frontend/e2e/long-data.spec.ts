import type { APIRequestContext, Page } from "@playwright/test";

import { firstIndicator } from "./api";
import { expect, test } from "./fixtures";
import {
  DOSSIER_ID,
  LONG,
  hostileDossier,
  hostileIndicators,
  hostileOverview,
  serveHostileDossier,
  serveOverview,
} from "./hostile";
import { expectFits, expectOnScreen, expectTextInPlace, sidewaysScrollers } from "./layout";
import { investigate, openInvestigate, openList, openOverview, openRecord, openStatus } from "./open";
import { expectFound, palette } from "./pages";
import type { Overview } from "../src/types/intel";

/**
 * A provider can send a name, a tag or a URL of any length, and a busy deployment can count in the
 * billions. None of that may push the page sideways, hide text behind an edge or run it into a
 * neighbour. Each scene is built once from ordinary data (a control, to show the checks do not cry
 * wolf) and once from data far larger than anything the design was drawn for.
 */
test.use({ reducedMotion: "reduce" });

interface Screen {
  name: string;
  width: number;
  height: number;
}

const SCREENS: readonly Screen[] = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "phone", width: 390, height: 844 },
  { name: "small phone", width: 320, height: 568 },
];

interface Tools {
  page: Page;
  request: APIRequestContext;
  screen: Screen;
}

interface Scene {
  name: string;
  open: (tools: Tools) => Promise<void>;
  /** Wide tables scroll inside a box of their own on a narrow screen. Nothing else may scroll sideways. */
  scrollers?: readonly string[];
}

const MATRIX = "Indicators by type and risk band";
const LIST = "Indicators, sorted by";

const HUGE = 987_654_321_012;

/** The real overview with every count as large as a very busy deployment could make it. */
function withHugeNumbers(overview: Overview): Overview {
  const everyKey = (counts: Record<string, number>): Record<string, number> =>
    Object.fromEntries(Object.keys(counts).map((key) => [key, HUGE]));
  const huge = (entries: Overview["countries"]): Overview["countries"] =>
    entries.map((entry) => ({ ...entry, count: HUGE }));
  return {
    ...overview,
    kpis: {
      total_indicators: HUGE,
      new_indicators_24h: HUGE,
      new_indicators_prev_24h: HUGE - 1,
      lookups_24h: HUGE,
      lookups_prev_24h: HUGE - 1,
      high_risk_indicators: HUGE,
      critical_indicators: HUGE,
      not_assessed_indicators: HUGE,
    },
    by_classification: everyKey(overview.by_classification),
    by_type: everyKey(overview.by_type),
    matrix: overview.matrix.map((row) => ({ ...row, counts: everyKey(row.counts) })),
    series: overview.series.map((point) => ({
      ...point,
      lookups: HUGE,
      high_risk_lookups: HUGE,
      new_indicators: HUGE,
    })),
    activity: overview.activity.map((row) => ({ ...row, hours: row.hours.map(() => HUGE) })),
    countries: huge(overview.countries),
    malware_families: huge(overview.malware_families),
    attack_techniques: huge(overview.attack_techniques),
    tags: huge(overview.tags),
    scope: { ...overview.scope, lookups_scanned: HUGE, answers_scanned: HUGE },
  };
}

/** Opens the details drawer of the row of a ranked list whose label is the longest. */
async function openLongestRow(page: Page, list: string): Promise<void> {
  const rows = page.getByRole("list", { name: list }).getByRole("button");
  const lengths = await rows.evaluateAll((buttons) => buttons.map((button) => button.textContent?.length ?? 0));
  await rows.nth(lengths.indexOf(Math.max(...lengths))).click();
  await expect(page.getByRole("dialog")).toBeVisible();
}

const RANKED_LISTS = [
  "Top provider-reported countries",
  "Malware families",
  "ATT&CK techniques",
  "Provider tags",
] as const;

/** Focuses the lookups chart, which opens the tooltip on the last day, and lists any tooltip text that is not inside it. */
async function readOutLastDay(page: Page): Promise<string[]> {
  const chart = page.getByRole("group", { name: "Lookups and high-risk lookups per day" });
  await chart.focus();
  const frame = chart.locator("svg rect[rx='3']");
  await expect(frame).toBeVisible();
  return frame.evaluate((rect) => {
    const box = rect.getBoundingClientRect();
    const found: string[] = [];
    const tip = rect.parentElement;
    for (const text of tip?.querySelectorAll("text") ?? []) {
      const at = text.getBoundingClientRect();
      if (at.left < box.left - 1 || at.right > box.right + 1) {
        found.push(`"${text.textContent}" runs from ${Math.round(at.left)} to ${Math.round(at.right)}px in a tooltip from ${Math.round(box.left)} to ${Math.round(box.right)}px`);
      }
    }
    for (const row of tip?.querySelectorAll(":scope > g") ?? []) {
      const [label, value] = row.querySelectorAll("text");
      if (label && value && label.getBoundingClientRect().right > value.getBoundingClientRect().left - 4) {
        found.push(`"${label.textContent}" runs into "${value.textContent}"`);
      }
    }
    return found;
  });
}

/** The list endpoint answers with these indicators, whatever is asked. */
async function serveIndicators(page: Page, items: unknown[]): Promise<void> {
  await page.route(/\/api\/v1\/intel\/indicators\?/, (route) =>
    route.fulfill({ status: 200, json: { items, total: items.length, limit: 25, offset: 0 } }),
  );
}

/** What the list's table measures: how wide it is, and how wide the cell of the first indicator is. */
async function tableWidths(page: Page): Promise<{ table: number; firstCell: number }> {
  return page.getByRole("table").evaluate((table) => ({
    table: table.getBoundingClientRect().width,
    firstCell: table.querySelector("tbody th")?.getBoundingClientRect().width ?? 0,
  }));
}

const TYPED = "W".repeat(2048);

const LONG_SCENES: readonly Scene[] = [
  {
    name: "the overview with very long names and values",
    scrollers: [MATRIX],
    open: async ({ page }) => {
      await serveOverview(page, (overview) => hostileOverview(overview, LONG));
      await openOverview(page);
    },
  },
  {
    name: "the overview with very large numbers",
    scrollers: [MATRIX],
    open: async ({ page }) => {
      await serveOverview(page, withHugeNumbers);
      await openOverview(page);
    },
  },
  ...RANKED_LISTS.map(
    (list): Scene => ({
      name: `a details drawer for the longest name in ${list}`,
      scrollers: [MATRIX],
      open: async ({ page, screen }) => {
        await serveOverview(page, (overview) => hostileOverview(overview, LONG));
        await openOverview(page);
        await openLongestRow(page, list);
        await expectOnScreen(page.getByRole("dialog"), screen);
      },
    }),
  ),
  {
    name: "a details drawer opened on very large numbers",
    scrollers: [MATRIX],
    open: async ({ page, screen }) => {
      await serveOverview(page, withHugeNumbers);
      await openOverview(page);
      await openLongestRow(page, "Malware families");
      await expectOnScreen(page.getByRole("dialog"), screen);
    },
  },
  {
    name: "the lookups chart read out on very large numbers",
    scrollers: [MATRIX],
    open: async ({ page }) => {
      await serveOverview(page, withHugeNumbers);
      await openOverview(page);
      expect(await readOutLastDay(page), "text of the tooltip").toEqual([]);
      // The exact figure goes to screen readers, whatever is drawn.
      await expect(page.getByRole("status").filter({ hasText: String(HUGE) })).toHaveCount(1);
    },
  },
  {
    name: "a stored record with very long provider data",
    open: async ({ page }) => {
      await serveHostileDossier(page, LONG);
      await openRecord(page, DOSSIER_ID);
    },
  },
  {
    name: "the Investigate page with a result full of very long data",
    open: async ({ page }) => {
      const { dossier } = hostileDossier(LONG);
      await page.route("**/api/v1/intel/investigate", (route) => route.fulfill({ status: 200, json: dossier }));
      await investigate(page, "long.example.com");
      await expect(page.getByRole("link", { name: "Open the saved record" })).toBeVisible();
    },
  },
  {
    name: "the indicators list with very long values",
    scrollers: [LIST],
    open: async ({ page }) => {
      await openList(page);
      const ordinary = await tableWidths(page);
      await serveIndicators(page, hostileIndicators(LONG, "recent"));
      await openList(page);
      // A value of any length wraps inside its column, so it costs the table no width at all.
      const long = await tableWidths(page);
      expect(long.table, "width of the table").toBeLessThanOrEqual(ordinary.table + 1);
      // The cell is as wide as its share of the table, but one long value must not take most of it.
      expect(long.firstCell / long.table, "share of the table taken by the cell with the indicator").toBeLessThanOrEqual(0.4);
    },
  },
  {
    name: "the indicators list with a very long search in the address",
    open: async ({ page }) => {
      await page.goto(`/indicators?q=${"W".repeat(2000)}`);
      await expectFound(page, 0);
    },
  },
  {
    name: "the confirmation to delete one very long indicator",
    scrollers: [LIST],
    open: async ({ page, screen }) => {
      await serveIndicators(page, hostileIndicators(LONG, "recent"));
      await openList(page);
      await page.getByRole("button", { name: /^Delete / }).first().click();
      await expectOnScreen(page.getByRole("dialog", { name: "Delete this indicator?", exact: true }), screen);
    },
  },
  {
    name: "the confirmation to delete several very long indicators",
    scrollers: [LIST],
    open: async ({ page, screen }) => {
      await serveIndicators(page, hostileIndicators(LONG, "recent"));
      await openList(page);
      await page.getByRole("checkbox", { name: "Select all indicators on this page" }).check();
      await page.getByRole("button", { name: /^Delete selected \(/ }).click();
      await expectOnScreen(page.getByRole("dialog", { name: /^Delete \d+ indicators\?$/ }), screen);
    },
  },
  {
    name: "the command palette with a very long search",
    scrollers: [MATRIX],
    open: async ({ page, screen }) => {
      await openOverview(page);
      await page.keyboard.press("Control+k");
      const { box, dialog, options } = palette(page);
      await box.fill(TYPED);
      await expect(options).toHaveCount(2);
      await expectOnScreen(dialog, screen);
    },
  },
  {
    name: "the Investigate page with a value that is far too long",
    open: async ({ page }) => {
      await openInvestigate(page);
      await page.getByRole("textbox", { name: /^Indicator/ }).fill(`${TYPED}W`);
      await page.getByRole("button", { name: "Investigate", exact: true }).click();
      await expect(page.getByRole("alert")).toContainText("An indicator can be at most 2048 characters.");
    },
  },
  {
    name: "the not-found page at a very long address",
    open: async ({ page }) => {
      await page.goto(`/${"W".repeat(2000)}`);
      await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
    },
  },
];

const ORDINARY_SCENES: readonly Scene[] = [
  { name: "the overview", scrollers: [MATRIX], open: ({ page }) => openOverview(page) },
  {
    name: "a details drawer",
    scrollers: [MATRIX],
    open: async ({ page, screen }) => {
      await openOverview(page);
      await openLongestRow(page, "Malware families");
      await expectOnScreen(page.getByRole("dialog"), screen);
    },
  },
  {
    name: "a stored record",
    open: async ({ page, request }) => {
      await openRecord(page, (await firstIndicator(request, { sort: "risk" })).indicator_id);
    },
  },
  { name: "the indicators list", scrollers: [LIST], open: ({ page }) => openList(page) },
  { name: "the Investigate page", open: ({ page }) => openInvestigate(page) },
  { name: "the system status", open: ({ page }) => openStatus(page) },
];

for (const screen of SCREENS) {
  test.describe(`${screen.name}, ${screen.width}x${screen.height}`, () => {
    test.use({ viewport: { width: screen.width, height: screen.height } });

    test.describe("very long names and values, very large numbers", () => {
      for (const scene of LONG_SCENES) {
        test(scene.name, async ({ page, request }) => {
          await scene.open({ page, request, screen });
          await expectFits(page, scene.name);
          await expectTextInPlace(page, scene.name);
          expect(await sidewaysScrollers(page, scene.scrollers), `scrolls sideways: ${scene.name}`).toEqual([]);
        });
      }
    });

    test.describe("ordinary data, as a control", () => {
      for (const scene of ORDINARY_SCENES) {
        test(scene.name, async ({ page, request }) => {
          await scene.open({ page, request, screen });
          await expectFits(page, scene.name);
          await expectTextInPlace(page, scene.name);
          expect(await sidewaysScrollers(page, scene.scrollers), `scrolls sideways: ${scene.name}`).toEqual([]);
        });
      }
    });
  });
}
