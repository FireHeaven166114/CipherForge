import type { Locator, Page } from "@playwright/test";

import type { FacetEntry, Overview } from "../src/types/intel";
import {
  CLASSIFICATION_LABELS,
  CLASSIFICATION_ORDER,
  TYPE_LABELS,
  countOf,
  countRequests,
  fetchIndicators,
  fetchOverview,
} from "./api";
import { expect, test } from "./fixtures";
import { chosenClassification, expectFound, panel } from "./pages";
import { bandOf, escapeRegExp, exactly, hourText, istClockSeconds, longDay, must, share, sum, trendText } from "./text";

const OVERVIEW_URL = "**/api/v1/intel/overview";
const OVERVIEW_REQUEST = /\/api\/v1\/intel\/overview$/;
const CHART = "Lookups and high-risk lookups per day";

async function openOverview(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();
}

/** Serves the real overview with a change applied, for states the demo data cannot show. */
async function serveOverview(page: Page, change: (overview: Overview) => Overview): Promise<void> {
  await page.route(OVERVIEW_URL, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ status: 200, json: change((await response.json()) as Overview) });
  });
}

/** What the browser prints for a country code, e.g. "Netherlands (NL)". */
async function countryText(page: Page, code: string): Promise<string> {
  const name = await page.evaluate(
    (region) => new Intl.DisplayNames(["en"], { type: "region" }).of(region),
    code,
  );
  return name === undefined || name === code ? code : `${name} (${code})`;
}

/** A row of a ranked list reads "<name>: <count>, highest risk <band>". */
function rowName(label: string, entry: FacetEntry): RegExp {
  const band = CLASSIFICATION_LABELS[bandOf(entry.max_risk)];
  return new RegExp(`^${escapeRegExp(label)}\\s?: ${escapeRegExp(countOf(entry.count))}, highest risk ${band}$`);
}

function figure(drawer: Locator, term: string): Locator {
  return drawer.locator("dt", { hasText: exactly(term) }).locator("xpath=following-sibling::dd[1]");
}

const EMPTY_KPIS: Overview["kpis"] = {
  total_indicators: 0,
  new_indicators_24h: 0,
  new_indicators_prev_24h: 0,
  lookups_24h: 0,
  lookups_prev_24h: 0,
  high_risk_indicators: 0,
  critical_indicators: 0,
  not_assessed_indicators: 0,
};

test.describe("the overview and the API", () => {
  test("the figures agree with one another", async ({ request }) => {
    const overview = await fetchOverview(request);
    const { kpis, by_classification: bands, by_type: types } = overview;

    expect(sum(Object.values(bands))).toBe(kpis.total_indicators);
    expect(sum(Object.values(types))).toBe(kpis.total_indicators);
    expect(kpis.critical_indicators).toBe(bands["critical"] ?? 0);
    expect(kpis.high_risk_indicators).toBe((bands["high"] ?? 0) + (bands["critical"] ?? 0));
    expect(kpis.not_assessed_indicators).toBe(bands["not_assessed"] ?? 0);
    for (const row of overview.matrix) {
      expect(sum(Object.values(row.counts)), `the ${row.indicator_type} row`).toBe(types[row.indicator_type] ?? 0);
    }

    expect(overview.series).toHaveLength(overview.scope.series_days);
    expect(overview.activity).toHaveLength(overview.scope.activity_days);
    for (const row of overview.activity) expect(row.hours).toHaveLength(24);

    const days = overview.series.map((point) => Date.parse(`${point.day}T00:00:00Z`));
    days.forEach((day, index) => {
      if (index > 0) expect(day - must(days[index - 1])).toBe(24 * 60 * 60 * 1000);
    });

    const [today, yesterday] = [overview.series.at(-1), overview.series.at(-2)];
    expect(kpis.lookups_24h).toBeLessThanOrEqual(must(today).lookups + must(yesterday).lookups);
    expect(kpis.new_indicators_24h).toBeLessThanOrEqual(must(today).new_indicators + must(yesterday).new_indicators);
  });

  test("every count agrees with the total of the list it leads to", async ({ request }) => {
    const { kpis, by_classification: bands, matrix } = await fetchOverview(request);
    const total = async (params: Record<string, string | readonly string[]>): Promise<number> =>
      (await fetchIndicators(request, { ...params, limit: 1 })).total;

    expect(await total({})).toBe(kpis.total_indicators);
    for (const band of CLASSIFICATION_ORDER) {
      expect(await total({ classification: band, assessed: "true" }), band).toBe(bands[band] ?? 0);
    }
    expect(await total({ classification: ["high", "critical"], assessed: "true" }), "high or critical").toBe(
      kpis.high_risk_indicators,
    );
    expect(await total({ assessed: "false" }), "not assessed").toBe(kpis.not_assessed_indicators);

    for (const row of matrix) {
      for (const band of CLASSIFICATION_ORDER) {
        expect(
          await total({ type: row.indicator_type, classification: band, assessed: "true" }),
          `${row.indicator_type} ${band}`,
        ).toBe(row.counts[band] ?? 0);
      }
      expect(await total({ type: row.indicator_type, assessed: "false" }), `${row.indicator_type} not assessed`).toBe(
        row.counts["not_assessed"] ?? 0,
      );
    }
  });

  test("the ranked lists really are ranked, and agree with the indicators list", async ({ request }) => {
    const overview = await fetchOverview(request);

    const scores = overview.top_risk.map((indicator) => indicator.risk_score);
    expect(scores).toEqual([...scores].sort((a, b) => b - a));
    expect(must(overview.top_risk[0]).indicator_id).toBe(
      must((await fetchIndicators(request, { sort: "risk", limit: 1 })).items[0]).indicator_id,
    );

    const checked = overview.recent.map((indicator) => Date.parse(must(indicator.last_checked_at)));
    expect(checked).toEqual([...checked].sort((a, b) => b - a));
    expect(must(overview.recent[0]).indicator_id).toBe(
      must((await fetchIndicators(request, { limit: 1 })).items[0]).indicator_id,
    );

    for (const facet of [overview.countries, overview.malware_families, overview.attack_techniques, overview.tags]) {
      const counts = facet.map((entry) => entry.count);
      expect(counts).toEqual([...counts].sort((a, b) => b - a));
      for (const entry of facet) {
        expect(entry.samples.length).toBeLessThanOrEqual(entry.count);
        expect(Math.max(...entry.samples.map((sample) => sample.risk_score))).toBe(entry.max_risk);
      }
    }
  });
});

test.describe("page structure", () => {
  test("has one h1 and the panels in a fixed reading order", async ({ page }) => {
    await openOverview(page);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Overview");
    await expect(panel(page, "Threat pulse")).toBeVisible();
    const titles = [
      "Threat pulse",
      "Risk posture",
      "Provider-reported countries",
      "Top countries",
      "Malware families",
      "ATT&CK techniques",
      "Provider tags",
      "Indicator types by risk",
      "Indicator mix",
      "Lookup activity",
      "Intelligence providers",
      "Highest risk",
      "Latest investigations",
      "Platform modules",
    ];
    // Each title is preceded by a decorative panel code that assistive technology skips.
    const headings = page.getByRole("heading", { level: 2 });
    await expect(headings).toHaveCount(titles.length);
    for (const [index, title] of titles.entries()) {
      await expect(headings.nth(index)).toHaveAccessibleName(title);
    }
    await expect(page.getByRole("link", { name: "Investigate an indicator" })).toHaveAttribute("href", "/investigate");
  });

  test("shows when the figures were fetched and what period each one covers", async ({ page, request }) => {
    const { scope } = await fetchOverview(request);
    await openOverview(page);
    await expect(page.getByText(/Live · refreshed \d{2}:\d{2}:\d{2} (AM|PM) IST/)).toBeVisible();
    await expect(page.getByText("Counts and risk bands cover every stored indicator.")).toContainText(
      `Trends cover the last ${scope.series_days} days and hourly activity the last ${scope.activity_days}, all in IST.`,
    );
  });
});

test.describe("headline figures", () => {
  test("show the API's numbers, with the change on the day before written out", async ({ page, request }) => {
    const { kpis } = await fetchOverview(request);
    await openOverview(page);

    const tiles = page.getByRole("region", { name: "Key figures" }).getByRole("link");
    await expect(tiles).toHaveCount(5);
    const expected = [
      {
        label: "Indicators tracked",
        value: kpis.total_indicators,
        text: [`${kpis.new_indicators_24h} new in the last 24 hours`, trendText(kpis.new_indicators_24h, kpis.new_indicators_prev_24h)],
        href: "/indicators",
      },
      {
        label: "Lookups, last 24 hours",
        value: kpis.lookups_24h,
        text: [trendText(kpis.lookups_24h, kpis.lookups_prev_24h)],
        href: "/indicators",
      },
      {
        label: "High-risk indicators",
        value: kpis.high_risk_indicators,
        text: ["High and critical together"],
        href: "/indicators?classification=high_risk&sort=risk",
      },
      {
        label: "Critical indicators",
        value: kpis.critical_indicators,
        text: ["Score above 80"],
        href: "/indicators?classification=critical&sort=risk",
      },
      {
        label: "Not assessed",
        value: kpis.not_assessed_indicators,
        text: ["No provider answered. That is not the same as clean."],
        href: "/indicators?classification=not_assessed",
      },
    ];
    for (const [index, tile] of expected.entries()) {
      const link = tiles.nth(index);
      await expect(link).toHaveAttribute("href", tile.href);
      await expect(link, `the ${tile.label} tile`).toHaveAccessibleName(
        new RegExp(`^${escapeRegExp(tile.label)} ${escapeRegExp(tile.value.toLocaleString("en-US"))}(?: |$)`),
      );
      for (const text of tile.text) await expect(link).toContainText(text);
    }
  });

  test("count up to the true value, which assistive technology has from the start", async ({ page, request }) => {
    const { kpis } = await fetchOverview(request);
    await openOverview(page);

    const tile = page.getByRole("region", { name: "Key figures" }).getByRole("link").first();
    const counter = tile.locator('[aria-hidden="true"]').filter({ hasText: /^[\d,]+$/ });
    await expect(counter).toHaveText(kpis.total_indicators.toLocaleString("en-US"));
    await expect(tile.locator(".sr-only").filter({ hasText: /^[\d,]+$/ })).toHaveText(
      kpis.total_indicators.toLocaleString("en-US"),
    );
  });

  test("show the final number at once when visual effects are off", async ({ page, request }) => {
    const { kpis } = await fetchOverview(request);
    await page.addInitScript(() => window.localStorage.setItem("cipherforge.effects", "off"));
    await openOverview(page);

    const tile = page.getByRole("region", { name: "Key figures" }).getByRole("link").first();
    await expect(tile.getByText(kpis.total_indicators.toLocaleString("en-US"), { exact: true })).toBeVisible();
    await expect(tile.locator('[aria-hidden="true"]').filter({ hasText: /^[\d,]+$/ })).toHaveCount(0);
  });

  test("the tiles are drill-downs: each opens exactly the indicators its number counts", async ({ page, request }) => {
    const { kpis } = await fetchOverview(request);
    const cases = [
      { name: /^Indicators tracked/, url: /\/indicators$/, found: kpis.total_indicators, shown: "All classifications" },
      { name: /^Lookups, last 24 hours/, url: /\/indicators$/, found: kpis.total_indicators, shown: "All classifications" },
      {
        name: /^High-risk indicators/,
        url: /\/indicators\?classification=high_risk&sort=risk$/,
        found: kpis.high_risk_indicators,
        shown: "High or critical",
      },
      {
        name: /^Critical indicators/,
        url: /\/indicators\?classification=critical&sort=risk$/,
        found: kpis.critical_indicators,
        shown: "Critical",
      },
      {
        name: /^Not assessed/,
        url: /\/indicators\?classification=not_assessed$/,
        found: kpis.not_assessed_indicators,
        shown: "Not assessed",
      },
    ];
    for (const item of cases) {
      await test.step(String(item.name), async () => {
        await openOverview(page);
        await page.getByRole("region", { name: "Key figures" }).getByRole("link", { name: item.name }).click();
        await expect(page).toHaveURL(item.url);
        await expect(page.getByRole("heading", { level: 1 })).toHaveText("Indicators");
        await expect(chosenClassification(page)).toHaveText(item.shown);
        await expectFound(page, item.found);
      });
    }
  });
});

test.describe("threat pulse", () => {
  const sentence = (point: Overview["series"][number]): string =>
    `${longDay(point.day)}: Lookups ${point.lookups}, High-risk lookups ${point.high_risk_lookups}`;

  test("has a data table with every day of the series", async ({ page, request }) => {
    const { series } = await fetchOverview(request);
    await openOverview(page);

    const table = page.getByRole("table", { name: CHART });
    await expect(table.locator("thead th")).toHaveText(["Day", "Lookups", "High-risk lookups"]);
    const rows = await table
      .locator("tbody tr")
      .evaluateAll((trs) => trs.map((tr) => Array.from(tr.children, (cell) => cell.textContent ?? "")));
    expect(rows).toEqual(series.map((point) => [longDay(point.day), String(point.lookups), String(point.high_risk_lookups)]));
  });

  test("can be read with the keyboard, one day at a time", async ({ page, request }) => {
    const { series } = await fetchOverview(request);
    await openOverview(page);

    const chart = page.getByRole("group", { name: CHART });
    await expect(chart).toHaveAttribute("aria-roledescription", "interactive chart");
    const readout = chart.getByRole("status");
    const first = must(series[0]);
    const last = must(series.at(-1));
    const beforeLast = must(series.at(-2));

    await expect(readout).toHaveText("");
    await chart.focus();
    await expect(readout).toHaveText(sentence(last));
    await chart.press("ArrowLeft");
    await expect(readout).toHaveText(sentence(beforeLast));
    await chart.press("ArrowRight");
    await expect(readout).toHaveText(sentence(last));
    await chart.press("ArrowRight");
    await expect(readout, "stops at the latest day").toHaveText(sentence(last));
    await chart.press("Home");
    await expect(readout).toHaveText(sentence(first));
    await chart.press("ArrowLeft");
    await expect(readout, "stops at the earliest day").toHaveText(sentence(first));
    await chart.press("End");
    await expect(readout).toHaveText(sentence(last));
    await chart.press("Escape");
    await expect(readout).toHaveText("");
    await expect(chart, "Escape clears the reading but keeps the focus").toBeFocused();
    await chart.press("ArrowLeft");
    await expect(readout, "starts again from the latest day").toHaveText(sentence(beforeLast));
    await page.keyboard.press("Tab");
    await expect(readout, "leaving the chart clears the reading").toHaveText("");
  });

  test("follows the pointer and shows the day's figures in a tooltip", async ({ page, request }) => {
    const { series } = await fetchOverview(request);
    await openOverview(page);

    const chart = page.getByRole("group", { name: CHART });
    const readout = chart.getByRole("status");
    const first = must(series[0]);
    const last = must(series.at(-1));
    const box = must(await chart.boundingBox(), "the chart's box");

    await chart.hover({ position: { x: 36, y: 90 } });
    await expect(readout).toHaveText(sentence(first));
    await expect(chart.locator("svg")).toContainText(longDay(first.day));

    await chart.hover({ position: { x: box.width - 18, y: 90 } });
    await expect(readout).toHaveText(sentence(last));
    await expect(chart.locator("svg")).toContainText(longDay(last.day));
    await expect(chart.locator("svg")).not.toContainText(longDay(first.day));

    await page.mouse.move(2, 2);
    await expect(readout).toHaveText("");
    await expect(chart.locator("svg")).not.toContainText(longDay(last.day));
  });
});

test.describe("risk posture", () => {
  test("lists every band with its count and share, and the bands lead to their indicators", async ({
    page,
    request,
  }) => {
    const { by_classification: bands } = await fetchOverview(request);
    await openOverview(page);

    const total = sum(Object.values(bands));
    const items = page.getByRole("list", { name: "Indicators by risk band" }).getByRole("listitem");
    await expect(items).toHaveCount(CLASSIFICATION_ORDER.length + 1);

    for (const [index, band] of CLASSIFICATION_ORDER.entries()) {
      const count = bands[band] ?? 0;
      const entry = items.nth(index).getByRole("link");
      await expect(entry).toHaveAccessibleName(`${CLASSIFICATION_LABELS[band]}: ${countOf(count)}, ${share(count, total)}`);
      await expect(entry).toHaveAttribute("href", `/indicators?classification=${band}&sort=risk`);
    }

    const notAssessed = bands["not_assessed"] ?? 0;
    const unassessed = items.nth(CLASSIFICATION_ORDER.length).getByRole("link");
    await expect(unassessed).toHaveAccessibleName(`Not assessed: ${countOf(notAssessed)}, ${share(notAssessed, total)}`);
    await expect(unassessed).toHaveAttribute("href", "/indicators?classification=not_assessed");
  });

  test("shows the total in the ring, and a band's own count while it is highlighted", async ({ page, request }) => {
    const { by_classification: bands } = await fetchOverview(request);
    await openOverview(page);

    const ring = panel(page, "Risk posture").locator("svg > text");
    await expect(ring.nth(0)).toHaveText(sum(Object.values(bands)).toLocaleString("en-US"));
    await expect(ring.nth(1)).toHaveText("indicators");

    const link = page.getByRole("list", { name: "Indicators by risk band" }).getByRole("link").first();
    await link.hover();
    await expect(ring.nth(0)).toHaveText(String(bands["critical"] ?? 0));
    await expect(ring.nth(1)).toHaveText("Critical");

    await page.mouse.move(2, 2);
    await expect(ring.nth(1)).toHaveText("indicators");

    await link.focus();
    await expect(ring.nth(1), "keyboard focus highlights it too").toHaveText("Critical");
  });

  test("states that not assessed is not the same as clean", async ({ page }) => {
    await openOverview(page);
    await expect(panel(page, "Risk posture")).toContainText("Not assessed means no provider answered. It is not the same as clean.");
  });

  test("each band opens exactly the indicators it counts, and so does not assessed", async ({ page, request }) => {
    const { by_classification: bands } = await fetchOverview(request);
    const targets = [
      ...CLASSIFICATION_ORDER.map((band) => ({
        band,
        label: CLASSIFICATION_LABELS[band],
        url: `/indicators\\?classification=${band}&sort=risk$`,
      })),
      { band: "not_assessed", label: "Not assessed", url: "/indicators\\?classification=not_assessed$" },
    ];
    for (const target of targets) {
      await test.step(target.band, async () => {
        await openOverview(page);
        await page
          .getByRole("list", { name: "Indicators by risk band" })
          .getByRole("link", { name: new RegExp(`^${target.label}:`) })
          .click();
        await expect(page).toHaveURL(new RegExp(target.url));
        await expect(chosenClassification(page)).toHaveText(target.label);
        await expectFound(page, bands[target.band] ?? 0);
      });
    }
  });
});

test.describe("types by risk", () => {
  const COLUMNS = ["informational", "low", "medium", "high", "critical", "not_assessed"] as const;
  const BAND_LABELS = { ...CLASSIFICATION_LABELS, not_assessed: "Not assessed" } as const;

  test("every cell has the API's count, and the non-zero ones open that slice", async ({ page, request }) => {
    const { matrix, by_type: types } = await fetchOverview(request);
    await openOverview(page);

    const table = page.getByRole("table", { name: "Indicators by type and risk band" });
    const headings = ["Type", "Informational", "Low", "Medium", "High", "Critical", "Not assessed", "Total"];
    await expect(table.getByRole("columnheader")).toHaveCount(headings.length);
    for (const [index, heading] of headings.entries()) {
      await expect(table.getByRole("columnheader").nth(index)).toHaveAccessibleName(heading);
    }

    const rows = table.locator("tbody tr");
    await expect(rows).toHaveCount(matrix.length);
    for (const [index, row] of matrix.entries()) {
      const label = TYPE_LABELS[row.indicator_type];
      const line = rows.nth(index);
      const header = line.getByRole("rowheader").getByRole("link");
      await expect(header).toHaveText(label);
      await expect(header).toHaveAttribute("href", `/indicators?type=${row.indicator_type}`);

      const cells = line.getByRole("cell");
      await expect(cells).toHaveCount(COLUMNS.length + 1);
      for (const [column, band] of COLUMNS.entries()) {
        const count = row.counts[band] ?? 0;
        const cell = cells.nth(column);
        await expect(cell, `${label} / ${band}`).toHaveText(String(count));
        if (count === 0) {
          await expect(cell.getByRole("link"), `${label} / ${band} has nowhere to go`).toHaveCount(0);
        } else {
          const link = cell.getByRole("link");
          await expect(link).toHaveAccessibleName(`${label}, ${BAND_LABELS[band]}: ${countOf(count)}`);
          await expect(link).toHaveAttribute("href", `/indicators?type=${row.indicator_type}&classification=${band}`);
        }
      }
      const rowTotal = sum(COLUMNS.map((band) => row.counts[band] ?? 0));
      expect(rowTotal).toBe(types[row.indicator_type] ?? 0);
      await expect(cells.nth(COLUMNS.length)).toHaveText(String(rowTotal));
    }
  });

  test("a cell opens the list for that type and band, with the same count", async ({ page, request }) => {
    const { matrix } = await fetchOverview(request);
    const picks = matrix.flatMap((row) =>
      [...CLASSIFICATION_ORDER, "not_assessed" as const]
        .filter((band) => (row.counts[band] ?? 0) > 0)
        .map((band) => ({ type: row.indicator_type, band, count: row.counts[band] ?? 0 })),
    );
    const some = new Set([
      must(picks[0]),
      must(picks.at(-1)),
      must(picks.find((pick) => pick.band === "not_assessed")),
    ]);
    for (const pick of some) {
      await test.step(`${pick.type} ${pick.band}`, async () => {
        await openOverview(page);
        await page
          .getByRole("link", {
            name: `${TYPE_LABELS[pick.type]}, ${BAND_LABELS[pick.band]}: ${countOf(pick.count)}`,
            exact: true,
          })
          .click();
        await expect(page).toHaveURL(new RegExp(`/indicators\\?type=${pick.type}&classification=${pick.band}$`));
        await expectFound(page, pick.count);
      });
    }
  });

  test("a type opens every indicator of that type", async ({ page, request }) => {
    const { by_type: types, matrix } = await fetchOverview(request);
    const type = must(matrix.find((row) => (types[row.indicator_type] ?? 0) > 0)).indicator_type;
    await openOverview(page);
    await page.getByRole("table", { name: "Indicators by type and risk band" }).getByRole("link", { name: TYPE_LABELS[type], exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/indicators\\?type=${type}$`));
    await expectFound(page, types[type] ?? 0);
  });
});

test.describe("indicator mix", () => {
  test("has one link per type with the API's count", async ({ page, request }) => {
    const { by_type: types, matrix } = await fetchOverview(request);
    await openOverview(page);

    const links = page.getByRole("group", { name: "Indicators by type", exact: true }).getByRole("link");
    await expect(links).toHaveCount(7);
    const known = new Set(matrix.map((row) => row.indicator_type));
    expect(known.size).toBe(7);
    for (const type of known) {
      const link = page.getByRole("link", { name: `${TYPE_LABELS[type]}: ${countOf(types[type] ?? 0)}`, exact: true });
      await expect(link).toHaveAttribute("href", `/indicators?type=${type}`);
    }
  });

  test("a spoke opens the indicators of that type", async ({ page, request }) => {
    const { by_type: types, matrix } = await fetchOverview(request);
    const type = must(matrix.find((row) => (types[row.indicator_type] ?? 0) > 0)).indicator_type;
    await openOverview(page);
    await page.getByRole("link", { name: `${TYPE_LABELS[type]}: ${countOf(types[type] ?? 0)}`, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/indicators\\?type=${type}$`));
    await expectFound(page, types[type] ?? 0);
  });
});

test.describe("lookup activity", () => {
  test("has a table with each day's lookups and busiest hour", async ({ page, request }) => {
    const { activity } = await fetchOverview(request);
    await openOverview(page);

    const table = page.getByRole("table", { name: "Lookups per day, with the busiest hour (IST)" });
    await expect(table.locator("thead th")).toHaveText(["Day", "Lookups", "Busiest hour"]);
    const rows = await table
      .locator("tbody tr")
      .evaluateAll((trs) => trs.map((tr) => Array.from(tr.children, (cell) => cell.textContent ?? "")));
    expect(rows).toEqual(
      activity.map((row) => {
        const peak = Math.max(...row.hours);
        return [
          longDay(row.day),
          String(sum(row.hours)),
          peak === 0 ? "None" : `${hourText(row.hours.indexOf(peak))} IST (${peak})`,
        ];
      }),
    );
  });

  test("draws a cell for every hour, brightest where the lookups peak", async ({ page, request }) => {
    const { activity } = await fetchOverview(request);
    await openOverview(page);

    const cells = panel(page, "Lookup activity").locator("svg rect:has(> title)");
    await expect(cells).toHaveCount(activity.length * 24);

    const peak = Math.max(...activity.flatMap((row) => row.hours));
    const day = must(activity.find((row) => row.hours.includes(peak)));
    const hour = day.hours.indexOf(peak);
    const title = `${longDay(day.day)}, ${hourText(hour)} IST: ${peak} ${peak === 1 ? "lookup" : "lookups"}`;
    await expect(cells.filter({ has: page.locator("title", { hasText: exactly(title) }) })).toHaveAttribute("fill-opacity", "1");

    const quiet = must(activity.find((row) => row.hours.includes(0)));
    const quietHour = quiet.hours.indexOf(0);
    const quietTitle = `${longDay(quiet.day)}, ${hourText(quietHour)} IST: 0 lookups`;
    await expect(cells.filter({ has: page.locator("title", { hasText: exactly(quietTitle) }) })).toHaveAttribute("fill-opacity", "0.07");
  });
});

test.describe("providers and modules", () => {
  test("say which providers are set up and that the demo's answers are made up", async ({ page, request }) => {
    const { providers } = await fetchOverview(request);
    await openOverview(page);

    const items = panel(page, "Intelligence providers").getByRole("listitem");
    await expect(items).toHaveCount(providers.length);
    for (const [index, provider] of providers.entries()) {
      const item = items.nth(index);
      await expect(item).toContainText(provider.display_name);
      await expect(item).toContainText(`Handles ${provider.supported_types.map((type) => TYPE_LABELS[type]).join(", ")}`);
      await expect(item).toContainText(provider.simulated ? "Simulated" : provider.configured ? "Configured" : "Not configured");
    }
    await expect(panel(page, "Intelligence providers")).toContainText(
      "Simulated providers return made-up answers for the development demo. Nothing leaves this machine.",
    );
  });

  test("warns when no provider is configured", async ({ page, request }) => {
    const { providers: known } = await fetchOverview(request);
    await serveOverview(page, (overview) => ({
      ...overview,
      providers: overview.providers.map((provider) => ({ ...provider, configured: false, simulated: false })),
    }));
    await openOverview(page);

    const providers = panel(page, "Intelligence providers");
    await expect(providers.getByRole("note")).toContainText("No threat-intelligence provider is configured");
    await expect(providers.getByRole("note")).toContainText("Not assessed");
    const items = providers.getByRole("listitem");
    await expect(items).toHaveCount(known.length);
    for (let index = 0; index < known.length; index += 1) {
      await expect(items.nth(index)).toContainText("Not configured");
    }
  });

  test("does not call a real provider simulated", async ({ page }) => {
    await serveOverview(page, (overview) => ({
      ...overview,
      providers: overview.providers.map((provider) => ({ ...provider, configured: true, simulated: false })),
    }));
    await openOverview(page);

    const providers = panel(page, "Intelligence providers");
    await expect(providers).not.toContainText("Simulated");
    await expect(providers).toContainText("Configured providers receive the indicators you investigate.");
    await expect(providers.getByRole("note")).toHaveCount(0);
  });

  test("mark the built modules live and the rest planned", async ({ page }) => {
    await openOverview(page);

    const modules = panel(page, "Platform modules").getByRole("listitem");
    await expect(modules).toHaveCount(5);
    const states: Record<string, string> = {
      "Threat intelligence": "Live",
      "Network monitoring": "Live",
      "Incident management": "Planned",
      "Secure file sharing": "Live",
      Administration: "Planned",
    };
    for (const [name, state] of Object.entries(states)) {
      const card = modules.filter({ hasText: name });
      await expect(card, name).toHaveCount(1);
      await expect(card.getByText(state, { exact: true })).toBeVisible();
    }
  });
});

test.describe("highest risk and latest investigations", () => {
  for (const { title, list, pick, more, href } of [
    {
      title: "Highest risk",
      list: "Highest-risk indicators",
      pick: (overview: Overview) => overview.top_risk,
      more: "View all by risk",
      href: "/indicators?sort=risk",
    },
    {
      title: "Latest investigations",
      list: "Latest investigations",
      pick: (overview: Overview) => overview.recent,
      more: "View all indicators",
      href: "/indicators",
    },
  ]) {
    test(`${title}: each row is a stored record and the list has a way to see them all`, async ({ page, request }) => {
      const indicators = pick(await fetchOverview(request));
      await openOverview(page);

      const items = page.getByRole("list", { name: list }).getByRole("listitem");
      await expect(items).toHaveCount(indicators.length);
      for (const [index, indicator] of indicators.entries()) {
        const item = items.nth(index);
        const assessed = indicator.confidence > 0;
        await expect(item.getByRole("link")).toHaveAttribute("href", `/indicators/${indicator.indicator_id}`);
        await expect(item).toContainText(indicator.indicator_value);
        await expect(item).toContainText(TYPE_LABELS[indicator.indicator_type]);
        await expect(item).toContainText(assessed ? CLASSIFICATION_LABELS[indicator.classification] : "Not assessed");
        await expect(item).toContainText(assessed ? `Score ${indicator.risk_score}` : "No score");
        await expect(item.locator("time")).toHaveAttribute(
          "title",
          /^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} (AM|PM) IST$/,
        );
      }

      await panel(page, title).getByRole("link", { name: more }).click();
      await expect(page).toHaveURL(new RegExp(`${escapeRegExp(href)}$`));
      await expect(page.getByRole("heading", { level: 1 })).toHaveText("Indicators");
    });
  }

  test("a row opens that record", async ({ page, request }) => {
    const { top_risk: top } = await fetchOverview(request);
    const indicator = must(top[0]);
    await openOverview(page);

    await page.getByRole("list", { name: "Highest-risk indicators" }).getByRole("link").first().click();
    await expect(page).toHaveURL(new RegExp(`/indicators/${indicator.indicator_id}$`));
    await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
    await expect(page.getByRole("main")).toContainText(indicator.indicator_value);
  });
});

const FACETS = [
  {
    name: "provider-reported country",
    list: "Top provider-reported countries",
    kind: "Provider-reported country",
    entries: (overview: Overview) => overview.countries.slice(0, 8),
    labelOf: (page: Page, key: string) => countryText(page, key),
  },
  {
    name: "malware family",
    list: "Malware families",
    kind: "Malware family",
    entries: (overview: Overview) => overview.malware_families,
    labelOf: (_page: Page, key: string) => Promise.resolve(key),
  },
  {
    name: "ATT&CK technique",
    list: "ATT&CK techniques",
    kind: "ATT&CK technique",
    entries: (overview: Overview) => overview.attack_techniques,
    labelOf: (_page: Page, key: string) => Promise.resolve(key),
  },
  {
    name: "provider tag",
    list: "Provider tags",
    kind: "Provider tag",
    entries: (overview: Overview) => overview.tags,
    labelOf: (_page: Page, key: string) => Promise.resolve(key),
  },
] as const;

test.describe("ranked lists", () => {
  for (const facet of FACETS) {
    test(`${facet.name}: the rows are the API's entries, most frequent first, with the risk behind each`, async ({
      page,
      request,
    }) => {
      const entries = facet.entries(await fetchOverview(request));
      expect(entries.length, `the demo data has ${facet.name} entries`).toBeGreaterThan(0);
      await openOverview(page);

      const rows = page.getByRole("list", { name: facet.list }).getByRole("button");
      await expect(rows).toHaveCount(entries.length);
      for (const [index, entry] of entries.entries()) {
        await expect(rows.nth(index)).toHaveAccessibleName(rowName(await facet.labelOf(page, entry.key), entry));
        await expect(rows.nth(index)).toHaveAttribute("aria-haspopup", "dialog");
      }
    });
  }
});

test.describe("the details drawer", () => {
  async function expectDrawer(
    page: Page,
    kind: string,
    title: string,
    entry: FacetEntry,
  ): Promise<Locator> {
    const drawer = page.getByRole("dialog", { name: `${kind}: ${title}` });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole("heading", { level: 2 })).toHaveText(title);
    await expect(drawer.getByText(kind, { exact: true })).toBeVisible();
    await expect(figure(drawer, "Indicators")).toHaveText(String(entry.count));
    await expect(figure(drawer, "Highest risk")).toContainText(CLASSIFICATION_LABELS[bandOf(entry.max_risk)]);
    await expect(figure(drawer, "Highest risk")).toContainText(String(entry.max_risk));

    const samples = drawer.getByRole("list").getByRole("listitem");
    await expect(samples).toHaveCount(entry.samples.length);
    for (const [index, sample] of entry.samples.entries()) {
      const item = samples.nth(index);
      await expect(item.getByRole("link")).toHaveText(sample.indicator_value);
      await expect(item.getByRole("link")).toHaveAttribute("href", `/indicators/${sample.indicator_id}`);
      await expect(item).toContainText(`${TYPE_LABELS[sample.indicator_type]} · score ${sample.risk_score}`);
      await expect(item).toContainText(CLASSIFICATION_LABELS[sample.classification]);
    }
    const truncated = drawer.getByText(/^Showing \d+ of/);
    if (entry.count > entry.samples.length) {
      await expect(truncated).toHaveText(`Showing ${entry.samples.length} of ${countOf(entry.count)}.`);
    } else {
      await expect(truncated).toHaveCount(0);
    }
    return drawer;
  }

  for (const facet of FACETS) {
    test(`opens for a ${facet.name} with the indicators behind it`, async ({ page, request }) => {
      const entries = facet.entries(await fetchOverview(request));
      await openOverview(page);

      const rows = page.getByRole("list", { name: facet.list }).getByRole("button");
      const picks = [0, entries.length - 1];
      const cut = entries.findIndex((entry) => entry.count > entry.samples.length);
      if (cut >= 0) picks.push(cut);
      for (const index of new Set(picks)) {
        const entry = must(entries[index]);
        await test.step(entry.key, async () => {
          await rows.nth(index).click();
          const drawer = await expectDrawer(page, facet.kind, await facet.labelOf(page, entry.key), entry);

          if (facet.kind === "Provider-reported country") {
            await expect(drawer).toContainText("It is not where an attacker is");
          }
          const external = drawer.locator('a[target="_blank"]');
          if (facet.kind === "ATT&CK technique" && /^T\d{4}(\.\d{3})?$/.test(entry.key)) {
            const link = drawer.getByRole("link", {
              name: `Read about ${entry.key} on MITRE ATT&CK (opens in a new tab)`,
            });
            await expect(link).toHaveAttribute("href", `https://attack.mitre.org/techniques/${entry.key.replace(".", "/")}/`);
            await expect(link).toHaveAttribute("target", "_blank");
            await expect(link).toHaveAttribute("rel", /\bnoopener\b/);
            await expect(link).toHaveAttribute("rel", /\bnoreferrer\b/);
            await expect(external).toHaveCount(1);
          } else {
            await expect(external).toHaveCount(0);
          }
          await page.keyboard.press("Escape");
          await expect(drawer).toBeHidden();
        });
      }
    });
  }

  test("moves focus in, holds it there and locks the page behind it", async ({ page, request }) => {
    const entry = must((await fetchOverview(request)).malware_families[0]);
    await openOverview(page);

    await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
    const drawer = page.getByRole("dialog", { name: `Malware family: ${entry.key}` });
    await expect(drawer.getByRole("button", { name: "Close details" })).toBeFocused();
    await expect(page.locator("#root")).toHaveAttribute("inert", "");
    await expect(page.locator("html")).toHaveClass(/overflow-hidden/);

    for (let press = 0; press < entry.samples.length + 3; press += 1) {
      await page.keyboard.press("Tab");
      await expect(drawer.locator(":focus"), "focus stays in the drawer").toHaveCount(1);
    }
    for (let press = 0; press < entry.samples.length + 3; press += 1) {
      await page.keyboard.press("Shift+Tab");
      await expect(drawer.locator(":focus")).toHaveCount(1);
    }

    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
    await expect(page.locator("#root")).not.toHaveAttribute("inert", "");
    await expect(page.locator("html")).not.toHaveClass(/overflow-hidden/);
  });

  test("closes with Escape, its button or a click outside, and focus goes back to the row", async ({
    page,
    request,
  }) => {
    const entry = must((await fetchOverview(request)).malware_families[0]);
    await openOverview(page);

    const row = page.getByRole("list", { name: "Malware families" }).getByRole("button").first();
    const drawer = page.getByRole("dialog", { name: `Malware family: ${entry.key}` });

    await row.click();
    await expect(drawer).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
    await expect(row).toBeFocused();

    await row.click();
    await drawer.getByRole("button", { name: "Close details" }).click();
    await expect(drawer).toBeHidden();
    await expect(row).toBeFocused();

    await row.click();
    await page.mouse.click(40, 450);
    await expect(drawer).toBeHidden();
    await expect(row).toBeFocused();
  });

  test("changes its title and figures when another row is chosen", async ({ page, request }) => {
    const [one, two] = (await fetchOverview(request)).malware_families;
    const [first, second] = [must(one), must(two)];
    await openOverview(page);

    const rows = page.getByRole("list", { name: "Malware families" }).getByRole("button");
    await rows.nth(0).click();
    await expect(page.getByRole("dialog", { name: `Malware family: ${first.key}` })).toBeVisible();
    await page.keyboard.press("Escape");
    await rows.nth(1).click();
    await expect(page.getByRole("dialog", { name: `Malware family: ${second.key}` })).toBeVisible();
    await expect(page.getByRole("dialog")).toHaveCount(1);
  });

  test("a listed indicator opens its record and closes the drawer", async ({ page, request }) => {
    const entry = must((await fetchOverview(request)).malware_families[0]);
    const sample = must(entry.samples[0]);
    await openOverview(page);

    await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
    await page.getByRole("dialog").getByRole("link", { name: sample.indicator_value }).click();
    await expect(page).toHaveURL(new RegExp(`/indicators/${sample.indicator_id}$`));
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
    await expect(page.locator("#root")).not.toHaveAttribute("inert", "");
    await expect(page.locator("html")).not.toHaveClass(/overflow-hidden/);
  });

  test("the command palette opens over the drawer, and Escape closes the palette first", async ({
    page,
    request,
  }) => {
    const entry = must((await fetchOverview(request)).malware_families[0]);
    await openOverview(page);

    await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
    const drawer = page.getByRole("dialog", { name: `Malware family: ${entry.key}` });
    await page.keyboard.press("Control+k");
    const palette = page.getByRole("dialog", { name: "Command palette" });
    await expect(palette).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(palette).toBeHidden();
    await expect(drawer).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
  });
});

test.describe("the map", () => {
  test("places one marker per country the providers reported, and says so when one has no position", async ({
    page,
    request,
  }) => {
    const { countries } = await fetchOverview(request);
    await openOverview(page);

    const map = page.getByRole("group", { name: "Provider-reported countries" });
    const labels = await map
      .getByRole("button")
      .evaluateAll((markers) => markers.map((marker) => marker.getAttribute("aria-label") ?? ""));

    const expected = new Set<string>();
    for (const entry of countries) {
      const band = CLASSIFICATION_LABELS[bandOf(entry.max_risk)];
      expected.add(`${await countryText(page, entry.key)}: ${countOf(entry.count)}, highest risk ${band}`);
    }
    for (const label of labels) expect(expected.has(label), `a marker for ${label}`).toBe(true);
    expect(new Set(labels).size, "no country is drawn twice").toBe(labels.length);

    const note = await page.getByText(/no position on this map/).allTextContents();
    const missing = note.length === 0 ? 0 : /^1 country/.test(must(note[0])) ? 1 : Number(/^(\d+)/.exec(must(note[0]))?.[1]);
    expect(labels.length + missing, "every country is on the map or counted in the note").toBe(countries.length);
    await expect(map.locator("title").first()).toHaveText(/\(provider-reported country\)$/);
  });

  test("a marker opens the same details as the list, from the keyboard too", async ({ page, request }) => {
    const { countries } = await fetchOverview(request);
    await openOverview(page);

    const markers = page.getByRole("group", { name: "Provider-reported countries" }).getByRole("button");
    const count = await markers.count();
    expect(count).toBeGreaterThan(0);

    const target = markers.first();
    const label = must(await target.getAttribute("aria-label"));
    const key = must(
      countries.find((entry) => label.endsWith(`(${entry.key}): ${countOf(entry.count)}, highest risk ${CLASSIFICATION_LABELS[bandOf(entry.max_risk)]}`)),
    ).key;
    const title = await countryText(page, key);
    const drawer = page.getByRole("dialog", { name: `Provider-reported country: ${title}` });

    await target.focus();
    await page.keyboard.press("Enter");
    await expect(drawer).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
    await expect(target, "focus goes back to the marker").toBeFocused();

    await page.keyboard.press("Space");
    await expect(drawer).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
    await expect(target).toBeFocused();
  });

  test("a click on a marker opens it", async ({ page, request }) => {
    const { countries } = await fetchOverview(request);
    await openOverview(page);

    const markers = page.getByRole("group", { name: "Provider-reported countries" }).getByRole("button");
    // The last marker is drawn on top of the others, so nothing covers the point that gets clicked.
    const top = markers.last();
    const label = must(await top.getAttribute("aria-label"));
    const key = must(countries.find((entry) => label.includes(`(${entry.key}):`))).key;
    await top.click();
    await expect(page.getByRole("dialog", { name: `Provider-reported country: ${await countryText(page, key)}` })).toBeVisible();
  });
});

test.describe("keeping up to date", () => {
  test("Refresh asks the API again and keeps the figures on screen meanwhile", async ({ page }) => {
    let gate: Promise<void> = Promise.resolve();
    await page.route(OVERVIEW_URL, async (route) => {
      await gate;
      await route.continue();
    });
    const requests = countRequests(page, OVERVIEW_REQUEST);
    await openOverview(page);
    expect(requests.count).toBe(1);

    let open = (): void => undefined;
    gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(page.getByRole("button", { name: "Refreshing…" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Refreshing…" }), "the button keeps the focus while it works").toBeFocused();
    await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();
    await expect.poll(() => requests.count).toBe(2);

    open();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeFocused();
    expect(requests.count).toBe(2);
  });

  test("re-asks by itself every minute", async ({ page }) => {
    await page.clock.install();
    const requests = countRequests(page, OVERVIEW_REQUEST);
    await openOverview(page);
    const stamp = async (): Promise<number> =>
      istClockSeconds(must(await page.getByText(/refreshed \d{2}:\d{2}:\d{2} (AM|PM) IST/).textContent()));
    const before = await stamp();
    expect(requests.count).toBe(1);

    await page.clock.runFor(61_000);
    await expect.poll(() => requests.count).toBe(2);
    await expect.poll(stamp).toBeGreaterThanOrEqual(before + 60);
  });

  test("keeps the last figures and says so when a refresh fails, then recovers", async ({ page, request, guard }) => {
    guard.expectStatus(503);
    const { kpis } = await fetchOverview(request);
    let failing = false;
    await page.route(OVERVIEW_URL, async (route) => {
      if (!failing) {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 503,
        json: { error: { code: "service_unavailable", message: "The database is busy.", correlation_id: "e2e-refresh" } },
      });
    });
    await openOverview(page);
    const tile = page.getByRole("region", { name: "Key figures" }).getByRole("link").first();
    await expect(tile).toHaveAccessibleName(new RegExp(`^Indicators tracked ${kpis.total_indicators.toLocaleString("en-US")}`));

    failing = true;
    await page.getByRole("button", { name: "Refresh" }).click();
    const alert = page.getByRole("main").getByRole("alert");
    await expect(alert).toContainText("The overview could not be refreshed. The figures below are from");
    await expect(page.getByText(/Stale · refreshed \d{2}:\d{2}:\d{2} (AM|PM) IST/)).toBeVisible();
    await expect(tile, "the old figures stay").toHaveAccessibleName(
      new RegExp(`^Indicators tracked ${kpis.total_indicators.toLocaleString("en-US")}`),
    );
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    failing = false;
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(alert).toBeHidden();
    await expect(page.getByText(/Live · refreshed \d{2}:\d{2}:\d{2} (AM|PM) IST/)).toBeVisible();
  });

  test("shows a loading note and placeholders until the first answer", async ({ page }) => {
    let open = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    await page.route(OVERVIEW_URL, async (route) => {
      await gate;
      await route.continue();
    });
    await page.goto("/");

    await expect(page.getByRole("status").filter({ hasText: "Loading the overview…" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh" }), "nothing to refresh yet").toHaveCount(0);
    await expect(page.getByRole("region", { name: "Key figures" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Investigate an indicator" })).toBeVisible();

    open();
    await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Loading the overview…" })).toHaveCount(0);
  });
});

test.describe("when the API does not answer", () => {
  test("explains an error answer and recovers on Try again", async ({ page, guard }) => {
    guard.expectStatus(500);
    let failing = true;
    await page.route(OVERVIEW_URL, async (route) => {
      if (!failing) {
        await route.continue();
        return;
      }
      await route.fulfill({
        status: 500,
        json: { error: { code: "internal_error", message: "The overview could not be built.", correlation_id: "e2e-overview-1" } },
      });
    });
    await page.goto("/");

    const alert = page.getByRole("main").getByRole("alert");
    await expect(alert).toContainText("The API reported an error");
    await expect(alert).toContainText("The overview could not be built.");
    await expect(alert).toContainText("Reference: e2e-overview-1");
    await expect(page.getByRole("region", { name: "Key figures" })).toHaveCount(0);

    failing = false;
    await alert.getByRole("button", { name: "Try again" }).click();
    await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();
    await expect(alert).toBeHidden();
  });

  test("says the API cannot be reached when the connection fails", async ({ page, guard }) => {
    guard.expectRequestFailure(OVERVIEW_REQUEST);
    await page.route(OVERVIEW_URL, (route) => route.abort("connectionrefused"));
    await page.goto("/");

    const alert = page.getByRole("main").getByRole("alert");
    await expect(alert).toContainText("Could not reach the API");
    await expect(alert.getByRole("button", { name: "Try again" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Investigate an indicator" }), "the rest of the page still works").toBeVisible();
  });

  test("reports an answer that is not the overview", async ({ page }) => {
    await page.route(OVERVIEW_URL, (route) => route.fulfill({ status: 200, json: { unexpected: true } }));
    await page.goto("/");

    await expect(page.getByRole("main").getByRole("alert")).toContainText("Unexpected response from the API");
    await expect(page.getByRole("region", { name: "Key figures" })).toHaveCount(0);
  });
});

test.describe("states the demo data cannot show", () => {
  test("an empty platform invites the first investigation and still lists providers and modules", async ({ page }) => {
    await serveOverview(page, (overview) => ({
      ...overview,
      kpis: EMPTY_KPIS,
      by_classification: {},
      by_type: {},
      matrix: [],
      series: [],
      activity: [],
      countries: [],
      malware_families: [],
      attack_techniques: [],
      tags: [],
      top_risk: [],
      recent: [],
    }));
    await openOverview(page);

    const empty = panel(page, "Nothing here yet");
    await expect(empty).toContainText("No indicators have been investigated yet.");
    await expect(empty.getByRole("link", { name: "Investigate the first one" })).toHaveAttribute("href", "/investigate");
    const labels = ["Indicators tracked", "Lookups, last 24 hours", "High-risk indicators", "Critical indicators", "Not assessed"];
    const tiles = page.getByRole("region", { name: "Key figures" }).getByRole("link");
    await expect(tiles).toHaveCount(labels.length);
    for (const [index, label] of labels.entries()) {
      await expect(tiles.nth(index), label).toHaveAccessibleName(new RegExp(`^${escapeRegExp(label)} 0(?: |$)`));
    }
    await expect(panel(page, "Intelligence providers")).toBeVisible();
    await expect(panel(page, "Platform modules")).toBeVisible();
    await expect(page.getByRole("heading", { level: 2, name: "Threat pulse" })).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 2, name: "Risk posture" })).toHaveCount(0);

    await empty.getByRole("link", { name: "Investigate the first one" }).click();
    await expect(page).toHaveURL(/\/investigate$/);
  });

  test("warns when the trends or the facets were built from only the newest records", async ({ page }) => {
    await serveOverview(page, (overview) => ({
      ...overview,
      scope: {
        ...overview.scope,
        lookups_truncated: true,
        lookups_scanned: 12345,
        answers_truncated: true,
        answers_scanned: 6789,
      },
    }));
    await openOverview(page);

    const notes = page.getByRole("note");
    await expect(notes.filter({ hasText: "Trends use only the 12,345 most recent lookups, so the oldest days may be undercounted." })).toBeVisible();
    await expect(
      notes.filter({
        hasText: "Countries, malware families, techniques and tags use only the 6,789 most recent provider answers.",
      }),
    ).toBeVisible();
  });

  test("a country the map has no position for is still listed, with a note", async ({ page }) => {
    const unplaced = async (): Promise<number> => {
      const notes = await page.getByText(/no position on this map/).allTextContents();
      const text = notes[0];
      if (text === undefined) return 0;
      return /^1 country/.test(text) ? 1 : Number(/^(\d+) countries/.exec(text)?.[1]);
    };
    await openOverview(page);
    const before = await unplaced();

    await serveOverview(page, (overview) => ({
      ...overview,
      countries: [...overview.countries, { key: "ZZ", count: 2, max_risk: 55, samples: [] }],
    }));
    await page.reload();
    await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();

    expect(await unplaced()).toBe(before + 1);
    await expect(page.getByText(/ countr(?:y has|ies have) no position on this map\. They are still counted in the list\./)).toBeVisible();
    await expect(
      page.getByRole("group", { name: "Provider-reported countries" }).getByRole("button", { name: /\(ZZ\):/ }),
    ).toHaveCount(0);
  });

  test("an entry without sample indicators says so", async ({ page }) => {
    await serveOverview(page, (overview) => ({
      ...overview,
      malware_families: [{ key: "NoSamples", count: 3, max_risk: 10, samples: [] }, ...overview.malware_families],
    }));
    await openOverview(page);

    await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
    const drawer = page.getByRole("dialog", { name: "Malware family: NoSamples" });
    await expect(drawer).toContainText("No indicator is listed for this value.");
    await expect(drawer).toContainText("Showing 0 of 3 indicators.");
  });
});
