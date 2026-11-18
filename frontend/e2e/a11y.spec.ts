import AxeBuilder from "@axe-core/playwright";
import type { APIRequestContext, Page } from "@playwright/test";

import { deleteViaApi, fetchIndicators, firstIndicator, fresh, uniqueSuffix } from "./api";
import { type Violation, settle, summarise } from "./axe";
import { type Guard, type Seed, expect, test } from "./fixtures";
import { investigate, openInvestigate, openList, openOverview, openRecord, openStatus } from "./open";
import { palette } from "./pages";
import { must } from "./text";

// WCAG 2.2 level AA, plus axe's own best-practice rules (landmarks, heading order, ...).
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

const OVERVIEW = /\/api\/v1\/intel\/overview$/;
const LIST = /\/api\/v1\/intel\/indicators\?/;
const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;
const SERVICE = /\/(health|ready)$/;
const DELETE_ONE = /\/api\/v1\/intel\/indicators\/[^/?]+$/;

async function expectAccessible(page: Page, what: string): Promise<void> {
  await settle(page);
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(violations.map(summarise), `accessibility problems: ${what}`).toEqual([]);
}

// axe cannot work out the colour behind text that sits on a gradient or beside a decorative pseudo-element, and
// it reports those checks as "incomplete" instead of failing them. On the overview that was 487 of 489 checks,
// so the scan above proves little about contrast. This audit paints the glass one flat colour that is lighter
// than the glass ever gets (light text that clears 4.5:1 on it clears it on the real, darker panels) and hides
// the decoration, so axe can measure nearly everything. Chart text, which axe treats as part of an image, is
// measured against the same flat colour here instead.
const FLAT_GLASS = "#1a2244";
const FLATTEN = `
  .cf-atmosphere, .cf-lamp, .cf-sweep { display: none !important; }
  *::before, *::after { display: none !important; }
  .hud-panel { background: ${FLAT_GLASS} !important; box-shadow: none !important; }
  .text-gradient { background: none !important; color: var(--color-arc) !important; }
`;

type AxeNode = Violation["nodes"][number];

// Short text and symbols are skipped by default because they may be icons. Here they are all text.
// Per-check options work at run time; axe's typings only list the options for rules.
const MEASURE_EVERYTHING = {
  checks: { "color-contrast": { options: { ignoreLength: true, ignoreUnicode: false } } },
} as unknown as Parameters<AxeBuilder["options"]>[0];

interface Measured {
  fgColor?: string;
  bgColor?: string;
  contrastRatio?: number;
  expectedContrastRatio?: string;
}

function dimness(node: AxeNode): string {
  const { fgColor, bgColor, contrastRatio, expectedContrastRatio } = (node.any[0]?.data ?? {}) as Measured;
  return `${node.target.join(" > ")}: ${fgColor} on ${bgColor} is ${contrastRatio}:1, needs ${expectedContrastRatio}\n      ${node.html.slice(0, 160)}`;
}

/** The text colour of each element against the flat glass, for the text axe could not measure. */
function dimOnGlass(page: Page, selectors: readonly string[]): Promise<string[]> {
  return page.evaluate(
    ({ selectors: targets, glass }) => {
      const painter = document.createElement("canvas").getContext("2d");
      if (!painter) throw new Error("There is no canvas to read colours with.");
      // The canvas turns any CSS colour (these are often color-mix() results) into plain sRGB.
      const read = (css: string): number[] => {
        painter.fillStyle = "#000000";
        painter.fillStyle = css;
        const value = painter.fillStyle;
        if (value.startsWith("#")) {
          return [1, 3, 5].map((start) => parseInt(value.slice(start, start + 2), 16)).concat(1);
        }
        const [r = 0, g = 0, b = 0, a = 1] = value
          .replace(/^rgba?\(|\)$/g, "")
          .split(",")
          .map(Number);
        return [r, g, b, a];
      };
      const channel = (value: number): number => {
        const share = value / 255;
        return share <= 0.03928 ? share / 12.92 : ((share + 0.055) / 1.055) ** 2.4;
      };
      const luminance = (colour: readonly number[]): number =>
        0.2126 * channel(colour[0] ?? 0) + 0.7152 * channel(colour[1] ?? 0) + 0.0722 * channel(colour[2] ?? 0);

      const ground = read(glass);
      const dim: string[] = [];
      for (const selector of targets) {
        const element = document.querySelector(selector);
        if (!element) continue;
        const style = getComputedStyle(element);
        const [r = 0, g = 0, b = 0, alpha = 1] = read(element instanceof SVGElement ? style.fill : style.color);
        const ink = [r, g, b].map((value, index) => value * alpha + (ground[index] ?? 0) * (1 - alpha));
        const lights = [luminance(ink), luminance(ground)].sort((a, b2) => b2 - a);
        const ratio = ((lights[0] ?? 0) + 0.05) / ((lights[1] ?? 0) + 0.05);
        const size = parseFloat(style.fontSize);
        const needs = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700) ? 3 : 4.5;
        if (ratio < needs) {
          dim.push(`${selector}: ${ratio.toFixed(2)}:1, needs ${needs}:1 ("${(element.textContent ?? "").trim().slice(0, 40)}")`);
        }
      }
      return dim;
    },
    { selectors, glass: FLAT_GLASS },
  );
}

async function expectReadable(page: Page, what: string): Promise<void> {
  await settle(page);
  // A constructed stylesheet, because the page's own policy forbids a <style> element.
  await page.evaluate((css) => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  }, FLATTEN);
  // Options first: withRules() sets the run options and options() replaces them.
  const result = await new AxeBuilder({ page })
    .options(MEASURE_EVERYTHING)
    .withRules(["color-contrast"])
    .analyze();
  const dim = result.violations.flatMap((rule) => rule.nodes).map(dimness);
  const unmeasured = result.incomplete
    .flatMap((rule) => rule.nodes)
    .flatMap((node) => (typeof node.target[0] === "string" ? [node.target[0]] : []));
  dim.push(...(await dimOnGlass(page, unmeasured)));
  expect(dim, `text that is hard to read: ${what}`).toEqual([]);
}

/** Holds every request that matches until the returned function is called. */
async function hold(page: Page, pattern: RegExp): Promise<() => void> {
  let release = (): void => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(pattern, async (route) => {
    await gate;
    await route.continue().catch(() => undefined);
  });
  return release;
}

function failure(status: number, code: string, message: string) {
  return { error: { code, message, correlation_id: `a11y-ref-${status}` } };
}

interface Tools {
  page: Page;
  request: APIRequestContext;
  guard: Guard;
  seed: Seed;
}

/** Stores indicators for the scene and shows them in the list. */
async function openSeeded(page: Page, seed: Seed, count: number) {
  const { search, items } = await seed(count);
  await openList(page, `?q=${search}`);
  return items;
}

function deleteButtonOf(page: Page, value: string) {
  return page.getByRole("button", { name: `Delete ${value}`, exact: true });
}

function confirmationToDeleteOne(page: Page) {
  return page.getByRole("dialog", { name: "Delete this indicator?", exact: true });
}

function confirmDeletionOfOne(page: Page): Promise<void> {
  return confirmationToDeleteOne(page).getByRole("button", { name: "Delete indicator", exact: true }).click();
}

/** Brings the app to a state. It may return a function that lets go of what it held back. */
type Scene = (tools: Tools) => Promise<(() => void) | void>;

const SCENES: Record<string, Scene> = {
  "the overview": ({ page }) => openOverview(page),
  "the overview while it loads": async ({ page }) => {
    const release = await hold(page, OVERVIEW);
    await page.goto("/");
    await expect(page.getByText("Loading the overview…")).toBeVisible();
    return release;
  },
  "the overview when it cannot load": async ({ page, guard }) => {
    guard.expectStatus(503);
    await page.route(OVERVIEW, (route) =>
      route.fulfill({ status: 503, json: failure(503, "service_unavailable", "The database is busy.") }),
    );
    await page.goto("/");
    await expect(page.getByRole("alert")).toContainText("The database is busy.");
  },
  "the overview with a chart reading": async ({ page }) => {
    await openOverview(page);
    const chart = page.getByRole("group", { name: "Lookups and high-risk lookups per day" });
    await chart.focus();
    await chart.press("ArrowLeft");
    await expect(chart.getByRole("status")).not.toHaveText("");
  },
  "the overview with a details drawer": async ({ page }) => {
    await openOverview(page);
    await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
  },
  "the command palette": async ({ page }) => {
    await openOverview(page);
    await page.keyboard.press("Control+k");
    await expect(palette(page).dialog).toBeVisible();
  },
  "the command palette with an indicator typed": async ({ page }) => {
    await openOverview(page);
    await page.keyboard.press("Control+k");
    await palette(page).box.fill("203.0.113.9");
    await expect(palette(page).options.first()).toBeVisible();
  },
  "the investigate page": ({ page }) => openInvestigate(page),
  "the investigate page with a problem in the field": async ({ page }) => {
    await openInvestigate(page);
    await page.getByRole("button", { name: "Investigate", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Enter an indicator to investigate.");
  },
  "the investigate page while a lookup runs": async ({ page }) => {
    const release = await hold(page, INVESTIGATE);
    await investigate(page, fresh.domain());
    await expect(page.getByText(/^Asking the providers about/)).toBeVisible();
    return release;
  },
  "the investigate page with a result": async ({ page }) => {
    await investigate(page, fresh.domain());
    await expect(page.getByRole("link", { name: "Open the saved record" })).toBeVisible();
  },
  "the investigate page with a provider that failed": async ({ page }) => {
    await investigate(page, `rate-limit-${uniqueSuffix()}.example.net`);
    await expect(page.getByRole("link", { name: "Open the saved record" })).toBeVisible();
  },
  "the investigate page when the API refuses": async ({ page, guard }) => {
    guard.expectStatus(429);
    await page.route(INVESTIGATE, (route) =>
      route.fulfill({
        status: 429,
        headers: { "Retry-After": "20" },
        json: failure(429, "rate_limited", "Too many investigations. Try again shortly."),
      }),
    );
    await investigate(page, fresh.domain());
    await expect(page.getByRole("alert")).toContainText("Rate limit reached");
  },
  "the indicators list": ({ page }) => openList(page),
  "the indicators list, narrowed and sorted": ({ page }) => openList(page, "?classification=high_risk&sort=risk"),
  "the indicators list with nothing found": async ({ page }) => {
    await page.goto(`/indicators?q=no-such-indicator-${uniqueSuffix()}`);
    await expect(page.getByText("No indicators match these filters.")).toBeVisible();
  },
  "the indicators list when it cannot load": async ({ page, guard }) => {
    guard.expectStatus(500);
    await page.route(LIST, (route) =>
      route.fulfill({ status: 500, json: failure(500, "internal_error", "The service is having a problem.") }),
    );
    await page.goto("/indicators");
    await expect(page.getByRole("alert")).toContainText("The service is having a problem.");
  },
  "the indicators list with some rows ticked": async ({ page, seed }) => {
    await openSeeded(page, seed, 3);
    const rows = page.getByRole("checkbox", { name: /^Select e2e-del-/ });
    await rows.nth(0).check();
    await rows.nth(1).check();
    await expect(page.getByRole("button", { name: "Delete selected (2)", exact: true })).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Select all indicators on this page" })).toBeChecked({
      indeterminate: true,
    });
  },
  "the indicators list with every row ticked": async ({ page, seed }) => {
    await openSeeded(page, seed, 3);
    await page.getByRole("checkbox", { name: "Select all indicators on this page" }).check();
    await expect(page.getByRole("button", { name: "Delete selected (3)", exact: true })).toBeVisible();
  },
  "the confirmation to delete one indicator": async ({ page, seed }) => {
    const [first] = await openSeeded(page, seed, 2);
    await deleteButtonOf(page, must(first, "an indicator").indicator_value).click();
    await expect(confirmationToDeleteOne(page)).toBeVisible();
  },
  "the confirmation to delete several indicators": async ({ page, seed }) => {
    await openSeeded(page, seed, 7);
    await page.getByRole("checkbox", { name: "Select all indicators on this page" }).check();
    await page.getByRole("button", { name: "Delete selected (7)", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Delete 7 indicators?", exact: true });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText("and 2 more");
  },
  "the confirmation to delete while it deletes": async ({ page, seed }) => {
    const [first] = await openSeeded(page, seed, 2);
    const release = await hold(page, DELETE_ONE);
    await deleteButtonOf(page, must(first, "an indicator").indicator_value).click();
    await confirmDeletionOfOne(page);
    await expect(confirmationToDeleteOne(page).getByRole("button", { name: "Deleting…" })).toBeVisible();
    return release;
  },
  "the confirmation when the deletion failed": async ({ page, seed, guard }) => {
    guard.expectStatus(500);
    await page.route(DELETE_ONE, (route) =>
      route.request().method() === "DELETE"
        ? route.fulfill({ status: 500, json: failure(500, "internal_error", "The service is having a problem.") })
        : route.continue(),
    );
    const [first] = await openSeeded(page, seed, 2);
    await deleteButtonOf(page, must(first, "an indicator").indicator_value).click();
    await confirmDeletionOfOne(page);
    await expect(confirmationToDeleteOne(page).getByRole("alert")).toContainText("The service is having a problem.");
  },
  "the indicators list after a deletion": async ({ page, seed }) => {
    const [first] = await openSeeded(page, seed, 2);
    await deleteButtonOf(page, must(first, "an indicator").indicator_value).click();
    await confirmDeletionOfOne(page);
    await expect(page.getByRole("status").filter({ hasText: "Deleted 1 indicator" })).toBeVisible();
  },
  "the indicators list after everything on it was deleted": async ({ page, seed }) => {
    await openSeeded(page, seed, 2);
    await page.getByRole("checkbox", { name: "Select all indicators on this page" }).check();
    await page.getByRole("button", { name: "Delete selected (2)", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Delete 2 indicators?", exact: true })
      .getByRole("button", { name: "Delete 2 indicators", exact: true })
      .click();
    await expect(page.getByText("No indicators match these filters.")).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Deleted 2 indicators" })).toBeVisible();
  },
  "a stored record with its delete confirmation": async ({ page, seed }) => {
    const { items } = await seed(1);
    await openRecord(page, must(items[0], "an indicator").indicator_id);
    await page.getByRole("button", { name: "Delete indicator", exact: true }).click();
    await expect(confirmationToDeleteOne(page)).toBeVisible();
  },
  "a stored record after it is deleted": async ({ page, seed }) => {
    const { items } = await seed(1);
    await openRecord(page, must(items[0], "an indicator").indicator_id);
    await page.getByRole("button", { name: "Delete indicator", exact: true }).click();
    await confirmDeletionOfOne(page);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator deleted" })).toBeVisible();
  },
  "a stored record that was already deleted": async ({ page, request, seed, guard }) => {
    guard.expectStatus(404);
    const { items } = await seed(1);
    const record = must(items[0], "an indicator");
    await openRecord(page, record.indicator_id);
    await deleteViaApi(request, [record.indicator_id]);
    await page.getByRole("button", { name: "Delete indicator", exact: true }).click();
    await confirmDeletionOfOne(page);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator already gone" })).toBeVisible();
  },
  "a stored record with the highest risk": async ({ page, request }) => {
    await openRecord(page, (await firstIndicator(request, { sort: "risk" })).indicator_id);
  },
  "a stored record that no provider answered for": async ({ page, request }) => {
    const [record] = (await fetchIndicators(request, { assessed: "false", limit: 1 })).items;
    await openRecord(page, must(record, "a record nobody answered for").indicator_id);
  },
  "a stored record while it is re-checked": async ({ page, request }) => {
    const release = await hold(page, INVESTIGATE);
    await openRecord(page, (await firstIndicator(request)).indicator_id);
    await page.getByRole("button", { name: "Re-check with providers" }).click();
    await expect(page.getByRole("button", { name: "Re-checking…" })).toBeVisible();
    return release;
  },
  "a record that does not exist": async ({ page, guard }) => {
    guard.expectStatus(404);
    await page.goto("/indicators/00000000-0000-4000-8000-000000000000");
    await expect(page.getByRole("heading", { level: 1, name: "Indicator not found" })).toBeVisible();
  },
  "the system status, operational": ({ page }) => openStatus(page),
  "the system status, degraded": async ({ page, guard }) => {
    guard.expectStatus(503);
    await page.route(/\/ready$/, (route) =>
      route.fulfill({ status: 503, json: { status: "not_ready", checks: { database: "unavailable" } } }),
    );
    await page.goto("/status");
    await expect(page.getByText("Degraded", { exact: true })).toBeVisible();
  },
  "the system status, down": async ({ page, guard }) => {
    guard.expectRequestFailure(SERVICE);
    await page.route(SERVICE, (route) => route.abort("connectionrefused"));
    await page.goto("/status");
    await expect(page.getByText("Down", { exact: true })).toBeVisible();
  },
  "the system status while it checks": async ({ page }) => {
    const release = await hold(page, SERVICE);
    await page.goto("/status");
    await expect(page.getByText("Contacting the API…")).toBeVisible();
    return release;
  },
  "a page that does not exist": async ({ page }) => {
    await page.goto("/there/is/nothing/here");
    await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
  },
};

function scan(
  names: readonly string[],
  check: (page: Page, what: string) => Promise<void> = expectAccessible,
): void {
  for (const name of names) {
    test(name, async ({ page, request, guard, seed }) => {
      const release = await must(SCENES[name], name)({ page, request, guard, seed });
      try {
        await check(page, name);
      } finally {
        if (release) release();
      }
    });
  }
}

test.describe("with motion reduced", () => {
  test.use({ reducedMotion: "reduce" });
  scan(Object.keys(SCENES));
});

test.describe("text contrast on the lightest glass", () => {
  test.use({ reducedMotion: "reduce" });
  scan(Object.keys(SCENES), expectReadable);

  test("the audit does notice text that is too dim", async ({ page }) => {
    await openStatus(page);
    await page.evaluate(() => {
      const glass = document.querySelector(".hud-panel");
      if (!glass) throw new Error("The status page has no panel.");
      const words = document.createElement("span");
      words.textContent = "Dim words";
      words.style.color = "#5b7099";
      const chart = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
      label.textContent = "Dim chart label";
      label.style.fill = "#5b7099";
      label.style.fontSize = "10px";
      chart.append(label);
      glass.append(words, chart);
    });

    const failure = await expectReadable(page, "a page with dim text").then(
      () => "",
      (error: unknown) => String(error),
    );
    expect(failure).toContain("Dim words");
    expect(failure).toContain("Dim chart label");
  });
});

test.describe("on a phone", () => {
  test.use({ reducedMotion: "reduce", viewport: { width: 390, height: 844 }, hasTouch: true });
  scan([
    "the overview",
    "the overview with a details drawer",
    "the command palette",
    "the investigate page with a result",
    "the indicators list",
    "the indicators list with some rows ticked",
    "the confirmation to delete several indicators",
    "a stored record with the highest risk",
    "a stored record after it is deleted",
    "the system status, operational",
  ]);
});

test.describe("with the effects on", () => {
  test.use({ reducedMotion: "no-preference" });
  scan([
    "the overview",
    "the investigate page",
    "the investigate page with a result",
    "the indicators list",
    "the confirmation to delete one indicator",
    "a stored record with the highest risk",
    "the system status, operational",
  ]);
});
