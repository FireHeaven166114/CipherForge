import type { Page, Request } from "@playwright/test";

import type { Indicator } from "../src/types/intel";
import {
  CLASSIFICATION_LABELS,
  CLASSIFICATION_ORDER,
  TYPE_LABELS,
  TYPE_ORDER,
  countRequests,
  fetchIndicator,
  fetchIndicators,
  firstIndicator,
  fresh,
  investigateViaApi,
  storedIndicator,
  uniqueSuffix,
} from "./api";
import { expect, test } from "./fixtures";
import { chosenClassification, expectDossier, expectFound, listFilters, panel, pause } from "./pages";
import { must } from "./text";

const LIST = /\/api\/v1\/intel\/indicators\?/;
const DETAIL = /\/api\/v1\/intel\/indicators\/[^/?]+$/;
const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;
const NO_SUCH_ID = "00000000-0000-4000-8000-000000000000";
const EN_DASH = "\u2013";
const EM_DASH = "\u2014";

const COLUMNS = ["Indicator", "Type", "Classification", "Score", "Confidence", "Sources", "Status", "Last checked"];
const ALL_CLASSIFICATIONS = [
  "All classifications",
  "High or critical",
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
  "Not assessed",
];

async function openList(page: Page, query = ""): Promise<void> {
  await page.goto(`/indicators${query}`);
  await expect(page.getByRole("heading", { level: 1, name: "Indicators", exact: true })).toBeVisible();
}

/** The path and query of the address bar, which is where the filters live. */
async function expectAddress(page: Page, address: string): Promise<void> {
  await expect
    .poll(() => {
      const { pathname, search } = new URL(page.url());
      return pathname + search;
    })
    .toBe(address);
}

/** The indicators the list shows, top to bottom. */
function shownValues(page: Page): Promise<string[]> {
  return page.locator("tbody th a").allTextContents();
}

function valuesOf(items: readonly Indicator[]): string[] {
  return items.map((item) => item.indicator_value);
}

/** The address of a list narrowed by every filter at once, which writes them in a fixed order. */
function filterQuery(search: string): string {
  return new URLSearchParams([
    ["q", search],
    ["type", "ipv6"],
    ["classification", "high_risk"],
    ["sort", "risk"],
  ]).toString();
}

/** Resolves with the next list request the browser makes whose query passes the check. */
function listRequest(page: Page, matches: (query: URLSearchParams) => boolean): Promise<Request> {
  return page.waitForRequest((request) => LIST.test(request.url()) && matches(new URL(request.url()).searchParams));
}

/** What each choice in the Classification filter asks the API for, and what its rows may show. */
const CHOICES = [
  { value: "high_risk", label: "High or critical", bands: ["high", "critical"], assessed: "true", badges: ["High", "Critical"] },
  ...CLASSIFICATION_ORDER.map((band) => ({
    value: band,
    label: CLASSIFICATION_LABELS[band],
    bands: [band] as string[],
    assessed: "true",
    badges: [CLASSIFICATION_LABELS[band]],
  })),
  { value: "not_assessed", label: "Not assessed", bands: [] as string[], assessed: "false", badges: ["Not assessed"] },
];

test.describe("the list", () => {
  test("shows the most recently checked indicators first, as the API lists them", async ({ page, request }) => {
    const stored = await fetchIndicators(request);
    await openList(page);
    await expectFound(page, stored.total);

    const table = page.getByRole("table", { name: "Indicators, sorted by most recent check" });
    await expect(table.getByRole("columnheader")).toHaveText(COLUMNS);
    expect(await shownValues(page)).toEqual(valuesOf(stored.items));
    await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
      `Showing 1${EN_DASH}${stored.items.length} of ${stored.total}`,
    );
  });

  test("every row repeats what the stored record says", async ({ page, request }) => {
    const stored = await fetchIndicators(request);
    await openList(page);
    await expectFound(page, stored.total);

    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(stored.items.length);
    for (const [index, record] of stored.items.entries()) {
      const row = rows.nth(index);
      const answered = record.confidence > 0;
      const cells = (await row.getByRole("cell").allTextContents()).map((text) => text.trim());
      const band = answered ? CLASSIFICATION_LABELS[record.classification] : "Not assessed";

      const link = row.getByRole("rowheader").getByRole("link");
      await expect(link, record.indicator_value).toHaveText(record.indicator_value);
      await expect(link).toHaveAttribute("href", `/indicators/${record.indicator_id}`);
      expect(cells[0], "type").toBe(TYPE_LABELS[record.indicator_type]);
      expect(cells[1], "classification").toMatch(new RegExp(`${band}$`));
      expect(cells[2], "score").toBe(answered ? String(record.risk_score) : EM_DASH);
      expect(cells[3], "confidence").toBe(answered ? String(record.confidence) : EM_DASH);
      expect(cells[4], "sources").toBe(String(record.source_count));
      expect(cells[5], "status").toBe(record.status === "active" ? "Active" : "Stale");
      if (record.last_checked_at === null) {
        expect(cells[6], "last checked").toBe("Never");
      } else {
        const stamp = await row.locator("time").getAttribute("datetime");
        expect(Date.parse(must(stamp)), "last checked").toBe(Date.parse(record.last_checked_at));
      }
    }
  });

  test("an indicator no provider answered for reads Not assessed, never Informational", async ({ page, request }) => {
    const record = must((await fetchIndicators(request, { assessed: "false", limit: 1 })).items[0], "an unanswered indicator");
    await openList(page, `?q=${encodeURIComponent(record.indicator_value)}`);

    const row = page.locator("tbody tr").filter({ has: page.getByRole("link", { name: record.indicator_value, exact: true }) });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText("Not assessed");
    await expect(row).not.toContainText("Informational");
    expect((await row.getByRole("cell").allTextContents()).map((text) => text.trim()).slice(2, 4)).toEqual([EM_DASH, EM_DASH]);
  });
});

test.describe("filters", () => {
  test("offer every type, every risk group the overview counts, and both sort orders", async ({ page }) => {
    await openList(page);
    const { type, classification, sort } = listFilters(page);
    await expect(type.locator("option")).toHaveText(["All types", ...TYPE_ORDER.map((entry) => TYPE_LABELS[entry])]);
    await expect(classification.locator("option")).toHaveText(ALL_CLASSIFICATIONS);
    await expect(sort.locator("option")).toHaveText(["Most recently checked", "Highest risk first"]);
  });

  for (const type of TYPE_ORDER) {
    test(`Type ${TYPE_LABELS[type]} lists only that type`, async ({ page, request }) => {
      const stored = await fetchIndicators(request, { type });
      expect(stored.total, `the demo data has ${type} indicators`).toBeGreaterThan(0);
      await openList(page);

      await listFilters(page).type.selectOption({ label: TYPE_LABELS[type] });
      await expectAddress(page, `/indicators?type=${type}`);
      await expectFound(page, stored.total);
      expect(await shownValues(page)).toEqual(valuesOf(stored.items));
      expect(await page.locator("tbody tr td:nth-of-type(1)").allTextContents()).toEqual(
        stored.items.map(() => TYPE_LABELS[type]),
      );
    });
  }

  for (const choice of CHOICES) {
    test(`Classification ${choice.label} lists exactly what the API counts for it`, async ({ page, request }) => {
      const stored = await fetchIndicators(request, { classification: choice.bands, assessed: choice.assessed });
      expect(stored.total, `the demo data has indicators for ${choice.label}`).toBeGreaterThan(0);
      await openList(page);

      const asked = listRequest(
        page,
        (query) => query.getAll("classification").join() === choice.bands.join() && query.get("assessed") === choice.assessed,
      );
      await listFilters(page).classification.selectOption({ label: choice.label });
      await asked;
      await expectAddress(page, `/indicators?classification=${choice.value}`);
      await expect(chosenClassification(page)).toHaveText(choice.label);
      await expectFound(page, stored.total);

      expect(await shownValues(page)).toEqual(valuesOf(stored.items));
      for (const badge of await page.locator("tbody tr td:nth-of-type(2)").allTextContents()) {
        expect(choice.badges.some((label) => badge.trim().endsWith(label)), `${badge} is one of ${choice.badges.join(", ")}`).toBe(true);
      }
    });
  }

  test("Highest risk first orders by score, and the default order comes back", async ({ page, request }) => {
    const byRisk = await fetchIndicators(request, { sort: "risk" });
    await openList(page);
    await expectFound(page, byRisk.total);

    await listFilters(page).sort.selectOption({ label: "Highest risk first" });
    await expectAddress(page, "/indicators?sort=risk");
    await expect(page.getByRole("table", { name: "Indicators, sorted by highest risk" })).toBeVisible();
    expect(await shownValues(page)).toEqual(valuesOf(byRisk.items));

    const scores = (await page.locator("tbody tr td:nth-of-type(3)").allTextContents()).map((text) =>
      text.trim() === EM_DASH ? 0 : Number(text.trim()),
    );
    expect(scores).toEqual([...scores].sort((a, b) => b - a));

    await listFilters(page).sort.selectOption({ label: "Most recently checked" });
    await expectAddress(page, "/indicators");
    await expect(page.getByRole("table", { name: "Indicators, sorted by most recent check" })).toBeVisible();
  });

  test("search finds part of a value, ignoring case and surrounding spaces", async ({ page, request }) => {
    const sample = await firstIndicator(request, { type: "domain" });
    const part = sample.indicator_value.slice(2, 10).toUpperCase();
    const stored = await fetchIndicators(request, { q: part });
    expect(stored.total).toBeGreaterThan(0);
    await openList(page);

    const { search } = listFilters(page);
    await search.fill(`  ${part}  `);
    await search.press("Enter");
    await expectAddress(page, `/indicators?${new URLSearchParams({ q: part }).toString()}`);
    await expectFound(page, stored.total);
    expect(await shownValues(page)).toEqual(valuesOf(stored.items));
    await expect(search).toHaveValue(part);
  });

  test("the Search button works too, and typing alone asks the API nothing", async ({ page, request }) => {
    const sample = await firstIndicator(request, { type: "ipv4" });
    const stored = await fetchIndicators(request, { q: sample.indicator_value });
    await openList(page);
    await expectFound(page, (await fetchIndicators(request)).total);

    const requests = countRequests(page, LIST);
    const { search, searchButton } = listFilters(page);
    await search.pressSequentially(sample.indicator_value, { delay: 10 });
    await expect(search).toHaveValue(sample.indicator_value);
    expect(requests.count, "no request until the analyst searches").toBe(0);

    await searchButton.click();
    await expectFound(page, stored.total);
    expect(requests.count).toBe(1);
    expect(await shownValues(page)).toEqual(valuesOf(stored.items));
  });

  test("percent and underscore in a search mean themselves, not any text", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    await openList(page);
    for (const wildcard of ["%", "_"]) {
      const stored = await fetchIndicators(request, { q: wildcard });
      expect(stored.total, `${wildcard} must not match everything`).toBeLessThan(all.total);

      const { search } = listFilters(page);
      await search.fill(wildcard);
      await search.press("Enter");
      await expectAddress(page, `/indicators?${new URLSearchParams({ q: wildcard }).toString()}`);
      await expectFound(page, stored.total);
      expect(await shownValues(page)).toEqual(valuesOf(stored.items));
    }
  });

  test("the search box takes at most 256 characters", async ({ page }) => {
    await openList(page);
    const { search } = listFilters(page);
    await search.fill("a".repeat(400));
    await expect(search).toHaveValue("a".repeat(256));
  });

  test("filters combine, appear in the address in a fixed order, and Reset clears them all", async ({ page, request }) => {
    const sample = must(
      (await fetchIndicators(request, { type: "ipv6", classification: ["high", "critical"], assessed: "true", limit: 1 })).items[0],
      "a high-risk IPv6 indicator",
    );
    const part = sample.indicator_value.slice(-4);
    const stored = await fetchIndicators(request, {
      q: part,
      type: "ipv6",
      classification: ["high", "critical"],
      assessed: "true",
      sort: "risk",
    });
    const all = await fetchIndicators(request);
    await openList(page);
    const { search, type, classification, sort, reset } = listFilters(page);
    await expect(reset, "nothing is filtered yet").toHaveCount(0);

    await sort.selectOption({ label: "Highest risk first" });
    await expect(reset, "sorting is not filtering").toHaveCount(0);
    await type.selectOption({ label: "IPv6" });
    await classification.selectOption({ label: "High or critical" });
    await search.fill(part);
    await search.press("Enter");

    await expectAddress(page, `/indicators?${filterQuery(part)}`);
    await expectFound(page, stored.total);
    expect(await shownValues(page)).toEqual(valuesOf(stored.items));
    await expect(reset).toBeVisible();

    await reset.click();
    await expectAddress(page, "/indicators");
    await expectFound(page, all.total);
    await expect(search).toHaveValue("");
    await expect(type).toHaveValue("");
    await expect(classification).toHaveValue("");
    await expect(sort).toHaveValue("recent");
    await expect(reset).toHaveCount(0);
  });

  test("changing a filter goes back to the first page", async ({ page, request }) => {
    const domains = await fetchIndicators(request, { type: "domain" });
    await openList(page, "?page=2");
    await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(`Showing 26${EN_DASH}`);

    await listFilters(page).type.selectOption({ label: "Domain" });
    await expectAddress(page, "/indicators?type=domain");
    await expectFound(page, domains.total);
    await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(`Showing 1${EN_DASH}`);
  });

  test("a search that matches nothing says so and offers a way out", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    await openList(page, `?q=no-such-indicator-${uniqueSuffix()}`);
    await expectFound(page, 0);
    await expect(page.getByText("No indicators match these filters.")).toBeVisible();
    await expect(page.getByRole("table")).toHaveCount(0);

    const resets = listFilters(page).reset;
    await expect(resets, "one in the filter bar and one beside the message").toHaveCount(2);
    await resets.last().click();
    await expectAddress(page, "/indicators");
    await expectFound(page, all.total);
  });

  test("a slow answer to an earlier choice never replaces the answer to the latest one", async ({ page, request }) => {
    const domains = await fetchIndicators(request, { type: "domain" });
    let release: () => void = () => undefined;
    const slowDone = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route(LIST, async (route) => {
      if (new URL(route.request().url()).searchParams.get("type") === "ipv4") {
        await pause(1_500);
        // The page has already given up on this request, so there may be nothing left to answer.
        await route.continue().catch(() => undefined);
        release();
      } else {
        await route.continue();
      }
    });
    await openList(page);
    await expectFound(page, (await fetchIndicators(request)).total);

    await listFilters(page).type.selectOption({ label: "IPv4" });
    await listFilters(page).type.selectOption({ label: "Domain" });
    await expectFound(page, domains.total);

    await slowDone;
    await expectFound(page, domains.total);
    expect(await shownValues(page)).toEqual(valuesOf(domains.items));
    await expect(listFilters(page).type).toHaveValue("domain");
  });
});

test.describe("paging", () => {
  test("moves through the list 25 at a time", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    expect(all.total, "the demo data spans several pages").toBeGreaterThan(50);
    const pages = Math.ceil(all.total / 25);

    await openList(page);
    await expectFound(page, all.total);
    const pagination = page.getByRole("navigation", { name: "Pagination" });
    const previous = pagination.getByRole("button", { name: "Previous" });
    const next = pagination.getByRole("button", { name: "Next" });

    await expect(pagination).toContainText(`Showing 1${EN_DASH}25 of ${all.total}`);
    await expect(previous).toBeDisabled();
    await expect(next).toBeEnabled();

    await next.click();
    await expectAddress(page, "/indicators?page=2");
    await expect(pagination).toContainText(`Showing 26${EN_DASH}50 of ${all.total}`);
    expect(await shownValues(page)).toEqual(valuesOf((await fetchIndicators(request, { offset: 25 })).items));
    await expect(previous).toBeEnabled();

    await previous.click();
    await expectAddress(page, "/indicators");
    await expectFound(page, all.total);
    expect(await shownValues(page)).toEqual(valuesOf(all.items));

    await openList(page, `?page=${pages}`);
    const last = await fetchIndicators(request, { offset: (pages - 1) * 25 });
    await expect(pagination).toContainText(`Showing ${(pages - 1) * 25 + 1}${EN_DASH}${all.total} of ${all.total}`);
    await expect(next).toBeDisabled();
    await expect(previous).toBeEnabled();
    expect(await shownValues(page)).toEqual(valuesOf(last.items));
    await expect(page.locator("tbody tr")).toHaveCount(all.total - (pages - 1) * 25);
  });

  test("a page past the end says so, and the first page is one click away", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    const beyond = Math.ceil(all.total / 25) + 1;
    await openList(page, `?page=${beyond}`);

    await expect(page.getByText("This page has no results.")).toBeVisible();
    await expectFound(page, all.total);
    await page.getByRole("button", { name: "Go to the first page" }).click();
    await expectAddress(page, "/indicators");
    expect(await shownValues(page)).toEqual(valuesOf(all.items));
  });

  test("a page number beyond what the API serves still ends in the same message", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    const asked = listRequest(page, (query) => query.get("offset") === "10000");
    await openList(page, "?page=999999");
    await asked;
    await expect(page.getByText("This page has no results.")).toBeVisible();
    await expectFound(page, all.total);
  });

  test("a page number that is not a whole number from 1 upwards means the first page", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    for (const bad of ["abc", "0", "-3", "2.5", ""]) {
      const asked = listRequest(page, (query) => query.get("offset") === "0");
      await openList(page, `?page=${bad}`);
      await asked;
      await expectFound(page, all.total);
      expect(await shownValues(page), `page=${bad}`).toEqual(valuesOf(all.items));
    }
  });
});

test.describe("the address bar", () => {
  test("holds every filter, so a link or a reload brings the same list back", async ({ page, request }) => {
    const sample = must(
      (await fetchIndicators(request, { type: "ipv6", classification: ["high", "critical"], assessed: "true", limit: 1 })).items[0],
      "a high-risk IPv6 indicator",
    );
    const part = sample.indicator_value.slice(-3);
    const stored = await fetchIndicators(request, {
      q: part,
      type: "ipv6",
      classification: ["high", "critical"],
      assessed: "true",
      sort: "risk",
    });
    const address = `?${filterQuery(part)}`;

    for (const reload of [false, true]) {
      if (reload) await page.reload();
      else await openList(page, address);
      await expectFound(page, stored.total);
      const { search, type, classification, sort } = listFilters(page);
      await expect(search).toHaveValue(part);
      await expect(type.locator("option:checked")).toHaveText("IPv6");
      await expect(classification.locator("option:checked")).toHaveText("High or critical");
      await expect(sort.locator("option:checked")).toHaveText("Highest risk first");
      expect(await shownValues(page)).toEqual(valuesOf(stored.items));
    }
  });

  test("anything it cannot read falls back to the defaults without an error", async ({ page, request }) => {
    const all = await fetchIndicators(request);
    const asked = listRequest(page, (query) => !query.has("type") && !query.has("classification") && !query.has("assessed") && query.get("sort") === "recent");
    await openList(page, "?type=nope&classification=nope&sort=nope&page=zero&unrelated=1");
    await asked;
    await expectFound(page, all.total);

    const { type, classification, sort } = listFilters(page);
    await expect(type).toHaveValue("");
    await expect(classification).toHaveValue("");
    await expect(sort).toHaveValue("recent");
    await expect(page.getByRole("alert")).toHaveCount(0);
  });

  test("a search longer than the API allows is cut to 256 characters", async ({ page }) => {
    const asked = listRequest(page, (query) => query.get("q") === "b".repeat(256));
    await openList(page, `?q=${"b".repeat(300)}`);
    await asked;
    await expect(listFilters(page).search).toHaveValue("b".repeat(256));
  });

  test("Back and Forward step through earlier choices", async ({ page, request }) => {
    const [ipv4, domain] = await Promise.all([fetchIndicators(request, { type: "ipv4" }), fetchIndicators(request, { type: "domain" })]);
    await openList(page);
    const { type } = listFilters(page);

    await type.selectOption({ label: "IPv4" });
    await expectFound(page, ipv4.total);
    await type.selectOption({ label: "Domain" });
    await expectFound(page, domain.total);

    await page.goBack();
    await expectFound(page, ipv4.total);
    await expect(type).toHaveValue("ipv4");
    await page.goBack();
    await expectAddress(page, "/indicators");
    await expect(type).toHaveValue("");
    await page.goForward();
    await expectFound(page, ipv4.total);
    await expect(type).toHaveValue("ipv4");
  });
});

test.describe("when the list cannot be shown normally", () => {
  test("a failing API says what went wrong, and Try again brings the list back", async ({ page, request, guard }) => {
    const all = await fetchIndicators(request);
    guard.expectStatus(500);
    let failing = true;
    await page.route(LIST, (route) =>
      failing
        ? route.fulfill({
            status: 500,
            json: { error: { code: "internal_error", message: "The service is having a problem.", correlation_id: "e2e-ref-500" } },
          })
        : route.continue(),
    );
    await openList(page);

    const notice = page.getByRole("alert").filter({ hasText: "The API reported an error" });
    await expect(notice).toContainText("The service is having a problem.");
    await expect(notice).toContainText("Reference: e2e-ref-500");
    await expect(page.getByRole("table")).toHaveCount(0);

    failing = false;
    await notice.getByRole("button", { name: "Try again" }).click();
    await expectFound(page, all.total);
    await expect(notice).toHaveCount(0);
  });

  test("an unreachable API is reported as such", async ({ page, guard }) => {
    guard.expectRequestFailure(LIST);
    await page.route(LIST, (route) => route.abort("failed"));
    await openList(page);
    await expect(page.getByRole("alert").filter({ hasText: "Could not reach the API" })).toBeVisible();
  });

  test("an API that answers with something unexpected is reported, not displayed", async ({ page }) => {
    await page.route(LIST, (route) => route.fulfill({ status: 200, json: { items: "nope" } }));
    await openList(page);
    await expect(page.getByRole("alert").filter({ hasText: "Unexpected response from the API" })).toBeVisible();
    await expect(page.getByRole("table")).toHaveCount(0);
  });

  test("shows that it is loading while it waits", async ({ page }) => {
    await page.route(LIST, async (route) => {
      await pause(1_000);
      await route.continue().catch(() => undefined);
    });
    await openList(page);
    await expect(page.getByText("Loading indicators…")).toBeVisible();
    await expect(page.getByText("Loading indicators…")).toBeHidden();
    await expect(page.getByRole("table")).toBeVisible();
  });

  test("an empty database invites the first investigation", async ({ page }) => {
    await page.route(LIST, (route) => route.fulfill({ status: 200, json: { items: [], total: 0, limit: 25, offset: 0 } }));
    await openList(page);
    await expectFound(page, 0);
    await expect(page.getByText("No indicators have been investigated yet.")).toBeVisible();
    await expect(listFilters(page).reset).toHaveCount(0);

    await page.getByRole("link", { name: "Investigate one now" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator" })).toBeVisible();
  });
});

test.describe("opening a record", () => {
  test("a row opens its record; Back returns to the same list and the back link to the whole list", async ({ page, request }) => {
    const domains = await fetchIndicators(request, { type: "domain", sort: "risk" });
    const all = await fetchIndicators(request);
    const target = must(domains.items[0], "a domain");

    await openList(page, "?type=domain&sort=risk");
    await expectFound(page, domains.total);
    await page.getByRole("link", { name: target.indicator_value, exact: true }).click();
    await expectAddress(page, `/indicators/${target.indicator_id}`);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
    await expect(panel(page, "CipherForge assessment")).toContainText(target.indicator_value);

    await page.goBack();
    await expectAddress(page, "/indicators?type=domain&sort=risk");
    await expectFound(page, domains.total);
    await expect(listFilters(page).type).toHaveValue("domain");
    await expect(listFilters(page).sort).toHaveValue("risk");

    await page.getByRole("link", { name: target.indicator_value, exact: true }).click();
    await page.getByRole("link", { name: "All indicators" }).click();
    await expectAddress(page, "/indicators");
    await expectFound(page, all.total);
  });
});

test.describe("a record", () => {
  // Numbers appear at once instead of counting up, so the page can be compared with the API.
  test.use({ reducedMotion: "reduce" });

  test("shows the stored dossier without asking any provider", async ({ page, request }) => {
    const record = await firstIndicator(request, { classification: "critical" });
    const detail = await fetchIndicator(request, record.indicator_id);
    const lookups = countRequests(page, INVESTIGATE);
    const reads = countRequests(page, DETAIL);

    await page.goto(`/indicators/${record.indicator_id}`);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
    await expect(page).toHaveTitle(`Indicator ${record.indicator_value.slice(0, 60)} \u00b7 CipherForge`);

    await expectDossier(page, detail);
    await expect(panel(page, "CipherForge assessment")).toContainText(
      record.status === "active"
        ? "Active. At least one provider answer is still fresh."
        : "Stale. No provider answer is fresh; investigate again to refresh.",
    );
    await expect(
      panel(page, "How the score was built").getByText("How scores are calculated (intel-risk-v1)"),
    ).toBeVisible();
    await expect(panel(page, "Internal evidence")).toBeVisible();

    expect(reads.count, "the record is read once").toBe(1);
    expect(lookups.count, "opening a record must not ask any provider").toBe(0);
  });

  test("a record no provider answered for says it was not assessed", async ({ page, request }) => {
    const record = must((await fetchIndicators(request, { assessed: "false", limit: 1 })).items[0], "an unanswered indicator");
    await page.goto(`/indicators/${record.indicator_id}`);

    const verdict = panel(page, "CipherForge assessment");
    await expect(verdict).toContainText("Not assessed");
    await expect(verdict).toContainText("No provider answered, so CipherForge has no evidence about this indicator.");
    await expect(verdict).toContainText("This is not a clean result");
    await expect(verdict).not.toContainText("Informational");
    await expect(panel(page, "How the score was built")).toContainText("No provider answered, so there is no score to break down.");
  });

  test("Re-check asks the providers again, shows it is working, and updates the record", async ({ page, request }) => {
    const created = await investigateViaApi(request, fresh.domain());
    const value = created.indicator.indicator_value;
    await page.route(INVESTIGATE, async (route) => {
      await pause(1_500);
      await route.continue().catch(() => undefined);
    });
    await page.goto(`/indicators/${created.indicator.indicator_id}`);
    await expect(panel(page, "CipherForge assessment")).toContainText(value);

    const sent = page.waitForRequest((candidate) => candidate.method() === "POST" && INVESTIGATE.test(candidate.url()));
    await page.getByRole("button", { name: "Re-check with providers" }).click();
    expect((await sent).postDataJSON()).toEqual({ indicator: value, refresh: true });

    await expect(page.getByRole("button", { name: "Re-checking…" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Re-checking…" }), "the button keeps the focus while it works").toBeFocused();
    await expect(page.getByRole("status").filter({ hasText: "Re-checking with the providers." })).toBeAttached();
    await expect(page.getByRole("status").filter({ hasText: "Re-check complete. The record was updated." })).toBeAttached();
    await expect(page.getByRole("button", { name: "Re-check with providers" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Re-check with providers" })).toBeFocused();

    const after = await storedIndicator(request, value);
    expect(Date.parse(must(after.last_checked_at))).toBeGreaterThan(Date.parse(must(created.indicator.last_checked_at)));
    await expect(panel(page, "CipherForge assessment")).toContainText(CLASSIFICATION_LABELS[after.classification]);
  });

  test("a failed re-check explains why and leaves the stored record on screen", async ({ page, request, guard }) => {
    const created = await investigateViaApi(request, fresh.domain());
    guard.expectStatus(503);
    await page.route(INVESTIGATE, (route) =>
      route.fulfill({
        status: 503,
        json: { error: { code: "unavailable", message: "The providers are not reachable.", correlation_id: "e2e-ref-503" } },
      }),
    );
    await page.goto(`/indicators/${created.indicator.indicator_id}`);
    await page.getByRole("button", { name: "Re-check with providers" }).click();

    const notice = page.getByRole("alert").filter({ hasText: "The API reported an error" });
    await expect(notice).toContainText("The providers are not reachable.");
    await expect(notice).toContainText("Reference: e2e-ref-503");
    await expect(panel(page, "CipherForge assessment")).toContainText(created.indicator.indicator_value);
    await expect(page.getByRole("button", { name: "Re-check with providers" })).toBeEnabled();
  });

  test("shows that it is loading while the record is fetched", async ({ page, request }) => {
    const record = await firstIndicator(request);
    await page.route(DETAIL, async (route) => {
      await pause(1_000);
      await route.continue().catch(() => undefined);
    });
    await page.goto(`/indicators/${record.indicator_id}`);
    await expect(page.getByText("Loading the stored record…")).toBeVisible();
    await expect(page.getByRole("button", { name: "Re-check with providers" })).toHaveCount(0);
    await expect(panel(page, "CipherForge assessment")).toBeVisible();
    await expect(page.getByText("Loading the stored record…")).toBeHidden();
  });

  test("an ID that is not an ID never reaches the API", async ({ page }) => {
    const reads = countRequests(page, DETAIL);
    await page.goto("/indicators/not-a-valid-id");
    await expect(page.getByRole("heading", { level: 1, name: "Indicator not found" })).toBeVisible();
    await expect(page.getByText("That is not a valid indicator ID. Open an indicator from the list instead.")).toBeVisible();
    await expect(page).toHaveTitle(/^Indicator not found \u00b7 CipherForge$/);
    expect(reads.count).toBe(0);

    await page.getByRole("link", { name: "All indicators" }).click();
    await expectAddress(page, "/indicators");
  });

  test("an ID nobody holds is reported as not found", async ({ page, guard }) => {
    guard.expectStatus(404);
    await page.goto(`/indicators/${NO_SUCH_ID}`);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator not found" })).toBeVisible();
    await expect(
      page.getByText("No stored indicator has this ID. It may have been removed, or the link may be wrong."),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: /Re-check/ })).toHaveCount(0);
  });

  test("an ID written with markup or path tricks is only ever text", async ({ page }) => {
    const reads = countRequests(page, DETAIL);
    await page.goto(`/indicators/${encodeURIComponent('<img src=x onerror="alert(1)">')}`);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator not found" })).toBeVisible();
    await page.goto(`/indicators/${encodeURIComponent("../../status")}`);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator not found" })).toBeVisible();
    expect(reads.count).toBe(0);
    await expect(page.locator("img[src='x']")).toHaveCount(0);
  });
});

test("a value typed into the search box appears in the address, not in the page markup", async ({ page }) => {
  const payload = '"><img src=x onerror=alert(1)>';
  await openList(page);
  const { search } = listFilters(page);
  await search.fill(payload);
  await search.press("Enter");
  await expectAddress(page, `/indicators?${new URLSearchParams({ q: payload }).toString()}`);
  await expect(page.getByText("No indicators match these filters.")).toBeVisible();
  await expect(search).toHaveValue(payload);
  await expect(page.locator("img[src='x']")).toHaveCount(0);
});
