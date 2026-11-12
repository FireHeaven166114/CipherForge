import type { Page, Request } from "@playwright/test";

import { firstIndicator, fetchIndicators, fresh } from "./api";
import { expect, test } from "./fixtures";
import { openOverview } from "./open";
import { expectFound, listFilters, palette } from "./pages";

// Motion on, so the effects switch can be used.
test.use({ reducedMotion: "no-preference" });

const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;

/** Everything the page has kept in the browser, apart from what it holds in memory. */
async function keptInBrowser(page: Page): Promise<{
  local: Record<string, string>;
  session: Record<string, string>;
  cookie: string;
  databases: string[];
  caches: string[];
  workers: number;
}> {
  return page.evaluate(async () => {
    const entries = (store: Storage): Record<string, string> =>
      Object.fromEntries(Array.from({ length: store.length }, (_, index) => store.key(index) ?? "").map((key) => [key, store.getItem(key) ?? ""]));
    return {
      local: entries(localStorage),
      session: entries(sessionStorage),
      cookie: document.cookie,
      databases: (await indexedDB.databases()).map((database) => database.name ?? ""),
      caches: await caches.keys(),
      workers: (await navigator.serviceWorker.getRegistrations()).length,
    };
  });
}

async function goTo(page: Page, letter: string): Promise<void> {
  await page.keyboard.press("g");
  await page.keyboard.press(letter);
}

test("using the console keeps nothing in the browser and sends nothing anywhere but its own server", async ({
  page,
  context,
  request,
}) => {
  const requests: Request[] = [];
  page.on("request", (sent) => {
    if (/^https?:/.test(sent.url())) requests.push(sent);
  });
  const stored = await firstIndicator(request, { sort: "risk" });
  const value = fresh.domain();

  // Overview, a details drawer, a record opened from it.
  await openOverview(page);
  await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toBeVisible();
  await drawer.locator("a[href^='/indicators/']").first().click();
  await expect(page).toHaveURL(/\/indicators\/[^/]+$/);
  await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();

  // The list, with a search, and the status page.
  await goTo(page, "l");
  const { search, searchButton } = listFilters(page);
  await search.fill(stored.indicator_value);
  await searchButton.click();
  await expectFound(page, (await fetchIndicators(request, { q: stored.indicator_value })).total);
  await page.getByRole("heading", { level: 1, name: "Indicators", exact: true }).click();
  await goTo(page, "s");
  await expect(page.getByText("Operational", { exact: true })).toBeVisible();

  // Nothing has been kept so far: not even a preference, because none was set.
  expect(await keptInBrowser(page), "after reading").toEqual({
    local: {},
    session: {},
    cookie: "",
    databases: [],
    caches: [],
    workers: 0,
  });

  // The one thing that is kept, once a person chooses it: the effects switch.
  await page.keyboard.press("Control+k");
  await palette(page).box.fill("effects");
  await palette(page).options.filter({ hasText: "Turn visual effects off" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-effects", "off");

  // A real investigation. The value travels in the body of a POST, never in an address.
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Investigate" }).click();
  await page.getByRole("textbox", { name: /^Indicator/ }).fill(value);
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await expect(page.getByText("This result is saved. You can return to it from the Indicators page.")).toBeVisible();

  expect(await keptInBrowser(page), "after choosing a preference and investigating").toEqual({
    local: { "cipherforge.effects": "off" },
    session: {},
    cookie: "",
    databases: [],
    caches: [],
    workers: 0,
  });
  expect(await context.cookies(), "cookies in the browser").toEqual([]);

  // Every request went to the console's own origin, with no cookie and no referrer.
  const origin = new URL(page.url()).origin;
  const headers = await Promise.all(requests.map(async (sent) => ({ url: sent.url(), headers: await sent.allHeaders() })));
  expect(requests.length, "requests seen").toBeGreaterThan(10);
  expect(headers.filter((sent) => new URL(sent.url).origin !== origin).map((sent) => sent.url), "requests to another origin").toEqual([]);
  expect(headers.filter((sent) => "cookie" in sent.headers).map((sent) => sent.url), "requests that carried a cookie").toEqual([]);
  expect(headers.filter((sent) => "referer" in sent.headers).map((sent) => sent.url), "requests that carried a referrer").toEqual([]);

  // The investigated value was sent once, in a body, and is in no address.
  const lookups = requests.filter((sent) => sent.method() === "POST" && INVESTIGATE.test(sent.url()));
  expect(lookups).toHaveLength(1);
  expect(lookups[0]?.postDataJSON()).toEqual({ indicator: value, refresh: false });
  expect(requests.filter((sent) => sent.url().includes(value) || sent.url().includes(encodeURIComponent(value))), "addresses holding the value").toEqual([]);
});
