import type { Locator, Page, Route } from "@playwright/test";

import { countRequests } from "./api";
import { expect, test } from "./fixtures";
import { panel, pause } from "./pages";
import { istClockSeconds, must } from "./text";

const HEALTH = /\/health$/;
const READY = /\/ready$/;
const CHECKS = /\/(?:health|ready)$/;
const UNREADABLE = "The API returned a response this app cannot read.";
const UNREACHABLE = "Could not reach the CipherForge API.";

const OVERALL = {
  Checking: { detail: "Contacting the API\u2026", beacon: "CHECKING" },
  Operational: { detail: "The API is up and its database is reachable.", beacon: "API ONLINE" },
  Degraded: { detail: "The API is up, but a dependency is not healthy.", beacon: "API DEGRADED" },
  Down: { detail: "The API cannot be reached.", beacon: "API OFFLINE" },
} as const;

type Overall = keyof typeof OVERALL;

type Reply = "live" | "refuse" | "hang" | { status: number; json?: unknown; html?: string };

const NOT_READY: Reply = { status: 503, json: { status: "not_ready", checks: { database: "unavailable" } } };

function fault(status: number, message: string): Reply {
  return { status, json: { error: { code: "e2e_failure", message, correlation_id: `e2e-ref-${status}` } } };
}

interface Script {
  health: Reply;
  ready: Reply;
}

/** Lets a test decide, and change, what each health check gets back. */
async function script(page: Page, initial: Partial<Script> = {}): Promise<Script> {
  const replies: Script = { health: "live", ready: "live", ...initial };
  const answer =
    (which: keyof Script) =>
    async (route: Route): Promise<void> => {
      const reply = replies[which];
      if (reply === "live") {
        await route.continue().catch(() => undefined);
      } else if (reply === "refuse") {
        await route.abort("connectionrefused").catch(() => undefined);
      } else if (reply === "hang") {
        // Never answered: the page has to give up on its own.
      } else if (reply.html !== undefined) {
        await route.fulfill({ status: reply.status, contentType: "text/html", body: reply.html });
      } else {
        await route.fulfill({ status: reply.status, json: reply.json });
      }
    };
  await page.route(HEALTH, answer("health"));
  await page.route(READY, answer("ready"));
  return replies;
}

/** Holds every matching request until the test lets it go; the earlier routes then answer it. */
async function hold(page: Page, pattern: RegExp): Promise<{ release: () => void }> {
  let release: () => void = () => undefined;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(pattern, async (route) => {
    await released;
    await route.fallback().catch(() => undefined);
  });
  return { release };
}

interface StatusView {
  overall: Locator;
  detail: Locator;
  refresh: Locator;
  checked: Locator;
  api: Locator;
  database: Locator;
  beacon: Locator;
}

function statusView(page: Page): StatusView {
  const main = page.getByRole("main");
  return {
    overall: main.getByText("Overall status", { exact: true }).locator("xpath=following-sibling::p[1]"),
    detail: main.locator("p[aria-live='polite']"),
    refresh: main.getByRole("button", { name: /^(?:Refresh|Checking\u2026)$/ }),
    checked: main.getByText(/This page refreshes automatically every 30 seconds\.$/),
    api: panel(page, "API"),
    database: panel(page, "Database"),
    beacon: beacon(page),
  };
}

/** The API light in the top bar, which every page carries. */
function beacon(page: Page): Locator {
  return page.getByRole("banner").getByRole("link", { name: /^(?:CHECKING|API ONLINE|API DEGRADED|API OFFLINE)$/ });
}

async function openStatus(page: Page): Promise<StatusView> {
  await page.goto("/status");
  await expect(page.getByRole("heading", { level: 1, name: "System status", exact: true })).toBeVisible();
  return statusView(page);
}

interface Cards {
  api: "Up" | "Unreachable" | "Checking";
  database: "Reachable" | "Unavailable" | "Unknown" | "Checking";
}

/** The page and the top bar tell the same story, in words. */
async function expectState(view: StatusView, overall: Overall, cards: Cards): Promise<void> {
  await expect(view.overall).toHaveText(overall);
  await expect(view.detail).toHaveText(OVERALL[overall].detail);
  await expect(view.api.locator("header")).toHaveText(new RegExp(`${cards.api}$`));
  await expect(view.database.locator("header")).toHaveText(new RegExp(`${cards.database}$`));
  await expect(view.beacon).toHaveText(OVERALL[overall].beacon);
}

/** Seconds past midnight IST in "Last checked hh:mm:ss AM IST". */
async function checkedAt(checked: Locator): Promise<number> {
  const text = must(await checked.textContent());
  return istClockSeconds(must(/Last checked (\d{2}:\d{2}:\d{2} (?:AM|PM) IST)/.exec(text))[1] ?? "");
}

function secondsBetween(earlier: number, later: number): number {
  return (later - earlier + 86_400) % 86_400;
}

test.describe("a healthy API", () => {
  test("is Operational, and says what the API reports about itself", async ({ page, request }) => {
    const health = (await (await request.get("/health")).json()) as { status: string; service: string; version: string };
    const ready = (await (await request.get("/ready")).json()) as unknown;
    expect(health.status).toBe("ok");
    expect(ready).toEqual({ status: "ready", checks: { database: "ok" } });

    await page.clock.setFixedTime(new Date("2031-03-04T05:06:07Z"));
    const view = await openStatus(page);

    await expect(page).toHaveTitle("System status \u00b7 CipherForge");
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
    await expect(view.refresh).toBeEnabled();
    await expect(view.checked).toHaveText("Last checked 10:36:07 AM IST. This page refreshes automatically every 30 seconds.");
    await expect(view.api.getByRole("term")).toHaveText(["Service", "Version"]);
    await expect(view.api.getByRole("definition")).toHaveText([health.service, health.version]);
    await expect(view.database).toContainText("The API can run queries against the database.");
    await expect(view.beacon).toHaveAttribute("href", "/status");
  });

  test("says it is checking, and offers no refresh, until the first answers arrive", async ({ page }) => {
    const gate = await hold(page, CHECKS);
    const view = await openStatus(page);

    await expectState(view, "Checking", { api: "Checking", database: "Checking" });
    await expect(view.api).toContainText("Waiting for a response\u2026");
    await expect(view.database).toContainText("Waiting for a response\u2026");
    await expect(view.checked).toHaveText("Not checked yet. This page refreshes automatically every 30 seconds.");
    await expect(view.refresh).toHaveText("Checking\u2026");
    await expect(view.refresh).toBeDisabled();

    gate.release();
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
    await expect(view.refresh).toHaveText("Refresh");
    await expect(view.refresh).toBeEnabled();
    await expect(view.checked).toContainText(/^Last checked \d{2}:\d{2}:\d{2} (AM|PM) IST\./);
  });

  test("Refresh asks again, says it is working and moves the time on", async ({ page }) => {
    await page.clock.setFixedTime(new Date("2031-03-04T05:06:07Z"));
    const health = countRequests(page, HEALTH);
    const ready = countRequests(page, READY);
    const view = await openStatus(page);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
    await expect(view.checked).toContainText("Last checked 10:36:07 AM IST.");

    const before = { health: health.count, ready: ready.count };
    const gate = await hold(page, CHECKS);
    await page.clock.setFixedTime(new Date("2031-03-04T05:07:09Z"));
    await view.refresh.click();

    await expect(view.refresh).toHaveText("Checking\u2026");
    await expect(view.refresh).toBeDisabled();
    // The last answer stays up while the next one is awaited, instead of flickering to "Checking".
    await expect(view.overall).toHaveText("Operational");
    await expect.poll(() => health.count).toBe(before.health + 1);
    await expect.poll(() => ready.count).toBe(before.ready + 1);

    gate.release();
    await expect(view.refresh).toHaveText("Refresh");
    await expect(view.refresh).toBeEnabled();
    await expect(view.checked).toContainText("Last checked 10:37:09 AM IST.");
    expect(health.count).toBe(before.health + 1);
    expect(ready.count).toBe(before.ready + 1);
  });

  test("Refresh works from the keyboard, and the keyboard stays on it", async ({ page }) => {
    const view = await openStatus(page);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });

    const gate = await hold(page, CHECKS);
    await view.refresh.focus();
    await page.keyboard.press("Enter");
    await expect(view.refresh).toHaveText("Checking\u2026");
    await expect(view.refresh).toBeFocused();

    gate.release();
    await expect(view.refresh).toHaveText("Refresh");
    await expect(view.refresh).toBeFocused();
    await page.keyboard.press("Space");
    await expect(view.refresh).toBeEnabled();
  });

  test("asks again by itself every 30 seconds", async ({ page }) => {
    await page.clock.install();
    const health = countRequests(page, HEALTH);
    const ready = countRequests(page, READY);
    const view = await openStatus(page);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
    const first = await checkedAt(view.checked);
    const before = { health: health.count, ready: ready.count };

    await page.clock.runFor(20_000);
    await pause(500);
    expect(health.count, "nothing is asked before the 30 seconds are up").toBe(before.health);
    expect(ready.count).toBe(before.ready);
    expect(await checkedAt(view.checked)).toBe(first);

    await page.clock.runFor(15_000);
    await expect.poll(() => health.count).toBeGreaterThan(before.health);
    await expect.poll(() => ready.count).toBeGreaterThan(before.ready);
    await expect.poll(async () => secondsBetween(first, await checkedAt(view.checked))).toBeGreaterThanOrEqual(30);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
  });

  test("leaving the page while a check is running does no harm", async ({ page }) => {
    const gate = await hold(page, CHECKS);
    const view = await openStatus(page);
    await expect(view.overall).toHaveText("Checking");

    await page.keyboard.press("g");
    await page.keyboard.press("o");
    await expect(page.getByRole("heading", { level: 1, name: "Overview", exact: true })).toBeVisible();

    gate.release();
    await expect(beacon(page)).toHaveText("API ONLINE");
    await expect(page.getByRole("heading", { level: 1, name: "Overview", exact: true })).toBeVisible();
  });
});

test.describe("the top bar", () => {
  test("reports the API on every page, and leads to the status page", async ({ page, guard }) => {
    guard.expectRequestFailure(HEALTH);
    const replies = await script(page);

    for (const path of ["/", "/investigate", "/indicators"]) {
      await page.goto(path);
      await expect(beacon(page)).toHaveText("API ONLINE");
    }

    replies.health = "refuse";
    for (const path of ["/", "/investigate", "/indicators"]) {
      await page.goto(path);
      await expect(beacon(page)).toHaveText("API OFFLINE");
      await expect(beacon(page)).toHaveAccessibleDescription("Open system status");
    }

    await beacon(page).click();
    const view = statusView(page);
    await expect(page.getByRole("heading", { level: 1, name: "System status", exact: true })).toBeVisible();
    await expectState(view, "Down", { api: "Unreachable", database: "Reachable" });
  });
});

test.describe("when something is wrong", () => {
  test("Degraded: the API is up and its database is not", async ({ page, guard }) => {
    // A 503 with a readable body is the API's way of saying "not ready", so it is data, not a failure.
    guard.expectStatus(503);
    await script(page, { ready: NOT_READY });
    const view = await openStatus(page);

    await expectState(view, "Degraded", { api: "Up", database: "Unavailable" });
    await expect(view.database).toContainText("The API is running but cannot reach the database.");
    await expect(view.api).toContainText("cipherforge-api");
  });

  test("Degraded: an unreadable readiness answer is reported on the Database card, with its reference", async ({
    page,
    guard,
  }) => {
    guard.expectStatus(500);
    await script(page, { ready: fault(500, "The readiness check failed.") });
    const view = await openStatus(page);

    await expectState(view, "Degraded", { api: "Up", database: "Unknown" });
    await expect(view.database).toContainText("The readiness check failed.");
    await expect(view.database).toContainText("Reference: e2e-ref-500");
  });

  test("Degraded: a readiness answer that is not a readiness report is not trusted", async ({ page }) => {
    await script(page, { ready: { status: 200, json: { status: "fine", checks: { database: "ok" } } } });
    const view = await openStatus(page);

    await expectState(view, "Degraded", { api: "Up", database: "Unknown" });
    await expect(view.database).toContainText(UNREADABLE);
  });

  test("Down: nothing answers", async ({ page, guard }) => {
    guard.expectRequestFailure(CHECKS);
    await script(page, { health: "refuse", ready: "refuse" });
    const view = await openStatus(page);

    await expectState(view, "Down", { api: "Unreachable", database: "Unknown" });
    await expect(view.api).toContainText(UNREACHABLE);
    await expect(view.database).toContainText(UNREACHABLE);
    // A failed check is still a check, and can be repeated.
    await expect(view.checked).toContainText(/^Last checked \d{2}:\d{2}:\d{2} (AM|PM) IST\./);
    await expect(view.refresh).toBeEnabled();
  });

  test("Down: a gateway error page is reported without showing what it said", async ({ page, guard }) => {
    guard.expectStatus(502);
    const html = "<html><body><h1>502 Bad Gateway</h1>upstream secret-host-7 refused the connection</body></html>";
    await script(page, { health: { status: 502, html }, ready: { status: 502, html } });
    const view = await openStatus(page);

    await expectState(view, "Down", { api: "Unreachable", database: "Unknown" });
    await expect(view.api).toContainText("The API responded with HTTP 502.");
    await expect(view.database).toContainText("The API responded with HTTP 502.");
    await expect(page.getByRole("main")).not.toContainText("secret-host-7");
  });

  test("Down: an answer that is not a health report", async ({ page }) => {
    await script(page, { health: { status: 200, json: { status: "ok" } } });
    const view = await openStatus(page);

    await expectState(view, "Down", { api: "Unreachable", database: "Reachable" });
    await expect(view.api).toContainText(UNREADABLE);
  });

  test("Down: an API that never answers is given 10 seconds, and is Checking until then", async ({ page }) => {
    test.setTimeout(60_000);
    await script(page, { health: "hang" });
    const view = await openStatus(page);

    await expect(view.overall).toHaveText("Checking");
    await expect(view.refresh).toBeDisabled();

    await expect(view.overall).toHaveText("Down", { timeout: 20_000 });
    await expectState(view, "Down", { api: "Unreachable", database: "Reachable" });
    await expect(view.api).toContainText("The request timed out.");
    await expect(view.refresh).toBeEnabled();
  });
});

test.describe("recovering", () => {
  test("Refresh brings a Down API back, and the top bar follows", async ({ page, guard }) => {
    guard.expectRequestFailure(CHECKS);
    const replies = await script(page, { health: "refuse", ready: "refuse" });
    const view = await openStatus(page);
    await expectState(view, "Down", { api: "Unreachable", database: "Unknown" });

    replies.health = "live";
    replies.ready = "live";
    await view.refresh.click();

    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
    await expect(view.refresh).toHaveText("Refresh");
  });

  test("Refresh shows a database that has gone away, and one that has come back", async ({ page, guard }) => {
    guard.expectStatus(503);
    const replies = await script(page);
    const view = await openStatus(page);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });

    replies.ready = NOT_READY;
    await view.refresh.click();
    await expectState(view, "Degraded", { api: "Up", database: "Unavailable" });

    replies.ready = "live";
    await view.refresh.click();
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
  });

  test("notices an outage and the recovery by itself, without Refresh being pressed", async ({ page, guard }) => {
    guard.expectRequestFailure(CHECKS);
    await page.clock.install();
    const replies = await script(page);
    const view = await openStatus(page);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });

    replies.health = "refuse";
    replies.ready = "refuse";
    await page.clock.runFor(35_000);
    await expectState(view, "Down", { api: "Unreachable", database: "Unknown" });

    replies.health = "live";
    replies.ready = "live";
    await page.clock.runFor(35_000);
    await expectState(view, "Operational", { api: "Up", database: "Reachable" });
  });
});
