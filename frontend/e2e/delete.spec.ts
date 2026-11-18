import type { Locator, Page, Response } from "@playwright/test";

import type { DeleteResult } from "../src/types/intel";
import { countOf, countRequests, deleteViaApi, fetchIndicators, fetchOverview, investigateViaApi, uniqueSuffix } from "./api";
import { expect, test } from "./fixtures";
import { expectInert, watchDialogs } from "./hostile";
import { openList, openOverview, openRecord } from "./open";
import { expectFound, panel, pause } from "./pages";
import { must } from "./text";

/**
 * Deleting what has been investigated: one indicator at a time, a run of them, or a whole page.
 * Every test seeds the indicators it deletes (see the `seed` fixture), so the demo data the other
 * specs read is never touched, and says what it expects of the API as well as of the page.
 */
test.use({ reducedMotion: "reduce" });

const API = "/api/v1/intel";
const ONE = /\/api\/v1\/intel\/indicators\/[^/?]+$/;
const BULK = /\/api\/v1\/intel\/indicators\/bulk-delete$/;
const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;

const SELECT_ALL = "Select all indicators on this page";
const HINT = "Tick rows to delete them. Hold Shift to tick a range.";
const PERMANENT = "This permanently removes it, and every provider answer stored for it, from the database. It cannot be undone.";
const AUDIT_NOTE = "The audit log is kept as it is: it still records the past lookups and gains a record of this deletion.";

/** The tick box in the row of this indicator. */
function tick(page: Page, value: string): Locator {
  return page.getByRole("checkbox", { name: `Select ${value}`, exact: true });
}

/** The delete button in the row of this indicator. */
function trash(page: Page, value: string): Locator {
  return page.getByRole("button", { name: `Delete ${value}`, exact: true });
}

function confirmation(page: Page, title: string): Locator {
  return page.getByRole("dialog", { name: title, exact: true });
}

/** The line that says what a deletion did. It exists only after one. */
function notice(page: Page, text: string): Locator {
  return page.getByRole("status").filter({ hasText: text });
}

/** The indicators the list shows, top to bottom. */
function shownValues(page: Page): Promise<string[]> {
  return page.locator("tbody th a").allTextContents();
}

function ticked(page: Page): Locator {
  return page.getByRole("checkbox", { checked: true });
}

/** The sentence the page shows afterwards, written out from what the API said it had done. */
function summary(result: DeleteResult): string {
  const gone = result.not_found.length;
  const already = gone === 0 ? "" : ` ${countOf(gone, "indicator")} ${gone === 1 ? "was" : "were"} already gone.`;
  if (result.deleted.length === 0) return `Nothing was deleted.${already}`;
  return `Deleted ${countOf(result.deleted.length, "indicator")} and ${countOf(result.observations_removed, "stored provider answer")}.${already}`;
}

/** Resolves with the API's answer to the next deletion of a single indicator. */
function answerToDelete(page: Page): Promise<Response> {
  return page.waitForResponse((response) => response.request().method() === "DELETE" && ONE.test(response.url()));
}

/** Resolves with the API's answer to the next deletion of several indicators. */
function answerToBulk(page: Page): Promise<Response> {
  return page.waitForResponse((response) => response.request().method() === "POST" && BULK.test(response.url()));
}

async function resultOf(answer: Promise<Response>): Promise<DeleteResult> {
  return (await (await answer).json()) as DeleteResult;
}

function recordUrl(id: string): string {
  return `${API}/indicators/${id}`;
}

test.describe("deleting from the list", () => {
  test("one indicator: asks first, then it is gone from the list, the API and a new search", async ({ page, request, seed }) => {
    const { search, items } = await seed(3);
    const target = must(items[1], "an indicator to delete");
    const kept = items.filter((item) => item.indicator_id !== target.indicator_id);
    await openList(page, `?q=${search}`);
    await expectFound(page, 3);
    const lookups = countRequests(page, INVESTIGATE);

    await trash(page, target.indicator_value).click();
    const dialog = confirmation(page, "Delete this indicator?");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("listitem")).toHaveText([target.indicator_value]);
    await expect(dialog).toContainText(PERMANENT);
    await expect(dialog).toContainText(AUDIT_NOTE);
    await expect(dialog.getByRole("button", { name: "Cancel" }), "the safe choice has the focus").toBeFocused();
    expect((await fetchIndicators(request, { q: search })).total, "asking deletes nothing").toBe(3);

    const answer = answerToDelete(page);
    await dialog.getByRole("button", { name: "Delete indicator", exact: true }).click();
    const reply = await answer;
    expect(new URL(reply.url()).pathname).toBe(recordUrl(target.indicator_id));
    const result = (await reply.json()) as DeleteResult;
    expect(result.deleted).toEqual([target.indicator_id]);
    expect(result.not_found).toEqual([]);

    await expect(dialog).toHaveCount(0);
    const done = notice(page, summary(result));
    await expect(done).toBeVisible();
    await expect(done, "the confirmation holds the focus the dialog let go of").toBeFocused();
    await expectFound(page, 2);
    expect((await shownValues(page)).sort()).toEqual(kept.map((item) => item.indicator_value).sort());
    await expect(done).toBeVisible();

    expect((await request.get(recordUrl(target.indicator_id))).status(), "its record").toBe(404);
    expect((await fetchIndicators(request, { q: target.indicator_value })).total, "a search for its value").toBe(0);
    for (const item of kept) {
      expect((await request.get(recordUrl(item.indicator_id))).status(), `the record of ${item.indicator_value}`).toBe(200);
    }
    expect(lookups.count, "deleting asks no provider").toBe(0);

    await done.getByRole("button", { name: "Dismiss" }).click();
    await expect(done).toHaveCount(0);
  });

  test("the same value can be investigated again afterwards, as a new record", async ({ request, seed }) => {
    const { search, items } = await seed(1);
    const target = must(items[0], "an indicator to delete");

    const removed = await deleteViaApi(request, [target.indicator_id]);
    expect(removed.deleted).toEqual([target.indicator_id]);
    expect((await fetchIndicators(request, { q: search })).total).toBe(0);

    const again = await investigateViaApi(request, target.indicator_value);
    expect(again.indicator.indicator_value).toBe(target.indicator_value);
    expect(again.indicator.indicator_id, "it is not the record that was deleted").not.toBe(target.indicator_id);
    expect((await request.get(recordUrl(target.indicator_id))).status(), "the old record stays gone").toBe(404);
    expect((await fetchIndicators(request, { q: search })).total).toBe(1);
  });

  test("it disappears from the overview too", async ({ page, request, seed }) => {
    const { search, items } = await seed(2);
    const target = must(items[0], "an indicator to delete");
    const before = await fetchOverview(request);
    expect(before.recent.map((item) => item.indicator_id), "the overview lists what was just investigated").toContain(
      target.indicator_id,
    );
    await openOverview(page);
    await expect(page.getByRole("list", { name: "Latest investigations" })).toContainText(target.indicator_value);

    await openList(page, `?q=${search}`);
    await trash(page, target.indicator_value).click();
    const answer = answerToDelete(page);
    await confirmation(page, "Delete this indicator?").getByRole("button", { name: "Delete indicator", exact: true }).click();
    await answer;
    await expectFound(page, 1);

    const after = await fetchOverview(request);
    expect(after.kpis.total_indicators, "indicators tracked").toBe(before.kpis.total_indicators - 1);
    for (const list of [after.recent, after.top_risk]) {
      expect(list.map((item) => item.indicator_id)).not.toContain(target.indicator_id);
    }
    await openOverview(page);
    await expect(page.getByRole("list", { name: "Latest investigations" })).not.toContainText(target.indicator_value);
  });

  test("Cancel, Escape and a click outside the dialog all leave everything in place", async ({ page, request, seed }) => {
    const { search, items } = await seed(2);
    const target = must(items[0], "an indicator");
    await openList(page, `?q=${search}`);
    await expectFound(page, 2);
    const single = countRequests(page, ONE, "DELETE");
    const several = countRequests(page, BULK, "POST");

    const opener = trash(page, target.indicator_value);
    const dialog = confirmation(page, "Delete this indicator?");

    await opener.click();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(opener, "the button that asked has the focus back").toBeFocused();

    await opener.click();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(opener).toBeFocused();

    await opener.click();
    await page.mouse.click(4, 4);
    await expect(dialog).toHaveCount(0);

    expect(single.count + several.count, "nothing was sent").toBe(0);
    await expect(page.getByRole("status").filter({ hasText: "Deleted" })).toHaveCount(0);
    await expectFound(page, 2);
    expect((await fetchIndicators(request, { q: search })).total).toBe(2);
  });

  test("Shift-click ticks a run of rows, and one request deletes exactly those", async ({ page, request, seed }) => {
    const { search, items } = await seed(5);
    await openList(page, `?q=${search}`);
    await expectFound(page, 5);
    const shown = await shownValues(page);
    expect(shown).toHaveLength(5);
    const idOf = new Map(items.map((item) => [item.indicator_value, item.indicator_id]));
    const run = shown.slice(1, 4);

    await tick(page, must(shown[1])).click();
    await expect(page.getByRole("button", { name: "Delete selected (1)", exact: true })).toBeVisible();
    await tick(page, must(shown[3])).click({ modifiers: ["Shift"] });
    for (const [index, value] of shown.entries()) {
      if (index >= 1 && index <= 3) await expect(tick(page, value), `row ${index + 1} is in the run`).toBeChecked();
      else await expect(tick(page, value), `row ${index + 1} is outside the run`).not.toBeChecked();
    }
    await expect(page.getByRole("checkbox", { name: SELECT_ALL })).toBeChecked({ indeterminate: true });
    await expect(page.getByText("3 selected", { exact: true })).toBeAttached();
    expect(await page.evaluate(() => window.getSelection()?.toString() ?? ""), "no text is highlighted by the Shift-click").toBe("");
    await expect(page.getByText(HINT)).toHaveCount(0);

    await page.getByRole("button", { name: "Delete selected (3)", exact: true }).click();
    const dialog = confirmation(page, "Delete 3 indicators?");
    await expect(dialog.getByRole("listitem")).toHaveText(run);
    await expect(dialog).toContainText(
      "This permanently removes them, and every provider answer stored for them, from the database. It cannot be undone.",
    );

    const sent = page.waitForRequest((candidate) => candidate.method() === "POST" && BULK.test(candidate.url()));
    const answer = resultOf(answerToBulk(page));
    await dialog.getByRole("button", { name: "Delete 3 indicators", exact: true }).click();
    const body = (await sent).postDataJSON() as { indicator_ids: string[] };
    expect([...body.indicator_ids].sort()).toEqual(run.map((value) => must(idOf.get(value))).sort());

    const result = await answer;
    expect([...result.deleted].sort()).toEqual([...body.indicator_ids].sort());
    expect(result.not_found).toEqual([]);
    await expect(dialog).toHaveCount(0);
    await expect(notice(page, summary(result))).toBeFocused();
    await expectFound(page, 2);
    expect(await shownValues(page)).toEqual([must(shown[0]), must(shown[4])]);
    await expect(ticked(page)).toHaveCount(0);

    expect((await fetchIndicators(request, { q: search })).items.map((item) => item.indicator_value).sort()).toEqual(
      [must(shown[0]), must(shown[4])].sort(),
    );
    for (const id of body.indicator_ids) expect((await request.get(recordUrl(id))).status()).toBe(404);
  });

  test("Select all ticks the whole page, and deleting everything leaves the empty list", async ({ page, request, seed }) => {
    const { search, items } = await seed(4);
    await openList(page, `?q=${search}`);
    await expectFound(page, 4);
    const all = page.getByRole("checkbox", { name: SELECT_ALL });
    await expect(all).not.toBeChecked();
    await expect(page.getByText(HINT)).toBeVisible();
    await expect(page.getByRole("button", { name: /^Delete selected/ })).toHaveCount(0);

    await all.check();
    for (const item of items) await expect(tick(page, item.indicator_value)).toBeChecked();
    await expect(all).toBeChecked();
    await expect(page.getByRole("button", { name: "Delete selected (4)", exact: true })).toBeVisible();

    await tick(page, must(items[0]).indicator_value).uncheck();
    await expect(all).toBeChecked({ indeterminate: true });
    await expect(page.getByRole("button", { name: "Delete selected (3)", exact: true })).toBeVisible();
    await all.check();
    await expect(page.getByRole("button", { name: "Delete selected (4)", exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Delete selected (4)", exact: true }).click();
    const dialog = confirmation(page, "Delete 4 indicators?");
    await expect(dialog.getByRole("listitem")).toHaveCount(4);
    const answer = resultOf(answerToBulk(page));
    await dialog.getByRole("button", { name: "Delete 4 indicators", exact: true }).click();
    const result = await answer;
    expect([...result.deleted].sort()).toEqual(items.map((item) => item.indicator_id).sort());

    await expect(notice(page, summary(result))).toBeVisible();
    await expectFound(page, 0);
    await expect(page.getByText("No indicators match these filters.")).toBeVisible();
    await expect(page.getByRole("table")).toHaveCount(0);
    expect((await fetchIndicators(request, { q: search })).total).toBe(0);
  });

  test("a long selection is summarised in the dialog but every indicator is deleted", async ({ page, request, seed }) => {
    const { search, items } = await seed(7);
    await openList(page, `?q=${search}`);
    await expectFound(page, 7);
    const shown = await shownValues(page);

    await page.getByRole("checkbox", { name: SELECT_ALL }).check();
    await page.getByRole("button", { name: "Delete selected (7)", exact: true }).click();
    const dialog = confirmation(page, "Delete 7 indicators?");
    await expect(dialog.getByRole("listitem")).toHaveText([...shown.slice(0, 5), "and 2 more"]);

    const answer = resultOf(answerToBulk(page));
    await dialog.getByRole("button", { name: "Delete 7 indicators", exact: true }).click();
    expect([...(await answer).deleted].sort()).toEqual(items.map((item) => item.indicator_id).sort());
    await expectFound(page, 0);
    expect((await fetchIndicators(request, { q: search })).total).toBe(0);
  });

  test("Clear selection takes every tick away", async ({ page, seed }) => {
    const { search } = await seed(3);
    await openList(page, `?q=${search}`);
    await expectFound(page, 3);
    const [first, second] = await shownValues(page);

    await tick(page, must(first)).check();
    await tick(page, must(second)).check();
    await expect(page.getByText("2 selected", { exact: true })).toBeAttached();
    await page.getByRole("button", { name: "Clear selection" }).click();

    await expect(ticked(page)).toHaveCount(0);
    await expect(page.getByText(HINT)).toBeVisible();
    await expect(page.getByRole("button", { name: /^Delete selected/ })).toHaveCount(0);
  });

  test("ticks belong to the filters they were made under", async ({ page, seed }) => {
    const { search } = await seed(3);
    await openList(page, `?q=${search}`);
    await expectFound(page, 3);
    await tick(page, must((await shownValues(page))[0])).check();
    await expect(page.getByRole("button", { name: "Delete selected (1)", exact: true })).toBeVisible();

    await page.getByLabel("Sort by", { exact: true }).selectOption({ label: "Highest risk first" });
    await expect(page.getByRole("table", { name: "Indicators, sorted by highest risk" })).toBeVisible();
    await expect(ticked(page)).toHaveCount(0);
    await expect(page.getByText(HINT)).toBeVisible();
  });

  test("deleting the only row of the last page steps back to the page before", async ({ page, request, seed }) => {
    const { search } = await seed(26);
    await openList(page, `?q=${search}`);
    await expectFound(page, 26);
    await expect(page.locator("tbody tr")).toHaveCount(25);

    // A tick stays on the page it was made on.
    await tick(page, must((await shownValues(page))[0])).check();
    await page.getByRole("navigation", { name: "Pagination" }).getByRole("button", { name: "Next" }).click();
    await expect(page.locator("tbody tr")).toHaveCount(1);
    await expect(ticked(page)).toHaveCount(0);

    const last = must((await shownValues(page))[0]);
    await trash(page, last).click();
    const answer = resultOf(answerToDelete(page));
    await confirmation(page, "Delete this indicator?").getByRole("button", { name: "Delete indicator", exact: true }).click();
    const result = await answer;

    await expect.poll(() => new URL(page.url()).search, { message: "the address goes back to the first page" }).toBe(
      `?${new URLSearchParams({ q: search }).toString()}`,
    );
    await expectFound(page, 25);
    await expect(page.locator("tbody tr")).toHaveCount(25);
    await expect(notice(page, summary(result))).toBeVisible();
    expect(await shownValues(page)).not.toContain(last);
    expect((await fetchIndicators(request, { q: search })).total).toBe(25);
  });

  test("everything can be done from the keyboard", async ({ page, request, seed }) => {
    const { search } = await seed(2);
    await openList(page, `?q=${search}`);
    await expectFound(page, 2);
    const first = must((await shownValues(page))[0]);

    await tick(page, first).focus();
    await page.keyboard.press("Space");
    await expect(tick(page, first)).toBeChecked();

    const remove = page.getByRole("button", { name: "Delete selected (1)", exact: true });
    await remove.focus();
    await page.keyboard.press("Enter");
    const dialog = confirmation(page, "Delete this indicator?");
    const cancel = dialog.getByRole("button", { name: "Cancel" });
    const confirm = dialog.getByRole("button", { name: "Delete indicator", exact: true });
    await expect(cancel).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(confirm).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(cancel, "Tab stays inside the dialog").toBeFocused();
    await page.keyboard.press("Escape");
    await expect(dialog).toHaveCount(0);
    await expect(remove, "the button that asked has the focus back").toBeFocused();

    await page.keyboard.press("Enter");
    await expect(cancel).toBeFocused();
    await page.keyboard.press("Tab");
    const answer = resultOf(answerToDelete(page));
    await page.keyboard.press("Enter");
    expect((await answer).deleted).toHaveLength(1);
    await expectFound(page, 1);
    expect((await fetchIndicators(request, { q: search })).total).toBe(1);
  });
});

test.describe("when a deletion does not go as planned", () => {
  test("a failure says why, keeps the dialog open and deletes nothing; trying again works", async ({ page, request, seed, guard }) => {
    guard.expectStatus(500);
    const { search, items } = await seed(2);
    const target = must(items[0], "an indicator");
    let failing = true;
    await page.route(ONE, (route) =>
      failing && route.request().method() === "DELETE"
        ? route.fulfill({
            status: 500,
            json: { error: { code: "internal_error", message: "The service is having a problem.", correlation_id: "e2e-ref-delete" } },
          })
        : route.continue(),
    );
    await openList(page, `?q=${search}`);
    await expectFound(page, 2);

    await trash(page, target.indicator_value).click();
    const dialog = confirmation(page, "Delete this indicator?");
    await dialog.getByRole("button", { name: "Delete indicator", exact: true }).click();

    const alert = dialog.getByRole("alert");
    await expect(alert).toContainText("The API reported an error");
    await expect(alert).toContainText("The service is having a problem.");
    await expect(alert).toContainText("Reference: e2e-ref-delete");
    await expect(dialog).toBeVisible();
    await expect(page.getByRole("status").filter({ hasText: "Deleted" })).toHaveCount(0);
    expect((await fetchIndicators(request, { q: search })).total, "the failed request deleted nothing").toBe(2);

    failing = false;
    await dialog.getByRole("button", { name: "Delete indicator", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expectFound(page, 1);
    expect((await fetchIndicators(request, { q: search })).items.map((item) => item.indicator_id)).not.toContain(target.indicator_id);
  });

  test("while it deletes, the dialog can be neither dismissed nor confirmed twice", async ({ page, seed }) => {
    const { search, items } = await seed(2);
    const target = must(items[0], "an indicator");
    let release = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    await page.route(ONE, async (route) => {
      if (route.request().method() === "DELETE") await gate;
      await route.continue().catch(() => undefined);
    });
    await openList(page, `?q=${search}`);
    await expectFound(page, 2);
    const sent = countRequests(page, ONE, "DELETE");

    await trash(page, target.indicator_value).click();
    const dialog = confirmation(page, "Delete this indicator?");
    await dialog.getByRole("button", { name: "Delete indicator", exact: true }).click();

    const busy = dialog.getByRole("button", { name: "Deleting…" });
    await expect(busy).toBeDisabled();
    await expect(dialog.getByRole("button", { name: "Cancel" })).toBeDisabled();
    // The buttons only look disabled to the browser's checks, so a click still reaches them.
    await busy.click({ force: true });
    await dialog.getByRole("button", { name: "Cancel" }).click({ force: true });
    await page.keyboard.press("Escape");
    await page.mouse.click(4, 4);
    await expect(dialog).toBeVisible();

    release();
    await expect(dialog).toHaveCount(0);
    await expectFound(page, 1);
    expect(sent.count, "the deletion was sent once").toBe(1);
  });

  test("an indicator somebody else already deleted is reported as gone", async ({ page, request, seed, guard }) => {
    guard.expectStatus(404);
    const { search, items } = await seed(2);
    const target = must(items[0], "an indicator");
    await openList(page, `?q=${search}`);
    await expectFound(page, 2);
    await deleteViaApi(request, [target.indicator_id]);

    await trash(page, target.indicator_value).click();
    const answer = answerToDelete(page);
    await confirmation(page, "Delete this indicator?").getByRole("button", { name: "Delete indicator", exact: true }).click();
    expect((await answer).status()).toBe(404);

    await expect(notice(page, "Nothing was deleted. 1 indicator was already gone.")).toBeVisible();
    await expectFound(page, 1);
    expect(await shownValues(page)).not.toContain(target.indicator_value);
  });

  test("in a selection, the ones that are already gone are counted, and the rest are deleted", async ({ page, request, seed }) => {
    const { search, items } = await seed(3);
    const gone = must(items[0], "an indicator");
    await openList(page, `?q=${search}`);
    await expectFound(page, 3);
    await page.getByRole("checkbox", { name: SELECT_ALL }).check();
    await deleteViaApi(request, [gone.indicator_id]);

    await page.getByRole("button", { name: "Delete selected (3)", exact: true }).click();
    const answer = resultOf(answerToBulk(page));
    await confirmation(page, "Delete 3 indicators?").getByRole("button", { name: "Delete 3 indicators", exact: true }).click();
    const result = await answer;
    expect(result.deleted).toHaveLength(2);
    expect(result.not_found).toEqual([gone.indicator_id]);

    await expect(notice(page, summary(result))).toContainText("1 indicator was already gone.");
    await expectFound(page, 0);
    expect((await fetchIndicators(request, { q: search })).total).toBe(0);
  });
});

test.describe("deleting from a record", () => {
  test("the button asks first; confirming removes the record and says so", async ({ page, request, seed }) => {
    const { search, items } = await seed(2);
    const target = must(items[0], "an indicator to delete");
    const other = must(items[1], "an indicator to keep");
    await openRecord(page, target.indicator_id);

    const dialog = confirmation(page, "Delete this indicator?");
    const opener = page.getByRole("button", { name: "Delete indicator", exact: true });
    await opener.click();
    await expect(dialog.getByRole("listitem")).toHaveText([target.indicator_value]);
    await expect(dialog.getByRole("button", { name: "Cancel" })).toBeFocused();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toHaveCount(0);
    await expect(opener, "the button that asked has the focus back").toBeFocused();
    expect((await request.get(recordUrl(target.indicator_id))).status(), "cancelling deletes nothing").toBe(200);

    await opener.click();
    const answer = resultOf(answerToDelete(page));
    await dialog.getByRole("button", { name: "Delete indicator", exact: true }).click();
    const result = await answer;
    expect(result.deleted).toEqual([target.indicator_id]);

    await expect(page.getByRole("heading", { level: 1, name: "Indicator deleted" })).toBeVisible();
    await expect(page).toHaveTitle("Indicator deleted \u00b7 CipherForge");
    await expect(page.getByText(summary(result), { exact: true })).toBeVisible();
    await expect(page.getByText(AUDIT_NOTE)).toBeVisible();
    await expect(panel(page, "CipherForge assessment")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Re-check|Delete/ })).toHaveCount(0);
    expect((await request.get(recordUrl(target.indicator_id))).status()).toBe(404);
    expect((await request.get(recordUrl(other.indicator_id))).status(), "the other record is untouched").toBe(200);

    await page.getByRole("link", { name: "Back to the list" }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Indicators", exact: true })).toBeVisible();
    expect((await fetchIndicators(request, { q: search })).items.map((item) => item.indicator_id)).toEqual([other.indicator_id]);
  });

  test("a record somebody else already deleted is reported as already gone", async ({ page, request, seed, guard }) => {
    guard.expectStatus(404);
    const { items } = await seed(1);
    const target = must(items[0], "an indicator");
    await openRecord(page, target.indicator_id);
    await deleteViaApi(request, [target.indicator_id]);

    await page.getByRole("button", { name: "Delete indicator", exact: true }).click();
    await confirmation(page, "Delete this indicator?").getByRole("button", { name: "Delete indicator", exact: true }).click();

    await expect(page.getByRole("heading", { level: 1, name: "Indicator already gone" })).toBeVisible();
    await expect(page.getByText("Nothing was deleted. 1 indicator was already gone.", { exact: true })).toBeVisible();
  });

  test("the address of a deleted record no longer opens anything", async ({ page, request, seed, guard }) => {
    guard.expectStatus(404);
    const { items } = await seed(1);
    const target = must(items[0], "an indicator");
    await deleteViaApi(request, [target.indicator_id]);

    await page.goto(`/indicators/${target.indicator_id}`);
    await expect(page.getByRole("heading", { level: 1, name: "Indicator not found" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Re-check|Delete/ })).toHaveCount(0);
  });

  test("a record cannot be deleted while a re-check is running", async ({ page, seed }) => {
    const { items } = await seed(1);
    const target = must(items[0], "an indicator");
    await page.route(INVESTIGATE, async (route) => {
      await pause(1_500);
      await route.continue().catch(() => undefined);
    });
    await openRecord(page, target.indicator_id);

    await page.getByRole("button", { name: "Re-check with providers" }).click();
    await expect(page.getByRole("button", { name: "Re-checking…" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Delete indicator", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "Delete indicator", exact: true }).click({ force: true });
    await expect(page.getByRole("dialog")).toHaveCount(0);

    await expect(page.getByRole("button", { name: "Delete indicator", exact: true })).toBeEnabled();
  });
});

test.describe("an indicator written as an attack", () => {
  test("is listed as plain text in the confirmation and deleted like any other", async ({ page, request }) => {
    watchDialogs(page);
    const value = `https://e2e-del-${uniqueSuffix()}.example.net/p?q=');alert(document.cookie);//&r=javascript:alert(1)`;
    const stored = (await investigateViaApi(request, value)).indicator;
    expect(stored.indicator_value).toBe(value);

    await openList(page, `?q=${encodeURIComponent(value)}`);
    await expectFound(page, 1);
    await trash(page, value).click();
    const dialog = confirmation(page, "Delete this indicator?");
    await expect(dialog.getByRole("listitem")).toHaveText([value]);
    await expectInert(page, "the confirmation");

    const answer = resultOf(answerToDelete(page));
    await dialog.getByRole("button", { name: "Delete indicator", exact: true }).click();
    expect((await answer).deleted).toEqual([stored.indicator_id]);
    await expectFound(page, 0);
    await expectInert(page, "the list after the deletion");
    expect((await fetchIndicators(request, { q: value })).total).toBe(0);
  });
});
