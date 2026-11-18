import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { makeIndicator, makeNotAssessed, makePage } from "../test/fixtures";
import { jsonResponse, stubFetch } from "../test/http";
import { renderRoute } from "../test/router";
import type { Indicator } from "../types/intel";
import IndicatorsPage from "./IndicatorsPage";

const OTHER_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const TABLE = /^Indicators, sorted by /;

function unassessed() {
  return { ...makeNotAssessed().indicator, indicator_id: OTHER_ID };
}

type FetchMock = ReturnType<typeof stubFetch>;

/** Serves every list request with `reply`, which sees the offset that was asked for. */
function serve(reply: (offset: number) => Response): FetchMock {
  return stubFetch((url) => {
    const offset = Number(new URL(url, "http://localhost").searchParams.get("offset") ?? 0);
    return reply(offset);
  });
}

function query(fetchMock: FetchMock, call = fetchMock.mock.calls.length - 1) {
  const url = new URL(String(fetchMock.mock.calls[call]?.[0]), "http://localhost");
  return { path: url.pathname, params: Object.fromEntries(url.searchParams) };
}

function lastUrl(fetchMock: FetchMock): URL {
  return new URL(String(fetchMock.mock.calls[fetchMock.mock.calls.length - 1]?.[0]), "http://localhost");
}

function location(): string {
  return screen.getByTestId("location").textContent ?? "";
}

function renderPage(url = "/indicators") {
  return renderRoute(<IndicatorsPage />, { url });
}

describe("IndicatorsPage", () => {
  it("lists indicators, most recently checked first, and marks unassessed ones", async () => {
    const fetchMock = serve(() => jsonResponse(makePage([makeIndicator(), unassessed()])));
    renderPage();
    expect(screen.getByText("Loading indicators…")).toBeInTheDocument();

    const table = await screen.findByRole("table", { name: TABLE });

    expect(query(fetchMock)).toEqual({
      path: "/api/v1/intel/indicators",
      params: { sort: "recent", limit: "25", offset: "0" },
    });
    expect(screen.getByRole("table")).toHaveAccessibleName(
      "Indicators, sorted by most recent check",
    );
    expect(within(table).getByRole("link", { name: "203.0.113.9" })).toHaveAttribute(
      "href",
      "/indicators/3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b",
    );
    expect(within(table).getByText("Not assessed")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("2 indicators found.");
    expect(screen.getByText("Showing 1–2 of 2")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Reset filters" })).not.toBeInTheDocument();
    expect(document.title).toBe("Indicators · CipherForge");
  });

  it("starts from the filters in the address and shows them in the controls", async () => {
    const fetchMock = serve((offset) =>
      jsonResponse(makePage([makeIndicator()], { total: 60, offset })),
    );
    renderPage("/indicators?q=203.0&type=ipv4&classification=high&sort=risk&page=2");

    await screen.findByRole("table", { name: TABLE });

    expect(query(fetchMock).params).toEqual({
      type: "ipv4",
      classification: "high",
      assessed: "true",
      q: "203.0",
      sort: "risk",
      limit: "25",
      offset: "25",
    });
    expect(screen.getByLabelText("Type")).toHaveValue("ipv4");
    expect(screen.getByLabelText("Classification")).toHaveValue("high");
    expect(screen.getByLabelText("Sort by")).toHaveValue("risk");
    expect(screen.getByRole("searchbox", { name: "Search" })).toHaveValue("203.0");
    expect(screen.getByRole("table")).toHaveAccessibleName("Indicators, sorted by highest risk");
    expect(screen.getByRole("button", { name: "Reset filters" })).toBeInTheDocument();
  });

  it("offers the groups the overview counts, in the order of severity", async () => {
    serve(() => jsonResponse(makePage([makeIndicator()])));
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    const options = within(screen.getByLabelText("Classification")).getAllByRole("option");

    expect(options.map((option) => option.textContent)).toEqual([
      "All classifications",
      "High or critical",
      "Critical",
      "High",
      "Medium",
      "Low",
      "Informational",
      "Not assessed",
    ]);
  });

  it("filters by high and critical together, and by the indicators no provider answered for", async () => {
    const fetchMock = serve(() => jsonResponse(makePage([makeIndicator()])));
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.selectOptions(screen.getByLabelText("Classification"), "High or critical");

    await waitFor(() => {
      expect(lastUrl(fetchMock).searchParams.getAll("classification")).toEqual(["high", "critical"]);
    });
    expect(lastUrl(fetchMock).searchParams.get("assessed")).toBe("true");
    expect(location()).toBe("/indicators?classification=high_risk");

    await user.selectOptions(screen.getByLabelText("Classification"), "Not assessed");

    await waitFor(() => {
      expect(lastUrl(fetchMock).searchParams.get("assessed")).toBe("false");
    });
    expect(lastUrl(fetchMock).searchParams.has("classification")).toBe(false);
    expect(location()).toBe("/indicators?classification=not_assessed");
  });

  it("never sends values from the address that the API does not define", async () => {
    const fetchMock = serve(() => jsonResponse(makePage([makeIndicator()])));
    renderPage("/indicators?type=bogus&classification=nope&sort=sideways&page=-4");

    await screen.findByRole("table", { name: TABLE });

    expect(query(fetchMock).params).toEqual({ sort: "recent", limit: "25", offset: "0" });
  });

  it("applies a filter at once, returns to the first page and records it in the address", async () => {
    const fetchMock = serve((offset) =>
      jsonResponse(makePage([makeIndicator()], { total: 60, offset })),
    );
    const user = userEvent.setup();
    renderPage("/indicators?page=2");
    await screen.findByText("Showing 26–50 of 60");

    await user.selectOptions(screen.getByLabelText("Type"), "ipv4");

    await screen.findByText("Showing 1–25 of 60");
    expect(location()).toBe("/indicators?type=ipv4");
    expect(query(fetchMock).params).toEqual({
      type: "ipv4",
      sort: "recent",
      limit: "25",
      offset: "0",
    });

    await user.selectOptions(screen.getByLabelText("Sort by"), "risk");
    await screen.findByRole("table", { name: "Indicators, sorted by highest risk" });
    expect(location()).toBe("/indicators?type=ipv4&sort=risk");
  });

  it("searches only when asked to, ignoring spaces around the text", async () => {
    const fetchMock = serve(() => jsonResponse(makePage([makeIndicator()])));
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });
    const callsBefore = fetchMock.mock.calls.length;

    await user.type(screen.getByRole("searchbox", { name: "Search" }), "  evil.test ");
    expect(fetchMock.mock.calls.length).toBe(callsBefore);

    await user.click(screen.getByRole("button", { name: "Search" }));

    await screen.findByRole("table", { name: TABLE });
    expect(location()).toBe("/indicators?q=evil.test");
    expect(query(fetchMock).params).toMatchObject({ q: "evil.test", offset: "0" });
  });

  it("moves between pages and keeps the page in the address", async () => {
    const fetchMock = serve((offset) =>
      jsonResponse(makePage([makeIndicator()], { total: 60, offset })),
    );
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Showing 1–25 of 60");
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Next" }));

    await screen.findByText("Showing 26–50 of 60");
    expect(location()).toBe("/indicators?page=2");
    expect(query(fetchMock).params).toMatchObject({ offset: "25" });

    await user.click(screen.getByRole("button", { name: "Previous" }));

    await screen.findByText("Showing 1–25 of 60");
    expect(location()).toBe("/indicators");
  });

  it("invites an investigation when nothing has been investigated yet", async () => {
    serve(() => jsonResponse(makePage([])));
    renderPage();

    expect(await screen.findByText("No indicators have been investigated yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Investigate one now" })).toHaveAttribute(
      "href",
      "/investigate",
    );
    expect(screen.queryByRole("button", { name: "Reset filters" })).not.toBeInTheDocument();
  });

  it("says no indicator matches the filters and offers to clear them", async () => {
    serve(() => jsonResponse(makePage([])));
    const user = userEvent.setup();
    renderPage("/indicators?q=nothing-like-this");

    expect(await screen.findByText("No indicators match these filters.")).toBeInTheDocument();
    expect(screen.queryByText("No indicators have been investigated yet.")).not.toBeInTheDocument();
    const [, fromEmptyState] = screen.getAllByRole("button", { name: "Reset filters" });
    await user.click(fromEmptyState as HTMLElement);

    expect(location()).toBe("/indicators");
    expect(screen.getByRole("searchbox", { name: "Search" })).toHaveValue("");
  });

  it("offers a way back when the page asked for is past the last result", async () => {
    serve((offset) => jsonResponse(makePage([], { total: 30, offset })));
    const user = userEvent.setup();
    renderPage("/indicators?page=9");

    expect(await screen.findByText("This page has no results.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Go to the first page" }));

    expect(location()).toBe("/indicators");
  });

  it("reports a failure with its reference and tries again on request", async () => {
    let calls = 0;
    serve(() => {
      calls += 1;
      return calls === 1
        ? jsonResponse(
            { error: { code: "internal_error", message: "Something failed.", correlation_id: "req-9" } },
            { status: 500 },
          )
        : jsonResponse(makePage([makeIndicator()]));
    });
    const user = userEvent.setup();
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(alert).toHaveTextContent("Reference: req-9");

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("table", { name: TABLE })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

function row(n: number): Indicator {
  return makeIndicator({
    indicator_id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
    indicator_value: `203.0.113.${n}`,
  });
}

interface Change {
  method: string;
  path: string;
  body: unknown;
}

/** A small stand-in for the API that really forgets what is deleted, and fails when told to. */
function serveRows(initial: readonly Indicator[], options: { failDeletes?: () => boolean } = {}) {
  let rows = [...initial];
  const fetchMock = stubFetch((url, init) => {
    const { pathname, searchParams } = new URL(url, "http://localhost");
    if (init?.method === "DELETE" || init?.method === "POST") {
      if (options.failDeletes?.()) {
        return jsonResponse(
          { error: { code: "internal_error", message: "Something failed.", correlation_id: "req-7" } },
          { status: 500 },
        );
      }
      const asked: string[] =
        init.method === "DELETE"
          ? [pathname.split("/").pop() ?? ""]
          : (JSON.parse(String(init.body)) as { indicator_ids: string[] }).indicator_ids;
      const deleted = asked.filter((id) => rows.some((item) => item.indicator_id === id));
      rows = rows.filter((item) => !deleted.includes(item.indicator_id));
      const notFound = asked.filter((id) => !deleted.includes(id));
      if (init.method === "DELETE" && deleted.length === 0) {
        return jsonResponse(
          { error: { code: "not_found", message: "Indicator not found." } },
          { status: 404 },
        );
      }
      return jsonResponse({
        deleted,
        not_found: notFound,
        observations_removed: deleted.length * 2,
      });
    }
    const offset = Number(searchParams.get("offset") ?? 0);
    return jsonResponse(makePage(rows.slice(offset, offset + 25), { total: rows.length, offset }));
  });
  return fetchMock;
}

/** The requests that changed something, which are all the page may send besides reading lists. */
function changes(fetchMock: FetchMock): Change[] {
  return fetchMock.mock.calls
    .filter(([, init]) => init?.method !== undefined && init.method !== "GET")
    .map(([url, init]) => ({
      method: String(init?.method),
      path: new URL(String(url), "http://localhost").pathname,
      body: typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined,
    }));
}

function box(name: string) {
  return screen.getByRole("checkbox", { name });
}

const SELECT_ALL = "Select all indicators on this page";
const HINT = "Tick rows to delete them. Hold Shift to tick a range.";

describe("IndicatorsPage deleting", () => {
  it("counts the ticked rows, shows the header box as partly ticked and clears on request", async () => {
    serveRows([row(1), row(2), row(3)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });
    expect(screen.getByText(HINT)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Delete selected/ })).not.toBeInTheDocument();

    await user.click(box("Select 203.0.113.2"));

    expect(box("Select 203.0.113.2")).toBeChecked();
    expect(box("Select 203.0.113.1")).not.toBeChecked();
    expect(box(SELECT_ALL)).toBePartiallyChecked();
    expect(screen.getByRole("button", { name: "Delete selected (1)" })).toBeInTheDocument();
    expect(screen.queryByText(HINT)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Clear selection" }));

    expect(box("Select 203.0.113.2")).not.toBeChecked();
    expect(box(SELECT_ALL)).not.toBePartiallyChecked();
    expect(screen.getByText(HINT)).toBeInTheDocument();
  });

  it("ticks and unticks every row on the page with the box in the header", async () => {
    serveRows([row(1), row(2), row(3)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(box(SELECT_ALL));

    for (const n of [1, 2, 3]) expect(box(`Select 203.0.113.${n}`)).toBeChecked();
    expect(box(SELECT_ALL)).toBeChecked();
    expect(screen.getByRole("button", { name: "Delete selected (3)" })).toBeInTheDocument();

    await user.click(box(SELECT_ALL));

    for (const n of [1, 2, 3]) expect(box(`Select 203.0.113.${n}`)).not.toBeChecked();
    expect(screen.getByText(HINT)).toBeInTheDocument();
  });

  it("ticks a whole run of rows when Shift is held", async () => {
    serveRows([row(1), row(2), row(3), row(4)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(box("Select 203.0.113.1"));
    await user.keyboard("{Shift>}");
    await user.click(box("Select 203.0.113.3"));
    await user.keyboard("{/Shift}");

    expect(box("Select 203.0.113.1")).toBeChecked();
    expect(box("Select 203.0.113.2")).toBeChecked();
    expect(box("Select 203.0.113.3")).toBeChecked();
    expect(box("Select 203.0.113.4")).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Delete selected (3)" })).toBeInTheDocument();
  });

  it("asks first, then deletes one indicator with a single request and says so", async () => {
    const fetchMock = serveRows([row(1), row(2), row(3)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.2" }));

    const dialog = screen.getByRole("dialog", { name: "Delete this indicator?" });
    expect(within(dialog).getByText("203.0.113.2")).toBeInTheDocument();
    expect(within(dialog).getByText(/every provider answer stored for it/)).toBeInTheDocument();
    expect(within(dialog).getByText(/The audit log is kept as it is/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(changes(fetchMock)).toEqual([]);

    await user.click(within(dialog).getByRole("button", { name: "Delete indicator" }));

    const notice = await screen.findByText("Deleted 1 indicator and 2 stored provider answers.");
    expect(changes(fetchMock)).toEqual([
      { method: "DELETE", path: `/api/v1/intel/indicators/${row(2).indicator_id}`, body: undefined },
    ]);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(notice.closest("[role=status]")).toHaveFocus();
    await screen.findByRole("table", { name: TABLE });
    expect(screen.queryByRole("link", { name: "203.0.113.2" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "203.0.113.1" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "203.0.113.3" })).toBeInTheDocument();
  });

  it("sends nothing when the dialog is cancelled and gives focus back to the button", async () => {
    const fetchMock = serveRows([row(1), row(2)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });
    const trash = screen.getByRole("button", { name: "Delete 203.0.113.1" });

    await user.click(trash);
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trash).toHaveFocus();
    expect(changes(fetchMock)).toEqual([]);

    await user.click(trash);
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(changes(fetchMock)).toEqual([]);
  });

  it("deletes the ticked rows together, in the order they are listed", async () => {
    const fetchMock = serveRows([row(1), row(2), row(3)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(box("Select 203.0.113.3"));
    await user.click(box("Select 203.0.113.1"));
    await user.click(screen.getByRole("button", { name: "Delete selected (2)" }));

    const dialog = screen.getByRole("dialog", { name: "Delete 2 indicators?" });
    expect(within(dialog).getAllByRole("listitem").map((item) => item.textContent)).toEqual([
      "203.0.113.1",
      "203.0.113.3",
    ]);

    await user.click(within(dialog).getByRole("button", { name: "Delete 2 indicators" }));

    await screen.findByText("Deleted 2 indicators and 4 stored provider answers.");
    expect(changes(fetchMock)).toEqual([
      {
        method: "POST",
        path: "/api/v1/intel/indicators/bulk-delete",
        body: { indicator_ids: [row(1).indicator_id, row(3).indicator_id] },
      },
    ]);
    await screen.findByRole("table", { name: TABLE });
    expect(screen.getByRole("link", { name: "203.0.113.2" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "203.0.113.1" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "203.0.113.3" })).not.toBeInTheDocument();
    expect(screen.getByText(HINT)).toBeInTheDocument();
  });

  it("names the first few of a long selection and counts the rest", async () => {
    serveRows(Array.from({ length: 8 }, (_, index) => row(index + 1)));
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(box(SELECT_ALL));
    await user.click(screen.getByRole("button", { name: "Delete selected (8)" }));

    const dialog = screen.getByRole("dialog", { name: "Delete 8 indicators?" });
    expect(within(dialog).getAllByRole("listitem")).toHaveLength(6);
    expect(within(dialog).getByText("and 3 more")).toBeInTheDocument();
  });

  it("keeps the dialog open and says why when the API fails, then deletes on the next try", async () => {
    let failing = true;
    const fetchMock = serveRows([row(1), row(2)], { failDeletes: () => failing });
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });
    const listReads = fetchMock.mock.calls.length;

    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.1" }));
    await user.click(screen.getByRole("button", { name: "Delete indicator" }));

    const dialog = screen.getByRole("dialog");
    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(alert).toHaveTextContent("Reference: req-7");
    expect(within(dialog).getByRole("button", { name: "Delete indicator" })).not.toHaveAttribute(
      "aria-disabled",
    );
    expect(fetchMock.mock.calls.length).toBe(listReads + 1);
    expect(screen.queryByText(/^Deleted /)).not.toBeInTheDocument();

    failing = false;
    await user.click(within(dialog).getByRole("button", { name: "Delete indicator" }));

    await screen.findByText("Deleted 1 indicator and 2 stored provider answers.");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(changes(fetchMock)).toHaveLength(2);
  });

  it("cannot be dismissed or pressed twice while the API is working", async () => {
    let finish: (response: Response) => void = () => undefined;
    const fetchMock = stubFetch((_url, init) => {
      if (init?.method === "DELETE") {
        return new Promise<Response>((resolve) => {
          finish = resolve;
        });
      }
      return jsonResponse(makePage([row(1)]));
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.1" }));
    await user.click(screen.getByRole("button", { name: "Delete indicator" }));

    const busy = await screen.findByRole("button", { name: "Deleting…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await user.click(busy);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(changes(fetchMock)).toHaveLength(1);

    finish(
      jsonResponse({ deleted: [row(1).indicator_id], not_found: [], observations_removed: 0 }),
    );

    await screen.findByText("Deleted 1 indicator and 0 stored provider answers.");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("goes to the last page that still has rows when the deletion empties the current one", async () => {
    const fetchMock = serveRows(Array.from({ length: 26 }, (_, index) => row(index + 1)));
    const user = userEvent.setup();
    renderPage("/indicators?page=2");
    await screen.findByText("Showing 26–26 of 26");

    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.26" }));
    await user.click(screen.getByRole("button", { name: "Delete indicator" }));

    await screen.findByText("Showing 1–25 of 25");
    expect(location()).toBe("/indicators");
    expect(query(fetchMock).params).toMatchObject({ offset: "0" });
    expect(screen.getByText("Deleted 1 indicator and 2 stored provider answers.")).toBeInTheDocument();
  });

  it("stays on the page when it still has rows after a deletion", async () => {
    serveRows(Array.from({ length: 27 }, (_, index) => row(index + 1)));
    const user = userEvent.setup();
    renderPage("/indicators?page=2");
    await screen.findByText("Showing 26–27 of 27");

    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.27" }));
    await user.click(screen.getByRole("button", { name: "Delete indicator" }));

    await screen.findByText("Showing 26–26 of 26");
    expect(location()).toBe("/indicators?page=2");
  });

  it("reports an indicator that was already gone as a result, not as a failure", async () => {
    let gone = false;
    stubFetch((_url, init) => {
      if (init?.method === "DELETE") {
        gone = true;
        return jsonResponse(
          { error: { code: "not_found", message: "Indicator not found." } },
          { status: 404 },
        );
      }
      return jsonResponse(makePage(gone ? [row(2)] : [row(1), row(2)]));
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });

    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.1" }));
    await user.click(screen.getByRole("button", { name: "Delete indicator" }));

    expect(
      await screen.findByText("Nothing was deleted. 1 indicator was already gone."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole("link", { name: "203.0.113.1" })).not.toBeInTheDocument();
    });
  });

  it("forgets the ticks when the filters or the page change", async () => {
    serveRows(Array.from({ length: 30 }, (_, index) => row(index + 1)));
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Showing 1–25 of 30");

    await user.click(box("Select 203.0.113.1"));
    await user.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Showing 26–30 of 30");
    await user.click(screen.getByRole("button", { name: "Previous" }));
    await screen.findByText("Showing 1–25 of 30");

    expect(box("Select 203.0.113.1")).not.toBeChecked();
    expect(screen.getByText(HINT)).toBeInTheDocument();

    await user.click(box("Select 203.0.113.1"));
    await user.selectOptions(screen.getByLabelText("Type"), "ipv4");

    await waitFor(() => {
      expect(box("Select 203.0.113.1")).not.toBeChecked();
    });
    expect(screen.getByText(HINT)).toBeInTheDocument();
  });

  it("lets the notice be dismissed", async () => {
    serveRows([row(1), row(2)]);
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("table", { name: TABLE });
    await user.click(screen.getByRole("button", { name: "Delete 203.0.113.1" }));
    await user.click(screen.getByRole("button", { name: "Delete indicator" }));
    await screen.findByText("Deleted 1 indicator and 2 stored provider answers.");

    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.queryByText(/^Deleted /)).not.toBeInTheDocument();
  });
});
