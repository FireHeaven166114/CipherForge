import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { makeIndicator, makeNotAssessed, makePage } from "../test/fixtures";
import { jsonResponse, stubFetch } from "../test/http";
import { renderRoute } from "../test/router";
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
