import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { makeIndicator, makeNotAssessed, makePage, makeStats } from "../test/fixtures";
import { jsonResponse, stubFetch } from "../test/http";
import { renderRoute } from "../test/router";
import OverviewPage from "./OverviewPage";

const FORBIDDEN = {
  error: {
    code: "forbidden",
    message: "You do not have access to threat intelligence.",
    correlation_id: "req-403",
  },
};

const RECENT_TABLE = "The most recently investigated indicators";

interface Responses {
  stats?: () => Response;
  recent?: () => Response;
}

function serve({ stats, recent }: Responses = {}) {
  return stubFetch((url) => {
    const { pathname } = new URL(url, "http://localhost");
    if (pathname === "/api/v1/intel/stats") return (stats ?? (() => jsonResponse(makeStats())))();
    if (pathname === "/api/v1/intel/indicators") {
      return (recent ?? (() => jsonResponse(makePage([makeIndicator()]))))();
    }
    return jsonResponse(
      { error: { code: "not_found", message: "No such route.", correlation_id: "x" } },
      { status: 404 },
    );
  });
}

function renderOverview() {
  return renderRoute(<OverviewPage />, { url: "/" });
}

function tile(label: string): HTMLElement {
  const element = screen.getByText(label).closest("div");
  if (!element) throw new Error(`No tile found for "${label}"`);
  return element;
}

function card(heading: string): HTMLElement {
  const element = screen.getByRole("heading", { name: heading }).closest("section");
  if (!element) throw new Error(`No card found for "${heading}"`);
  return element;
}

describe("OverviewPage", () => {
  it("summarises what has been investigated and which providers are configured", async () => {
    const fetchMock = serve({
      recent: () =>
        jsonResponse(
          makePage([
            makeIndicator(),
            { ...makeNotAssessed().indicator, indicator_id: "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d" },
          ]),
        ),
    });
    renderOverview();
    expect(screen.getByText("Loading statistics…")).toBeInTheDocument();
    expect(screen.getByText("Loading recent indicators…")).toBeInTheDocument();

    expect(await screen.findByText("Indicators stored")).toBeInTheDocument();
    expect(tile("Indicators stored")).toHaveTextContent("12");
    expect(tile("Lookups in the last 24 hours")).toHaveTextContent("9");
    expect(tile("Providers configured")).toHaveTextContent("1 of 2");
    expect(tile("Providers configured")).toHaveTextContent("Not configured: AlienVault OTX");
    expect(screen.queryByRole("note")).not.toBeInTheDocument();

    const classification = within(card("Indicators by classification"));
    expect(classification.getByText("Critical").closest("li")).toHaveTextContent("1 (8%)");
    expect(classification.getByText("Informational").closest("li")).toHaveTextContent("4 (33%)");
    expect(within(card("Indicators by type")).getByText("IPv4").closest("li")).toHaveTextContent(
      "6 (50%)",
    );

    const providers = within(card("Threat-intelligence providers"));
    expect(providers.getByText("Configured")).toBeInTheDocument();
    expect(providers.getByText("Not configured")).toBeInTheDocument();

    const table = await screen.findByRole("table", { name: RECENT_TABLE });
    expect(within(table).getByRole("link", { name: "203.0.113.9" })).toBeInTheDocument();
    expect(within(table).getByText("Not assessed")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Investigate an indicator" })).toHaveAttribute(
      "href",
      "/investigate",
    );
    expect(screen.getByRole("link", { name: "View all indicators" })).toHaveAttribute(
      "href",
      "/indicators",
    );
    const recentRequest = new URL(String(fetchMock.mock.calls[1]?.[0]), "http://localhost");
    expect(Object.fromEntries(recentRequest.searchParams)).toEqual({ sort: "recent", limit: "5" });
  });

  it("warns that every result will be Not assessed when no provider is configured", async () => {
    const stats = makeStats();
    serve({
      stats: () =>
        jsonResponse({
          ...stats,
          providers: stats.providers.map((provider) => ({ ...provider, configured: false })),
        }),
    });
    renderOverview();

    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent("No threat-intelligence provider is configured");
    expect(note).toHaveTextContent("Not assessed");
    expect(tile("Providers configured")).toHaveTextContent("0 of 2");
  });

  it("invites a first investigation instead of drawing empty charts", async () => {
    serve({
      stats: () =>
        jsonResponse(
          makeStats({
            total_indicators: 0,
            lookups_last_24h: 0,
            by_classification: {},
            by_type: {},
          }),
        ),
      recent: () => jsonResponse(makePage([])),
    });
    renderOverview();

    expect(await screen.findByText("No indicators have been investigated yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Investigate the first one" })).toHaveAttribute(
      "href",
      "/investigate",
    );
    expect(await screen.findByText("Nothing has been investigated yet.")).toBeInTheDocument();
    expect(screen.queryByText("Indicators by classification")).not.toBeInTheDocument();
  });

  it("keeps the rest of the page working when statistics fail, and retries on request", async () => {
    let statsCalls = 0;
    serve({
      stats: () => {
        statsCalls += 1;
        return statsCalls === 1
          ? jsonResponse(FORBIDDEN, { status: 403 })
          : jsonResponse(makeStats());
      },
    });
    const user = userEvent.setup();
    renderOverview();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Access denied");
    expect(alert).toHaveTextContent("Reference: req-403");
    expect(await screen.findByRole("table", { name: RECENT_TABLE })).toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("Indicators stored")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("reports a failure to load recent indicators without hiding the statistics", async () => {
    serve({
      recent: () =>
        jsonResponse(
          { error: { code: "internal_error", message: "Something failed.", correlation_id: "req-500" } },
          { status: 500 },
        ),
    });
    renderOverview();

    expect(await screen.findByText("Indicators stored")).toBeInTheDocument();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(alert).toHaveTextContent("Reference: req-500");
  });
});
