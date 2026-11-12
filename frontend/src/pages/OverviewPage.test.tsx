import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { INDICATOR_ID, makeOverview, makeProviders } from "../test/fixtures";
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

/** Answers the overview request with whatever `answer` returns for that call number (1, 2, ...). */
function serveOverview(answer: (call: number) => Response) {
  let calls = 0;
  return stubFetch((url) => {
    const { pathname } = new URL(url, "http://localhost");
    if (pathname !== "/api/v1/intel/overview") {
      return jsonResponse(
        { error: { code: "not_found", message: "No such route.", correlation_id: "x" } },
        { status: 404 },
      );
    }
    calls += 1;
    return answer(calls);
  });
}

function renderOverview() {
  return renderRoute(<OverviewPage />, { url: "/" });
}

function panel(title: string): HTMLElement {
  const element = screen.getByRole("heading", { name: title }).closest("section");
  if (!element) throw new Error(`No panel found for "${title}"`);
  return element;
}

async function figure(name: RegExp): Promise<HTMLElement> {
  return screen.findByRole("link", { name });
}

describe("OverviewPage", () => {
  it("reads everything from the one overview request", async () => {
    const fetchMock = serveOverview(() => jsonResponse(makeOverview()));
    renderOverview();
    expect(screen.getByText("Loading the overview…")).toBeInTheDocument();

    await figure(/Indicators tracked/);

    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual(["/api/v1/intel/overview"]);
    expect(screen.getByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Investigate an indicator" })).toHaveAttribute(
      "href",
      "/investigate",
    );
  });

  it("shows the headline numbers with how they changed, each leading to the list behind it", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    renderOverview();

    const tracked = await figure(/Indicators tracked/);
    expect(tracked).toHaveTextContent("12");
    expect(tracked).toHaveTextContent("3 new in the last 24 hours");
    expect(tracked).toHaveTextContent("+2 vs 1 in the previous 24 hours");
    expect(tracked).toHaveAttribute("href", "/indicators");

    const lookups = screen.getByRole("link", { name: /Lookups, last 24 hours/ });
    expect(lookups).toHaveTextContent("9");
    expect(lookups).toHaveTextContent("+5 vs 4 in the previous 24 hours");

    const highRisk = screen.getByRole("link", { name: /High-risk indicators/ });
    expect(highRisk).toHaveTextContent("3");
    expect(highRisk).toHaveAttribute("href", "/indicators?classification=high_risk&sort=risk");

    const critical = screen.getByRole("link", { name: /Critical indicators/ });
    expect(critical).toHaveTextContent("1");
    expect(critical).toHaveAttribute("href", "/indicators?classification=critical&sort=risk");

    const notAssessed = screen.getByRole("link", { name: /^Not assessed.*not the same as clean/ });
    expect(notAssessed).toHaveTextContent("1");
    expect(notAssessed).toHaveAttribute("href", "/indicators?classification=not_assessed");
  });

  it("says when the figures were fetched", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    renderOverview();

    expect(await screen.findByText(/Live · refreshed \d{2}:\d{2}:\d{2} UTC/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled();
  });

  it("draws every panel and lists the indicators behind the numbers", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    renderOverview();
    await figure(/Indicators tracked/);

    for (const title of [
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
    ]) {
      expect(screen.getByRole("heading", { level: 2, name: title })).toBeInTheDocument();
    }

    const top = within(panel("Highest risk"));
    expect(top.getByRole("link", { name: /203\.0\.113\.9/ })).toHaveAttribute(
      "href",
      `/indicators/${INDICATOR_ID}`,
    );
    const latest = within(panel("Latest investigations"));
    const unassessed = latest.getByRole("link", { name: /login\.example\.test/ });
    expect(unassessed).toHaveTextContent("Not assessed");
    expect(unassessed).toHaveTextContent("No score");
    expect(unassessed).not.toHaveTextContent("Informational");
  });

  it("marks the modules that are not built as planned", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    renderOverview();
    await figure(/Indicators tracked/);

    const modules = within(panel("Platform modules"));
    expect(modules.getAllByText("Planned")).toHaveLength(4);
    expect(modules.getByText("Live")).toBeInTheDocument();
  });

  it("opens the detail behind a bar, links to its indicators and closes with Escape", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    const user = userEvent.setup();
    renderOverview();
    await figure(/Indicators tracked/);

    const opener = within(panel("Malware families")).getByRole("button", { name: /^Examplebot/ });
    await user.click(opener);

    const dialog = screen.getByRole("dialog", { name: "Malware family: Examplebot" });
    expect(within(dialog).getByRole("link", { name: "203.0.113.9" })).toHaveAttribute(
      "href",
      `/indicators/${INDICATOR_ID}`,
    );
    expect(within(dialog).getByText("2")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("explains that a country is what the providers report, not where an attacker is", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    const user = userEvent.setup();
    renderOverview();
    await figure(/Indicators tracked/);

    await user.click(within(panel("Top countries")).getByRole("button", { name: /^Netherlands \(NL\)/ }));

    const dialog = screen.getByRole("dialog", { name: "Provider-reported country: Netherlands (NL)" });
    expect(dialog).toHaveTextContent("It is not where an attacker is");
  });

  it("links an ATT&CK technique to MITRE in a new tab without leaking the opener", async () => {
    serveOverview(() => jsonResponse(makeOverview()));
    const user = userEvent.setup();
    renderOverview();
    await figure(/Indicators tracked/);

    await user.click(within(panel("ATT&CK techniques")).getByRole("button", { name: /^T1059\.001/ }));

    const link = within(screen.getByRole("dialog")).getByRole("link", { name: /Read about T1059\.001/ });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/001/");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("flags simulated providers instead of calling them configured", async () => {
    serveOverview(() => jsonResponse(makeOverview({ providers: makeProviders(true) })));
    renderOverview();
    await figure(/Indicators tracked/);

    const providers = within(panel("Intelligence providers"));
    expect(providers.getAllByText("Simulated")).toHaveLength(2);
    expect(providers.queryByText("Configured")).not.toBeInTheDocument();
  });

  it("warns that every result will be Not assessed when no provider is configured", async () => {
    const providers = makeProviders().map((provider) => ({ ...provider, configured: false }));
    serveOverview(() => jsonResponse(makeOverview({ providers })));
    renderOverview();
    await figure(/Indicators tracked/);

    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("No threat-intelligence provider is configured");
    expect(note).toHaveTextContent("Not assessed");
  });

  it("says plainly when the aggregates were built from only the newest records", async () => {
    const base = makeOverview();
    serveOverview(() =>
      jsonResponse(
        makeOverview({
          scope: { ...base.scope, lookups_scanned: 20000, lookups_truncated: true, answers_truncated: true },
        }),
      ),
    );
    renderOverview();
    await figure(/Indicators tracked/);

    const notes = screen.getAllByRole("note").map((note) => note.textContent);
    expect(notes.join(" ")).toMatch(/Trends use only the 20,000 most recent lookups/);
    expect(notes.join(" ")).toMatch(/provider answers/);
  });

  it("invites a first investigation instead of drawing empty charts", async () => {
    serveOverview(() =>
      jsonResponse(
        makeOverview({
          kpis: {
            total_indicators: 0,
            new_indicators_24h: 0,
            new_indicators_prev_24h: 0,
            lookups_24h: 0,
            lookups_prev_24h: 0,
            high_risk_indicators: 0,
            critical_indicators: 0,
            not_assessed_indicators: 0,
          },
        }),
      ),
    );
    renderOverview();

    expect(await screen.findByText("No indicators have been investigated yet.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Investigate the first one" })).toHaveAttribute(
      "href",
      "/investigate",
    );
    expect(screen.queryByRole("heading", { name: "Threat pulse" })).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Intelligence providers" })).toBeInTheDocument();
  });

  it("reports a failure and loads the figures when asked to try again", async () => {
    serveOverview((call) => (call === 1 ? jsonResponse(FORBIDDEN, { status: 403 }) : jsonResponse(makeOverview())));
    const user = userEvent.setup();
    renderOverview();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Access denied");
    expect(alert).toHaveTextContent("Reference: req-403");

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    await figure(/Indicators tracked/);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("keeps the last figures on screen when a refresh fails", async () => {
    serveOverview((call) =>
      call === 1
        ? jsonResponse(makeOverview())
        : jsonResponse(
            { error: { code: "internal_error", message: "Something failed.", correlation_id: "req-500" } },
            { status: 500 },
          ),
    );
    const user = userEvent.setup();
    renderOverview();
    await figure(/Indicators tracked/);

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The overview could not be refreshed");
    expect(screen.getByRole("link", { name: /Indicators tracked/ })).toHaveTextContent("12");
    expect(screen.getByText(/Stale · refreshed/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeEnabled();
  });

  it("replaces the figures with newer ones after a refresh", async () => {
    serveOverview((call) =>
      jsonResponse(
        call === 1
          ? makeOverview()
          : makeOverview({ kpis: { ...makeOverview().kpis, total_indicators: 13 } }),
      ),
    );
    const user = userEvent.setup();
    renderOverview();
    expect(await figure(/Indicators tracked/)).toHaveTextContent("12");

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByRole("link", { name: /Indicators tracked.*13/ })).toBeInTheDocument();
  });
});
