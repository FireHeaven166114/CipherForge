import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../services/apiClient";
import { type NetworkCall, apiError, networkApi, requested } from "../../test/networkApi";
import {
  ALERT_ID,
  SESSION_ID,
  makeAlert,
  makeAlertPage,
  makeCompletedEnrichment,
  makeRules,
} from "../../test/networkFixtures";
import AlertsPanel from "./AlertsPanel";

type Props = ComponentProps<typeof AlertsPanel>;
type Handlers = Parameters<typeof networkApi>[0];
type FetchMock = ReturnType<typeof networkApi>;

function propsFor(overrides: Partial<Props> = {}): Props {
  return {
    session: { id: SESSION_ID, status: "completed", alerts_total: 1 },
    intervalMs: 15_000,
    version: 0,
    rules: { status: "success", data: makeRules() },
    enrichmentEnabled: true,
    onEnriched: vi.fn(),
    ...overrides,
  };
}

function setup(overrides: Partial<Props> = {}, handlers: Handlers = {}) {
  const fetchMock = networkApi(handlers);
  const props = propsFor(overrides);
  const view = render(<AlertsPanel {...props} />);
  return {
    fetchMock,
    props,
    rerender: (next: Partial<Props>) => view.rerender(<AlertsPanel {...props} {...next} />),
    unmount: view.unmount,
  };
}

/** Every list request the panel has made, oldest first. */
function listRequests(fetchMock: FetchMock): URL[] {
  return requested(fetchMock, "GET")
    .filter((address) => address.includes("/alerts?"))
    .map((address) => new URL(address, "http://localhost"));
}

function lastRequest(fetchMock: FetchMock): URL {
  const all = listRequests(fetchMock);
  const last = all[all.length - 1];
  if (last === undefined) throw new Error("The panel has not asked for the list yet.");
  return last;
}

const pageOfSixty = ({ url }: NetworkCall) => {
  const offset = Number(url.searchParams.get("offset"));
  return makeAlertPage([makeAlert({ id: `alert-at-${offset}`, title: `Alert at offset ${offset}` })], 60);
};

const neverAnswers = () => new Promise<never>(() => undefined);

const alertList = () => screen.findByRole("list", { name: "Alerts" });

describe("AlertsPanel: the list", () => {
  it("asks for the first page of the session's alerts, with no filter", async () => {
    const { fetchMock } = setup();
    await alertList();

    const [only, ...others] = listRequests(fetchMock);
    expect(others).toEqual([]);
    expect(only?.pathname).toBe(`/api/v1/network/sessions/${SESSION_ID}/alerts`);
    expect(Object.fromEntries(only?.searchParams ?? [])).toEqual({ limit: "25", offset: "0" });
    expect(screen.getByRole("heading", { level: 2, name: "Alerts" })).toBeInTheDocument();
  });

  it("shows every alert with its severity as a word and its rule as a title", async () => {
    setup(
      {},
      {
        alerts: () =>
          makeAlertPage([
            makeAlert(),
            makeAlert({
              id: "alert-critical",
              severity: "critical",
              rule_id: "NET-006",
              title: "Repeated connections to suspicious ports",
            }),
          ]),
      },
    );
    const list = await alertList();

    expect(within(list).getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent)).toEqual([
      "Port scan",
      "Repeated connections to suspicious ports",
    ]);
    expect(within(list).getByText("High")).toBeInTheDocument();
    expect(within(list).getByText("Critical")).toBeInTheDocument();
  });

  it("says that it is loading while the first answer is on its way", () => {
    setup({}, { alerts: neverAnswers });

    expect(screen.getByText("Loading alerts…")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Alerts" })).not.toBeInTheDocument();
  });

  it("explains an empty session without calling the traffic safe", async () => {
    setup({}, { alerts: () => makeAlertPage([]) });

    expect(
      await screen.findByText(
        "No alerts were raised in this session. That says only that no rule fired: it is not a statement that the traffic is safe.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Alerts" })).not.toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Alerts pagination" })).not.toBeInTheDocument();
  });

  it("reports a failure to load, and the list comes back when the reader tries again", async () => {
    let calls = 0;
    setup(
      {},
      {
        alerts: () =>
          ++calls === 1 ? apiError(500, "internal_error", "The server could not list the alerts.") : makeAlertPage(),
      },
    );

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("The server could not list the alerts.");
    await userEvent.click(within(notice).getByRole("button", { name: "Try again" }));

    expect(await alertList()).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("AlertsPanel: filters", () => {
  it("filters by severity, one parameter for each, in the order low to critical", async () => {
    const { fetchMock } = setup();
    await alertList();
    const critical = screen.getByRole("button", { name: "Critical" });
    const high = screen.getByRole("button", { name: "High" });
    expect(critical).toHaveAttribute("aria-pressed", "false");

    await userEvent.click(critical);
    await alertList();
    expect(lastRequest(fetchMock).searchParams.getAll("severity")).toEqual(["critical"]);
    expect(critical).toHaveAttribute("aria-pressed", "true");

    await userEvent.click(high);
    await alertList();
    expect(lastRequest(fetchMock).searchParams.getAll("severity")).toEqual(["high", "critical"]);

    await userEvent.click(critical);
    await alertList();
    expect(lastRequest(fetchMock).searchParams.getAll("severity")).toEqual(["high"]);
    expect(critical).toHaveAttribute("aria-pressed", "false");
    expect(high).toHaveAttribute("aria-pressed", "true");
  });

  it("offers the four severities in a labelled group", async () => {
    setup();
    await alertList();

    const group = screen.getByRole("group", { name: "Severity" });
    expect(within(group).getAllByRole("button").map((button) => button.textContent)).toEqual([
      expect.stringContaining("Low"),
      expect.stringContaining("Medium"),
      expect.stringContaining("High"),
      expect.stringContaining("Critical"),
    ]);
  });

  it("filters by rule, and offers every detection rule by its id and title", async () => {
    const { fetchMock } = setup();
    await alertList();
    const select = screen.getByLabelText("Rule");

    const options = within(select).getAllByRole("option").map((option) => option.textContent);
    expect(options).toHaveLength(8);
    expect(options.slice(0, 2)).toEqual(["All rules", "NET-001 - Port scan"]);
    expect(lastRequest(fetchMock).searchParams.has("rule")).toBe(false);

    await userEvent.selectOptions(select, "NET-005");
    await alertList();

    expect(lastRequest(fetchMock).searchParams.get("rule")).toBe("NET-005");
    expect(select).toHaveValue("NET-005");
  });

  it("combines the two filters in one request", async () => {
    const { fetchMock } = setup();
    await alertList();

    await userEvent.click(screen.getByRole("button", { name: "Medium" }));
    await alertList();
    await userEvent.selectOptions(screen.getByLabelText("Rule"), "NET-002");
    await alertList();

    const query = lastRequest(fetchMock).searchParams;
    expect(query.getAll("severity")).toEqual(["medium"]);
    expect(query.get("rule")).toBe("NET-002");
  });

  it("lets the reader clear the filters, and shows the button only while one is set", async () => {
    const { fetchMock } = setup();
    await alertList();
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Low" }));
    await userEvent.selectOptions(screen.getByLabelText("Rule"), "NET-007");
    await alertList();
    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    await alertList();

    expect(Object.fromEntries(lastRequest(fetchMock).searchParams)).toEqual({ limit: "25", offset: "0" });
    expect(screen.getByRole("button", { name: "Low" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByLabelText("Rule")).toHaveValue("");
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("says that nothing matches when a filter leaves nothing, not that the session is quiet", async () => {
    setup(
      {},
      {
        alerts: ({ url }) => (url.searchParams.has("severity") ? makeAlertPage([]) : makeAlertPage()),
      },
    );
    await alertList();

    await userEvent.click(screen.getByRole("button", { name: "Critical" }));

    expect(await screen.findByText("No alerts match these filters.")).toBeInTheDocument();
    expect(screen.queryByText(/not a statement that the traffic is safe/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  });

  it("offers only 'All rules' while the rules are loading, and while they could not be loaded", () => {
    const { unmount } = setup({ rules: { status: "loading" } });
    expect(within(screen.getByLabelText("Rule")).getAllByRole("option")).toHaveLength(1);
    unmount();

    const error = new ApiError({ message: "No rules.", status: 500, code: "internal_error" });
    setup({ rules: { status: "error", error } });
    const options = within(screen.getByLabelText("Rule")).getAllByRole("option");
    expect(options.map((option) => option.textContent)).toEqual(["All rules"]);
  });

  it("keeps the chosen rule selected even if the list of rules goes away", async () => {
    const { rerender } = setup();
    await alertList();
    await userEvent.selectOptions(screen.getByLabelText("Rule"), "NET-003");
    await alertList();

    rerender({ rules: { status: "loading" } });

    const select = screen.getByLabelText("Rule");
    expect(select).toHaveValue("NET-003");
    expect(within(select).getByRole("option", { name: "NET-003" })).toBeInTheDocument();
  });
});

describe("AlertsPanel: paging", () => {
  it("shows the page the reader is on, and asks for the next one by its offset", async () => {
    const { fetchMock } = setup({}, { alerts: pageOfSixty });
    expect(await screen.findByText("Alert at offset 0")).toBeInTheDocument();
    expect(screen.getByText("Showing 1–25 of 60")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Alerts pagination" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));

    expect(await screen.findByText("Alert at offset 25")).toBeInTheDocument();
    expect(lastRequest(fetchMock).searchParams.get("offset")).toBe("25");
    expect(lastRequest(fetchMock).searchParams.get("limit")).toBe("25");
    expect(screen.getByText("Showing 26–50 of 60")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText("Alert at offset 50")).toBeInTheDocument();
    expect(screen.getByText("Showing 51–60 of 60")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText("Alert at offset 25")).toBeInTheDocument();
  });

  it("goes back to the first page when a filter changes", async () => {
    const { fetchMock } = setup({}, { alerts: pageOfSixty });
    await screen.findByText("Alert at offset 0");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Alert at offset 25");

    await userEvent.click(screen.getByRole("button", { name: "High" }));

    expect(await screen.findByText("Alert at offset 0")).toBeInTheDocument();
    expect(lastRequest(fetchMock).searchParams.get("offset")).toBe("0");
    expect(lastRequest(fetchMock).searchParams.getAll("severity")).toEqual(["high"]);
  });

  it("goes back to the first page when the rule changes, and when the filters are cleared", async () => {
    const { fetchMock } = setup({}, { alerts: pageOfSixty });
    await screen.findByText("Alert at offset 0");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Alert at offset 25");

    await userEvent.selectOptions(screen.getByLabelText("Rule"), "NET-001");
    await screen.findByText("Alert at offset 0");
    expect(lastRequest(fetchMock).searchParams.get("offset")).toBe("0");

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText("Alert at offset 25");
    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));

    await screen.findByText("Alert at offset 0");
    expect(lastRequest(fetchMock).searchParams.get("offset")).toBe("0");
  });
});

describe("AlertsPanel: staying current", () => {
  it("reads the list again when the page asks for fresh data", async () => {
    const { fetchMock, rerender } = setup();
    await alertList();
    expect(listRequests(fetchMock)).toHaveLength(1);

    rerender({ version: 1 });

    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(2));
  });

  it("reads the list again at once when the session gains an alert or settles", async () => {
    const { fetchMock, props, rerender } = setup({ session: { id: SESSION_ID, status: "running", alerts_total: 1 } });
    await alertList();

    rerender({ session: { ...props.session, alerts_total: 2 } });
    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(2));

    rerender({ session: { ...props.session, alerts_total: 2, status: "completed" } });
    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(3));
  });

  it("does not ask again when nothing about the session changed", async () => {
    const { fetchMock, props, rerender } = setup();
    await alertList();

    rerender({ session: { ...props.session } });
    await act(async () => {
      await Promise.resolve();
    });

    expect(listRequests(fetchMock)).toHaveLength(1);
  });

  it("keeps the list on screen, and says it is old, when a refresh fails", async () => {
    let calls = 0;
    const { rerender } = setup(
      {},
      {
        alerts: () => (++calls === 1 ? makeAlertPage() : apiError(503, "internal_error", "Try later.")),
      },
    );
    await alertList();

    rerender({ version: 1 });

    const warning = await screen.findByRole("alert");
    expect(warning).toHaveTextContent(
      /The alerts could not be refreshed\. The list below is from \d{2}:\d{2}:\d{2} [AP]M IST\./,
    );
    expect(screen.getByRole("list", { name: "Alerts" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Port scan" })).toBeInTheDocument();
  });

  it("polls at the interval it was given", async () => {
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    try {
      const { fetchMock } = setup({ intervalMs: 2000 });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(listRequests(fetchMock)).toHaveLength(1);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(1999);
      });
      expect(listRequests(fetchMock)).toHaveLength(1);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(1);
      });
      expect(listRequests(fetchMock)).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("AlertsPanel: looking an address up from an alert", () => {
  it("sends the lookup for that alert, tells the page, and reads the list again", async () => {
    let looked = false;
    const { fetchMock, props } = setup(
      {},
      {
        alerts: () => makeAlertPage([looked ? makeAlert({ enrichment: makeCompletedEnrichment() }) : makeAlert()]),
        enrich: () => {
          looked = true;
          return makeAlert({ enrichment: makeCompletedEnrichment() });
        },
      },
    );
    await alertList();

    await userEvent.click(screen.getByRole("button", { name: /^Look up address/ }));

    expect(await screen.findByText("Risk score 72 of 100")).toBeInTheDocument();
    expect(requested(fetchMock, "POST")).toEqual([`/api/v1/network/alerts/${ALERT_ID}/enrich`]);
    expect(props.onEnriched).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(2));
    expect(screen.queryByRole("button", { name: /^Look up address/ })).not.toBeInTheDocument();
  });

  it("offers no lookup while external enrichment is switched off", async () => {
    setup({ enrichmentEnabled: false });
    await alertList();

    expect(screen.queryByRole("button", { name: /^Look up address/ })).not.toBeInTheDocument();
  });

  it("keeps the list when a lookup fails, with the reason beside that alert", async () => {
    const { props } = setup(
      {},
      { enrich: () => apiError(409, "enrichment_disabled", "Enrichment is disabled.") },
    );
    await alertList();

    await userEvent.click(screen.getByRole("button", { name: /^Look up address/ }));

    expect(await screen.findByText("External enrichment is switched off")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Port scan" })).toBeInTheDocument();
    expect(props.onEnriched).not.toHaveBeenCalled();
  });
});
