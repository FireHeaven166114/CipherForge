import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";

import { type NetworkCall, apiError, networkApi, requested } from "../../test/networkApi";
import { HOST_IP, SCANNER_IP, SESSION_ID, makeFlow, makeFlowPage } from "../../test/networkFixtures";
import FlowsPanel from "./FlowsPanel";

type Props = ComponentProps<typeof FlowsPanel>;
type Handlers = Parameters<typeof networkApi>[0];
type FetchMock = ReturnType<typeof networkApi>;

function propsFor(overrides: Partial<Props> = {}): Props {
  return {
    session: { id: SESSION_ID, status: "completed", flows_stored: 40, flows_not_stored: 0 },
    intervalMs: 15_000,
    version: 0,
    ...overrides,
  };
}

function setup(overrides: Partial<Props> = {}, handlers: Handlers = {}) {
  const fetchMock = networkApi(handlers);
  const props = propsFor(overrides);
  const view = render(<FlowsPanel {...props} />);
  return {
    fetchMock,
    props,
    rerender: (next: Partial<Props>) => view.rerender(<FlowsPanel {...props} {...next} />),
  };
}

function listRequests(fetchMock: FetchMock): URL[] {
  return requested(fetchMock, "GET")
    .filter((address) => address.includes("/flows?"))
    .map((address) => new URL(address, "http://localhost"));
}

const flowTable = () => screen.findByRole("table", { name: "Finished flows of this session" });

const pagesOfFlows = ({ url }: NetworkCall) => {
  const offset = Number(url.searchParams.get("offset"));
  return makeFlowPage([makeFlow({ id: offset + 1, src_port: 41000 + offset })], 60);
};

function rowOf(source: string): HTMLElement {
  const row = screen.getByText(source).closest("tr");
  if (row === null) throw new Error(`No row for ${source}`);
  return row;
}

describe("FlowsPanel: the table", () => {
  it("asks for the first page of the session's flows", async () => {
    const { fetchMock } = setup();
    await flowTable();

    const [only, ...others] = listRequests(fetchMock);
    expect(others).toEqual([]);
    expect(only?.pathname).toBe(`/api/v1/network/sessions/${SESSION_ID}/flows`);
    expect(Object.fromEntries(only?.searchParams ?? [])).toEqual({ limit: "25", offset: "0" });
    expect(screen.getByRole("heading", { level: 2, name: "Flows" })).toBeInTheDocument();
  });

  it("has a column for everything the flow records", async () => {
    setup();
    const table = await flowTable();

    expect(within(table).getAllByRole("columnheader").map((header) => header.textContent)).toEqual([
      "Flow",
      "Protocol",
      "First seen",
      "Last seen",
      "Duration",
      "Packets out / in",
      "Data out / in",
      "TCP flags",
      "Ended by",
    ]);
  });

  it("shows one flow: who talked to whom, when, for how long, how much, and how it ended", async () => {
    setup({}, { flows: () => makeFlowPage([makeFlow({ packets_out: 12, packets_in: 3400, bytes_out: 2400, bytes_in: 5_000_000 })]) });
    await flowTable();

    const row = within(rowOf(`${SCANNER_IP}:40001`));
    expect(row.getByRole("rowheader")).toHaveTextContent(`${SCANNER_IP}:40001`);
    expect(row.getByRole("rowheader")).toHaveTextContent(`${HOST_IP}:22`);
    const [protocol, first, last, duration, packets, data, flags, endedBy] = row.getAllByRole("cell");
    expect(protocol).toHaveTextContent(/^TCP$/);
    // A date is followed by how long ago it was, which depends on the day the test runs.
    expect(first).toHaveTextContent(/^20-05-2026 02:00:05 PM IST/);
    expect(last).toHaveTextContent(/^20-05-2026 02:00:06 PM IST/);
    expect(duration).toHaveTextContent(/^1\.0 s$/);
    expect(packets).toHaveTextContent(/^12 \/ 3,400$/);
    expect(data).toHaveTextContent(/^2\.34 KB \/ 4\.77 MB$/);
    expect(flags).toHaveTextContent(/^SYN$/);
    expect(endedBy).toHaveTextContent(/^Idle$/);
  });

  it("writes an IPv6 endpoint with the address in brackets", async () => {
    setup(
      {},
      {
        flows: () =>
          makeFlowPage([
            makeFlow({ src_ip: "2001:db8::1", src_port: 5353, dst_ip: "2001:db8::2", dst_port: 443, protocol: "udp" }),
          ]),
      },
    );
    await flowTable();

    expect(screen.getByText("[2001:db8::1]:5353")).toBeInTheDocument();
    expect(screen.getByText("[2001:db8::2]:443")).toBeInTheDocument();
  });

  it("writes an endpoint without a port as the bare address", async () => {
    setup(
      {},
      { flows: () => makeFlowPage([makeFlow({ protocol: "icmp", src_port: null, dst_port: null, tcp_flags: null, tcp_flag_names: [] })]) },
    );
    await flowTable();

    const row = within(rowOf(SCANNER_IP));
    expect(row.getByText(HOST_IP)).toBeInTheDocument();
    expect(row.getByText("ICMP")).toBeInTheDocument();
  });

  it("names the TCP flags, and says why there are none", async () => {
    setup(
      {},
      {
        flows: () =>
          makeFlowPage([
            makeFlow({ id: 1, src_port: 1001, tcp_flags: 18, tcp_flag_names: ["SYN", "ACK"] }),
            makeFlow({ id: 2, src_port: 1002, tcp_flags: 0, tcp_flag_names: [] }),
            makeFlow({ id: 3, src_port: 1003, protocol: "udp", tcp_flags: null, tcp_flag_names: [] }),
          ]),
      },
    );
    await flowTable();

    expect(within(rowOf(`${SCANNER_IP}:1001`)).getByText("SYN ACK")).toBeInTheDocument();
    expect(within(rowOf(`${SCANNER_IP}:1002`)).getByText("None")).toBeInTheDocument();
    expect(within(rowOf(`${SCANNER_IP}:1003`)).getByText("Not TCP")).toBeInTheDocument();
  });

  it("puts the reasons a flow ended into words, including ones it does not know", async () => {
    setup(
      {},
      {
        flows: () =>
          makeFlowPage(
            ["idle", "evicted", "closed", "ended", "reset_by_peer"].map((reason, index) =>
              makeFlow({ id: index + 1, src_port: 2000 + index, close_reason: reason }),
            ),
          ),
      },
    );
    await flowTable();

    const reasons = ["idle", "evicted", "closed", "ended", "reset_by_peer"].map(
      (_, index) => within(rowOf(`${SCANNER_IP}:${2000 + index}`)).getAllByRole("cell").at(-1)?.textContent,
    );
    expect(reasons).toEqual(["Idle", "Evicted", "Closed", "Session ended", "Reset by peer"]);
  });

  it("keeps a wide table inside its own scrolling area, which the keyboard can reach and which has a name", async () => {
    setup();
    const table = await flowTable();

    const area = table.closest(".overflow-x-auto");
    expect(area).not.toBeNull();
    expect(area).toHaveAttribute("tabindex", "0");
    expect(screen.getByRole("region", { name: "Finished flows, scrolls sideways" })).toBe(area);
  });

  it("explains what a flow is and why open ones are not listed", () => {
    setup();

    expect(screen.getByText(/A flow is the packets of one conversation between two endpoints\./)).toBeInTheDocument();
    expect(screen.getByText(/Flows still open are counted under Active flows but not listed yet\./)).toBeInTheDocument();
  });
});

describe("FlowsPanel: flows that were counted but not stored", () => {
  it("warns that the table is incomplete and says by how many flows", async () => {
    setup({ session: { id: SESSION_ID, status: "completed", flows_stored: 5000, flows_not_stored: 1234 } });
    await flowTable();

    const notice = screen.getByRole("note");
    expect(notice).toHaveTextContent("Some finished flows are not listed");
    expect(notice).toHaveTextContent("1,234 finished flows went over the limit kept for one session.");
    expect(notice).toHaveTextContent("counted in the totals but not stored");
  });

  it("uses the singular for a single flow", async () => {
    setup({ session: { id: SESSION_ID, status: "completed", flows_stored: 5000, flows_not_stored: 1 } });
    await flowTable();

    expect(screen.getByRole("note")).toHaveTextContent(
      "1 finished flow went over the limit kept for one session. It is counted in the totals but not stored",
    );
  });

  it("shows no such warning when every finished flow was stored", async () => {
    setup();
    await flowTable();

    expect(screen.queryByRole("note")).not.toBeInTheDocument();
  });
});

describe("FlowsPanel: states", () => {
  it("says it is loading while the first answer is on its way", () => {
    setup({}, { flows: () => new Promise<never>(() => undefined) });

    expect(screen.getByText("Loading flows…")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("says so when a session has no finished flows yet", async () => {
    setup({}, { flows: () => makeFlowPage([]) });

    expect(await screen.findByText("No finished flows to list yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Flows pagination" })).not.toBeInTheDocument();
  });

  it("reports a failure to load, and the table comes back when the reader tries again", async () => {
    let calls = 0;
    setup(
      {},
      { flows: () => (++calls === 1 ? apiError(500, "internal_error", "The server could not list the flows.") : makeFlowPage()) },
    );

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("The server could not list the flows.");
    await userEvent.click(within(notice).getByRole("button", { name: "Try again" }));

    expect(await flowTable()).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("explains that a session which is not there cannot be read", async () => {
    setup({}, { flows: () => apiError(404, "session_not_found", "No such session.") });

    expect(await screen.findByRole("alert")).toHaveTextContent("Session not found");
  });

  it("keeps the table on screen, and says it is old, when a refresh fails", async () => {
    let calls = 0;
    const { rerender } = setup(
      {},
      { flows: () => (++calls === 1 ? makeFlowPage() : apiError(503, "internal_error", "Try later.")) },
    );
    await flowTable();

    rerender({ version: 1 });

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /The flows could not be refreshed\. The table below is from \d{2}:\d{2}:\d{2} [AP]M IST\./,
    );
    expect(screen.getByRole("table", { name: "Finished flows of this session" })).toBeInTheDocument();
  });
});

describe("FlowsPanel: paging", () => {
  it("asks for the next page by its offset, and goes back again", async () => {
    const { fetchMock } = setup({}, { flows: pagesOfFlows });
    expect(await screen.findByText(`${SCANNER_IP}:41000`)).toBeInTheDocument();
    expect(screen.getByText("Showing 1–25 of 60")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Flows pagination" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));

    expect(await screen.findByText(`${SCANNER_IP}:41025`)).toBeInTheDocument();
    const second = listRequests(fetchMock).at(-1);
    expect(second?.searchParams.get("offset")).toBe("25");
    expect(second?.searchParams.get("limit")).toBe("25");
    expect(screen.getByText("Showing 26–50 of 60")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(await screen.findByText(`${SCANNER_IP}:41050`)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Previous" }));
    expect(await screen.findByText(`${SCANNER_IP}:41025`)).toBeInTheDocument();
  });
});

describe("FlowsPanel: staying current", () => {
  it("reads the table again when the page asks for fresh data", async () => {
    const { fetchMock, rerender } = setup();
    await flowTable();
    expect(listRequests(fetchMock)).toHaveLength(1);

    rerender({ version: 1 });

    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(2));
  });

  it("reads the table again at once when more flows were stored, or the session settled", async () => {
    const { fetchMock, props, rerender } = setup({
      session: { id: SESSION_ID, status: "running", flows_stored: 3, flows_not_stored: 0 },
    });
    await flowTable();

    rerender({ session: { ...props.session, flows_stored: 4 } });
    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(2));

    rerender({ session: { ...props.session, flows_stored: 4, status: "completed" } });
    await waitFor(() => expect(listRequests(fetchMock)).toHaveLength(3));
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
        await vi.advanceTimersByTimeAsync(2000);
      });
      expect(listRequests(fetchMock)).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
