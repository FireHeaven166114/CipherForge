import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { IDLE_POLL_MS, LIVE_POLL_MS } from "../features/network/polling";
import { hangingFetch, jsonResponse, stubFetch } from "../test/http";
import {
  type NetworkHandlers,
  apiError,
  networkApi,
  requested,
  runningStatus,
} from "../test/networkApi";
import {
  ALERT_ID,
  ENDED_AT,
  HOST_IP,
  OTHER_SESSION_ID,
  SCANNER_IP,
  SESSION_ID,
  makeAlert,
  makeAlertPage,
  makeBackend,
  makeCompletedEnrichment,
  makeEnrichment,
  makeExternalIp,
  makeFlow,
  makeFlowPage,
  makeInterface,
  makeInterfaces,
  makeNetworkStatus,
  makeRules,
  makeSession,
  makeSessionDetail,
  makeSessionPage,
} from "../test/networkFixtures";
import {
  API,
  NO_LOOKUPS,
  NO_TRAFFIC,
  OTHER_ALERT_ID,
  SESSION_LINK,
  SESSION_URL,
  type NetworkFetch,
  address,
  alertItem,
  cellTexts,
  flush,
  itemOf,
  lastRead,
  liveSession,
  openCapture,
  openPage,
  openSession,
  panel,
  reads,
  renderPage,
  sentTo,
  valueOf,
  withFakeClock,
} from "../test/networkPage";
import type { Enrichment, SessionDetail } from "../types/network";

const NO_DRIVER =
  "No packet-capture driver was found. Install Npcap (Windows) or libpcap (Linux), then restart the API.";
const DENIED =
  "The operating system refused packet capture to the CipherForge server process. Start the API with the privileges capture needs (see docs/network-monitoring.md).";

describe("NetworkPage: the frame", () => {
  it("shows the header and a loading note while the status is read", () => {
    stubFetch(hangingFetch());
    renderPage();

    expect(screen.getByRole("heading", { level: 1, name: "Network" })).toBeInTheDocument();
    expect(screen.getByText("MOD-05 · NETWORK MONITOR")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Loading the network monitor…");
    expect(screen.queryByRole("button", { name: "Refresh" })).not.toBeInTheDocument();
    expect(document.title).toBe("Network · CipherForge");
  });

  it("says so when the API cannot be reached, and tries again on request", async () => {
    const user = userEvent.setup();
    let reachable = false;
    networkApi({
      status: () => {
        if (!reachable) throw new TypeError("Failed to fetch");
        return makeNetworkStatus();
      },
    });
    renderPage();

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("Could not reach the CipherForge API.");
    expect(screen.queryByRole("heading", { level: 2, name: "Live capture" })).not.toBeInTheDocument();

    reachable = true;
    await user.click(within(notice).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { level: 2, name: "Live capture" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("tells a caller without the analyst role what is needed", async () => {
    networkApi({ status: () => apiError(403, "forbidden", "Forbidden.") });
    renderPage();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Network monitoring needs the security analyst role.",
    );
    expect(screen.queryByRole("heading", { level: 2, name: "Live capture" })).not.toBeInTheDocument();
  });

  it("shows when the status was read, in IST, and reads every list again on Refresh", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession();
    const lists = [
      `${API}/status`,
      `${API}/sessions`,
      SESSION_URL,
      `${SESSION_URL}/alerts`,
      `${SESSION_URL}/flows`,
    ];
    await waitFor(() => {
      for (const path of lists) expect(reads(fetchMock, path)).toBe(1);
    });
    expect(screen.getByText(/^Live · refreshed \d{2}:\d{2}:\d{2} (AM|PM) IST$/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => {
      for (const path of lists) expect(reads(fetchMock, path)).toBe(2);
    });
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  it("keeps what it has and warns when a refresh fails", async () => {
    const user = userEvent.setup();
    let failing = false;
    await openPage({
      status: () => (failing ? apiError(500, "internal_error", "The status failed.") : makeNetworkStatus()),
    });

    failing = true;
    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /The capture status could not be refreshed\. What is shown is from \d{2}:\d{2}:\d{2} (AM|PM) IST\./,
    );
    expect(screen.getByText(/^Stale · refreshed /)).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 2, name: "Live capture" })).toBeInTheDocument();
  });
});

describe("NetworkPage: the capture control", () => {
  it("is ready: Start can be pressed and Stop cannot", async () => {
    await openCapture();
    const live = panel("Live capture");

    expect(within(live).getByText("Ready")).toBeInTheDocument();
    expect(within(live).getByText("Ready. Choose an interface and press Start.")).toBeInTheDocument();
    expect(within(live).getByRole("button", { name: "Start capture" })).not.toHaveAttribute("aria-disabled");
    expect(within(live).getByRole("button", { name: "Stop capture" })).toHaveAttribute("aria-disabled", "true");
    expect(valueOf(live, "Capture backend")).toHaveTextContent("npcap");
    expect(valueOf(live, "Capture backend")).toHaveTextContent("Available");
  });

  it("says live capture is not available when no capture library was found, and still takes a file", async () => {
    const user = userEvent.setup();
    const fetchMock = await openCapture({
      status: () =>
        makeNetworkStatus({
          state: "not_configured",
          backend: makeBackend({ name: "none", available: false }),
          error_code: "capture_backend_missing",
          message: NO_DRIVER,
        }),
      interfaces: () => makeInterfaces([], makeBackend({ name: "none", available: false })),
    });
    const live = panel("Live capture");

    expect(within(live).getByText("Not configured")).toBeInTheDocument();
    expect(within(live).getByText("Live capture is not available")).toBeInTheDocument();
    expect(within(live).getByText(/Npcap on Windows, or libpcap on Linux and macOS/)).toBeInTheDocument();
    expect(within(live).getByText(/Analysing a saved PCAP file may still work\./)).toBeInTheDocument();
    expect(within(live).getByText(NO_DRIVER)).toBeInTheDocument();
    expect(valueOf(live, "Capture backend")).toHaveTextContent("Not available");
    expect(within(live).getByText(/No capture interfaces found\./)).toBeInTheDocument();
    const start = within(live).getByRole("button", { name: "Start capture" });
    expect(start).toHaveAttribute("aria-disabled", "true");
    expect(start).toHaveAccessibleDescription("Live capture is not available on this server.");
    expect(within(panel("Analyse a capture file")).getByLabelText("Capture file")).toBeEnabled();

    await user.click(start);
    expect(requested(fetchMock, "POST")).toEqual([]);
  });

  it("explains a refusal by the operating system, and names the guide as plain text", async () => {
    await openCapture({
      status: () =>
        makeNetworkStatus({
          state: "permission_denied",
          error_code: "capture_permission_denied",
          message: DENIED,
        }),
    });
    const live = panel("Live capture");

    expect(within(live).getByText("Permission denied")).toBeInTheDocument();
    expect(within(live).getByText("Packet capture was refused by the operating system.")).toBeInTheDocument();
    expect(within(live).getByText("The operating system refused packet capture")).toBeInTheDocument();
    expect(within(live).getByText(/for the account that runs the CipherForge API/)).toBeInTheDocument();
    expect(within(live).getByText(/The privileges capture needs differ by platform/)).toBeInTheDocument();
    expect(within(live).getAllByText(/docs\/network-monitoring\.md/).length).toBeGreaterThan(0);
    expect(within(live).queryByRole("link")).not.toBeInTheDocument();
  });

  it("shows the message of a capture that failed", async () => {
    await openCapture({
      status: () =>
        makeNetworkStatus({
          state: "failed",
          error_code: "capture_failed",
          message: "The capture stopped because the interface went away.",
        }),
    });
    const live = panel("Live capture");

    expect(within(live).getByText("Failed")).toBeInTheDocument();
    expect(within(live).getByText("The last capture failed.")).toBeInTheDocument();
    expect(within(live).getByText("The last capture failed")).toBeInTheDocument();
    expect(within(live).getByText("The capture stopped because the interface went away.")).toBeInTheDocument();
  });

  it("keeps Start unavailable while someone else's capture holds the slot, and still takes a file", async () => {
    const user = userEvent.setup();
    const fetchMock = await openCapture({ status: () => makeNetworkStatus({ busy: true }) });
    const live = panel("Live capture");

    expect(within(live).getByText("Another capture is running")).toBeInTheDocument();
    expect(within(live).getByText(/Only one live capture can run at a time/)).toBeInTheDocument();
    const start = within(live).getByRole("button", { name: "Start capture" });
    expect(start).toHaveAttribute("aria-disabled", "true");
    expect(start).toHaveAccessibleDescription("Another capture holds the single capture slot.");
    expect(within(live).getByRole("button", { name: "Stop capture" })).toHaveAttribute("aria-disabled", "true");
    expect(within(panel("Analyse a capture file")).getByLabelText("Capture file")).toBeEnabled();

    await user.click(start);
    expect(requested(fetchMock, "POST")).toEqual([]);
  });

  it("shows a stopped capture and lets another one start", async () => {
    await openCapture({
      status: () => makeNetworkStatus({ state: "stopped", interface: "eth0", session_id: SESSION_ID }),
    });
    const live = panel("Live capture");

    expect(within(live).getByText("Stopped")).toBeInTheDocument();
    expect(within(live).getByText("The capture is stopped.")).toBeInTheDocument();
    expect(within(live).getByText("Capture stopped")).toBeInTheDocument();
    expect(within(live).getByRole("button", { name: "Start capture" })).not.toHaveAttribute("aria-disabled");
    expect(within(live).getByRole("button", { name: "Stop capture" })).toHaveAttribute("aria-disabled", "true");
  });

  it("locks the interface while a capture runs, and offers Stop", async () => {
    await openCapture({ status: () => runningStatus(), session: () => liveSession(), ...NO_TRAFFIC });
    const live = panel("Live capture");

    expect(within(live).getByText("Running")).toBeInTheDocument();
    expect(
      within(live).getByText("Capturing on eth0. The figures below update as packets arrive."),
    ).toBeInTheDocument();
    const select = within(live).getByRole("combobox", { name: "Interface" });
    expect(select).toBeDisabled();
    expect(select).toHaveValue("eth0");
    expect(valueOf(live, "Capture interface")).toHaveTextContent("eth0");
    expect(within(live).getByRole("button", { name: "Stop capture" })).not.toHaveAttribute("aria-disabled");
    const start = within(live).getByRole("button", { name: "Start capture" });
    expect(start).toHaveAttribute("aria-disabled", "true");
    expect(start).toHaveAccessibleDescription("A capture is already running. Stop it to start another.");
  });
});

describe("NetworkPage: the interfaces", () => {
  it("lists them by name and description, and shows the addresses of the chosen one", async () => {
    const user = userEvent.setup();
    await openCapture();
    const live = panel("Live capture");
    const select = within(live).getByRole("combobox", { name: "Interface" });

    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "eth0 - Ethernet adapter",
      "lo - Loopback",
    ]);
    expect(select).toHaveValue("eth0");
    expect(within(live).getByText(`Addresses: ${HOST_IP}`)).toBeInTheDocument();

    await user.selectOptions(select, "lo");

    expect(select).toHaveValue("lo");
    expect(within(live).getByText("Addresses: 127.0.0.1")).toBeInTheDocument();
  });

  it("says when there is none to capture on, and disables Start", async () => {
    await openCapture({ interfaces: () => makeInterfaces([]) });
    const live = panel("Live capture");

    expect(
      within(live).getByText("No capture interfaces found. Refresh the list after connecting or enabling one."),
    ).toBeInTheDocument();
    expect(within(live).getByRole("combobox", { name: "Interface" })).toBeDisabled();
    const start = within(live).getByRole("button", { name: "Start capture" });
    expect(start).toHaveAttribute("aria-disabled", "true");
    expect(start).toHaveAccessibleDescription("There is no interface to capture on.");
  });

  it("asks the server to look again on Refresh interfaces, and lists what it finds", async () => {
    const user = userEvent.setup();
    const fetchMock = await openCapture({
      interfaces: ({ url }) =>
        makeInterfaces(
          url.searchParams.get("refresh") === "true"
            ? [makeInterface(), makeInterface({ id: "wlan0", name: "wlan0", description: "Wi-Fi", addresses: [] })]
            : [makeInterface()],
        ),
    });
    const live = panel("Live capture");
    expect(within(live).queryByRole("option", { name: "wlan0 - Wi-Fi" })).not.toBeInTheDocument();

    await user.click(within(live).getByRole("button", { name: "Refresh interfaces" }));

    expect(await within(live).findByRole("option", { name: "wlan0 - Wi-Fi" })).toBeInTheDocument();
    expect(requested(fetchMock)).toContain(`${API}/interfaces?refresh=true`);
  });

  it("reports an interface list that could not be read, and reads it again on request", async () => {
    const user = userEvent.setup();
    let failing = true;
    await openPage({
      interfaces: () => (failing ? apiError(500, "internal_error", "The interface list failed.") : makeInterfaces()),
    });
    const live = panel("Live capture");

    const notice = await within(live).findByRole("alert");
    expect(notice).toHaveTextContent("The interface list failed.");

    failing = false;
    await user.click(within(notice).getByRole("button", { name: "Try again" }));

    expect(await within(live).findByRole("option", { name: "eth0 - Ethernet adapter" })).toBeInTheDocument();
    expect(within(live).queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("NetworkPage: starting and stopping", () => {
  it("starts a capture on the chosen interface and follows it", async () => {
    const user = userEvent.setup();
    let started = false;
    const fetchMock = await openCapture({
      status: () => (started ? runningStatus({ interface: "lo" }) : makeNetworkStatus()),
      start: () => {
        started = true;
        return runningStatus({ interface: "lo" });
      },
      session: () => liveSession({ interface: "lo", source_label: "lo" }),
      ...NO_TRAFFIC,
    });
    const live = panel("Live capture");

    await user.selectOptions(within(live).getByRole("combobox", { name: "Interface" }), "lo");
    await user.click(within(live).getByRole("button", { name: "Start capture" }));

    expect(
      await within(live).findByText("Capturing on lo. The figures below update as packets arrive."),
    ).toBeInTheDocument();
    const sent = sentTo(fetchMock, `${API}/capture/start`);
    expect(sent?.body).toBe(JSON.stringify({ interface: "lo" }));
    expect(within(live).getByText("Running")).toBeInTheDocument();
    expect(within(live).getByRole("combobox", { name: "Interface" })).toBeDisabled();
    expect(await screen.findByRole("heading", { level: 2, name: "Session summary" })).toBeInTheDocument();
    expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("Live capture: lo");
    expect(address()).toBe("/network");
  });

  it("watches the new capture, not a session that was open from the history", async () => {
    const user = userEvent.setup();
    let started = false;
    await openCapture({
      status: () => (started ? runningStatus() : makeNetworkStatus()),
      start: () => {
        started = true;
        return runningStatus();
      },
      sessions: () => makeSessionPage([makeSession({ id: OTHER_SESSION_ID, source_label: "old.pcap" })]),
      session: ({ id }) =>
        id === SESSION_ID ? liveSession() : makeSessionDetail({ id: OTHER_SESSION_ID, source_label: "old.pcap" }),
      ...NO_TRAFFIC,
    });
    await user.click(await screen.findByRole("button", { name: "View session old.pcap" }));
    await waitFor(() => expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("Capture file: old.pcap"));
    expect(address()).toBe(`/network?session=${OTHER_SESSION_ID}`);

    await user.click(within(panel("Live capture")).getByRole("button", { name: "Start capture" }));

    await waitFor(() => expect(address()).toBe("/network"));
    await waitFor(() => expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("Live capture: eth0"));
    expect(screen.queryByText(/You are looking at a session you picked/)).not.toBeInTheDocument();
  });

  it("stops the capture, and keeps its results", async () => {
    const user = userEvent.setup();
    let stopped = false;
    const ended = makeNetworkStatus({ state: "stopped", interface: "eth0", session_id: SESSION_ID });
    const fetchMock = await openCapture({
      status: () => (stopped ? ended : runningStatus()),
      stop: () => {
        stopped = true;
        return ended;
      },
      session: () => (stopped ? liveSession({ status: "completed", ended_at: ENDED_AT }) : liveSession()),
      ...NO_TRAFFIC,
    });
    const live = panel("Live capture");

    await user.click(within(live).getByRole("button", { name: "Stop capture" }));

    expect(await within(live).findByText("The capture is stopped.")).toBeInTheDocument();
    expect(sentTo(fetchMock, `${API}/capture/stop`)).toBeDefined();
    expect(within(live).getByText("Stopped")).toBeInTheDocument();
    expect(within(live).getByText("Capture stopped")).toBeInTheDocument();
    expect(within(live).getByRole("button", { name: "Start capture" })).not.toHaveAttribute("aria-disabled");
    expect(within(live).getByRole("button", { name: "Stop capture" })).toHaveAttribute("aria-disabled", "true");
    expect(await within(panel("Session summary")).findByText("Completed")).toBeInTheDocument();
  });

  it.each([
    ["capture_permission_denied", 503, "Packet capture not permitted"],
    ["capture_already_running", 409, "A capture is already running"],
    ["interface_unavailable", 503, "Interface unavailable"],
  ] as const)("explains why a start was refused (%s)", async (code, status, title) => {
    const user = userEvent.setup();
    await openCapture({ start: () => apiError(status, code) });
    const live = panel("Live capture");

    await user.click(within(live).getByRole("button", { name: "Start capture" }));

    expect(await within(live).findByRole("alert")).toHaveTextContent(title);
    expect(within(live).getByText("Ready. Choose an interface and press Start.")).toBeInTheDocument();
    expect(address()).toBe("/network");
  });

  it("explains why a stop was refused", async () => {
    const user = userEvent.setup();
    await openCapture({
      status: () => runningStatus(),
      stop: () => apiError(409, "capture_not_running"),
      session: () => liveSession(),
      ...NO_TRAFFIC,
    });
    const live = panel("Live capture");

    await user.click(within(live).getByRole("button", { name: "Stop capture" }));

    expect(await within(live).findByRole("alert")).toHaveTextContent("No capture to stop");
  });

  it("does not send a second command while one is on its way", async () => {
    const user = userEvent.setup();
    let started = false;
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchMock = await openCapture({
      status: () => (started ? runningStatus() : makeNetworkStatus()),
      start: async () => {
        await gate;
        started = true;
        return runningStatus();
      },
      session: () => liveSession(),
      ...NO_TRAFFIC,
    });
    const live = panel("Live capture");

    await user.click(within(live).getByRole("button", { name: "Start capture" }));
    const busy = await within(live).findByRole("button", { name: "Starting…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await user.click(busy);

    expect(requested(fetchMock, "POST")).toEqual([`${API}/capture/start`]);
    release();
    expect(await within(live).findByText(/^Capturing on eth0/)).toBeInTheDocument();
  });
});

describe("NetworkPage: following a capture", () => {
  withFakeClock();

  async function open(handlers: NetworkHandlers = {}, url = "/network"): Promise<NetworkFetch> {
    const fetchMock = networkApi(handlers);
    renderPage(url);
    await flush();
    return fetchMock;
  }

  const summary = () => panel("Session summary");

  it("asks again every two seconds while a capture runs, and the figures follow", async () => {
    let packets = 2_500;
    const fetchMock = await open({
      status: () => runningStatus(),
      session: () => liveSession({ packets_total: packets, bytes_total: packets * 2 }),
      ...NO_TRAFFIC,
    });
    expect(valueOf(summary(), "Packets")).toHaveTextContent(/^2,500$/);
    expect(valueOf(summary(), "Data")).toHaveTextContent(/^4\.88 KB$/);
    expect(screen.getByText("Live · refreshed 02:05:00 PM IST")).toBeInTheDocument();

    packets = 3_600;
    await flush(LIVE_POLL_MS - 1);
    expect(reads(fetchMock, `${API}/status`)).toBe(1);
    expect(reads(fetchMock, SESSION_URL)).toBe(1);

    await flush(1);

    expect(reads(fetchMock, `${API}/status`)).toBe(2);
    expect(reads(fetchMock, SESSION_URL)).toBe(2);
    expect(reads(fetchMock, `${API}/sessions`)).toBe(2);
    expect(valueOf(summary(), "Packets")).toHaveTextContent(/^3,600$/);
    expect(valueOf(summary(), "Data")).toHaveTextContent(/^7\.03 KB$/);
    expect(screen.getByText("Live · refreshed 02:05:02 PM IST")).toBeInTheDocument();
  });

  it("checks quietly every fifteen seconds while nothing runs", async () => {
    const fetchMock = await open();

    await flush(IDLE_POLL_MS - 1);
    expect(reads(fetchMock, `${API}/status`)).toBe(1);
    expect(reads(fetchMock, `${API}/sessions`)).toBe(1);

    await flush(1);

    expect(reads(fetchMock, `${API}/status`)).toBe(2);
    expect(reads(fetchMock, `${API}/sessions`)).toBe(2);
    expect(screen.getByText("Live · refreshed 02:05:15 PM IST")).toBeInTheDocument();
  });

  it("asks every two seconds while an analysis runs, even one that started elsewhere", async () => {
    const fetchMock = await open({
      status: () => makeNetworkStatus({ analysis: { running: true, session_id: null, max_upload_mb: 50 } }),
    });

    await flush(LIVE_POLL_MS);

    expect(reads(fetchMock, `${API}/status`)).toBe(2);
    expect(reads(fetchMock, `${API}/sessions`)).toBe(2);
  });

  it("slows down again once the capture has ended", async () => {
    let ended = false;
    const stopped = makeNetworkStatus({ state: "stopped", interface: "eth0", session_id: SESSION_ID });
    const fetchMock = await open({
      status: () => (ended ? stopped : runningStatus()),
      session: () => (ended ? liveSession({ status: "completed", ended_at: ENDED_AT }) : liveSession()),
      ...NO_TRAFFIC,
    });

    ended = true;
    await flush(LIVE_POLL_MS);
    expect(reads(fetchMock, `${API}/status`)).toBe(2);
    expect(within(panel("Live capture")).getByText("The capture is stopped.")).toBeInTheDocument();
    expect(within(summary()).getByText("Completed")).toBeInTheDocument();

    await flush(IDLE_POLL_MS - 1);
    expect(reads(fetchMock, `${API}/status`)).toBe(2);
    expect(reads(fetchMock, SESSION_URL)).toBe(2);

    await flush(1);
    expect(reads(fetchMock, `${API}/status`)).toBe(3);
    expect(reads(fetchMock, SESSION_URL)).toBe(3);
  });

  it("keeps the last figures and says so when a poll fails, then recovers on the next one", async () => {
    let failing = false;
    await open({
      status: () => runningStatus(),
      session: () => (failing ? apiError(500, "internal_error", "The session failed.") : liveSession()),
      ...NO_TRAFFIC,
    });

    failing = true;
    await flush(LIVE_POLL_MS);

    expect(screen.getByRole("alert")).toHaveTextContent(
      "The session could not be refreshed. The figures below are from 02:05:00 PM IST.",
    );
    expect(valueOf(summary(), "Packets")).toHaveTextContent(/^120$/);

    failing = false;
    await flush(LIVE_POLL_MS);

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("NetworkPage: the session on show", () => {
  it("opens the session named in the address and sums it up, with its times in IST", async () => {
    await openSession();
    const summary = panel("Session summary");

    expect(address()).toBe(SESSION_LINK);
    expect(screen.getByText("You are looking at a session you picked.")).toBeInTheDocument();
    expect(within(summary).getByText("Completed")).toBeInTheDocument();
    expect(valueOf(summary, "Source")).toHaveTextContent("Capture file: sample.pcap");
    expect(valueOf(summary, "Capture started")).toHaveTextContent("20-05-2026 02:00:00 PM IST");
    expect(valueOf(summary, "Capture ended")).toHaveTextContent("20-05-2026 02:01:30 PM IST");
    expect(valueOf(summary, "First packet")).toHaveTextContent("20-05-2026 02:00:05 PM IST");
    expect(valueOf(summary, "Last packet")).toHaveTextContent("20-05-2026 02:00:50 PM IST");
    expect(valueOf(summary, "Duration")).toHaveTextContent(/^1 min 30 s$/);
    expect(valueOf(summary, "Packets")).toHaveTextContent(/^40$/);
    expect(valueOf(summary, "Data")).toHaveTextContent(/^2\.34 KB$/);
    expect(valueOf(summary, "Active flows")).toHaveTextContent(/^0$/);
    expect(valueOf(summary, "Flows seen")).toHaveTextContent(/^40$/);
    expect(valueOf(summary, "Alerts")).toHaveTextContent(/^1$/);
    expect(valueOf(summary, "Packets dropped")).toHaveTextContent(/^0$/);
    expect(valueOf(summary, "Alerts by rule")).toHaveTextContent("NET-001: 1");
    expect(within(summary).queryByText("Some traffic was not analysed")).not.toBeInTheDocument();
  });

  it("shows a live session as still running, and does not allow deleting it", async () => {
    await openSession({ status: () => runningStatus(), session: () => liveSession(), ...NO_TRAFFIC }, "/network");
    const summary = panel("Session summary");

    expect(within(summary).getByText("Running")).toBeInTheDocument();
    expect(valueOf(summary, "Source")).toHaveTextContent("Live capture: eth0");
    expect(valueOf(summary, "Capture ended")).toHaveTextContent("Still running");
    expect(valueOf(summary, "Duration")).toHaveTextContent(/^12 s$/);
    expect(valueOf(summary, "Active flows")).toHaveTextContent(/^3$/);
    const remove = within(summary).getByRole("button", { name: "Delete session" });
    expect(remove).toHaveAttribute("aria-disabled", "true");
    expect(remove).toHaveAccessibleDescription("A session cannot be deleted while it is running.");
    expect(screen.queryByText(/You are looking at a session you picked/)).not.toBeInTheDocument();
  });

  it("is honest about what the totals leave out", async () => {
    await openSession({
      session: () =>
        makeSessionDetail({
          packets_dropped: 12,
          non_ip_packets: 3,
          malformed_packets: 2,
          flows_evicted: 4,
          flows_stored: 40,
          flows_not_stored: 7,
          alerts_suppressed: 5,
          alerts_lost: 1,
          talkers_truncated: true,
        }),
    });
    const summary = panel("Session summary");
    const counters = within(summary).getByRole("region", { name: "What the totals leave out" });

    expect(valueOf(summary, "Packets dropped")).toHaveTextContent(/^12$/);
    expect(within(summary).getByText("Some traffic was not analysed")).toBeInTheDocument();
    expect(Array.from(counters.querySelectorAll("dt"), (term) => term.textContent)).toEqual([
      "Packets dropped by the monitor▲ 12",
      "Non-IP packets3",
      "Malformed packets▲ 2",
      "Flows closed early▲ 4",
      "Flows stored40",
      "Flows not stored▲ 7",
      "Repeat alerts suppressed5",
      "Alerts lost▲ 1",
      "Top talkers truncated▲ Yes",
    ]);
    expect(within(counters).getByText(/The monitor's bounded queue overflowed/)).toBeInTheDocument();
    expect(within(counters).getByText(/This is not the operating system's drop count/)).toBeInTheDocument();
    expect(screen.getByText("These lists may undercount")).toBeInTheDocument();
    expect(screen.getByText("Some finished flows are not listed")).toBeInTheDocument();
    expect(screen.getByText(/7 finished flows went over the limit kept for one session\./)).toBeInTheDocument();
  });

  it("does not read a zero as proof that nothing was missed", async () => {
    await openSession();
    const counters = within(panel("Session summary")).getByRole("region", {
      name: "What the totals leave out",
    });

    expect(Array.from(counters.querySelectorAll("dt"), (term) => term.textContent)).toEqual([
      "Packets dropped by the monitor0",
      "Non-IP packets0",
      "Malformed packets0",
      "Flows closed early0",
      "Flows stored40",
      "Flows not stored0",
      "Repeat alerts suppressed0",
      "Alerts lost0",
      "Top talkers truncatedNo",
    ]);
    expect(within(counters).getByText(/so zero does not prove none were lost/)).toBeInTheDocument();
    expect(screen.queryByText("These lists may undercount")).not.toBeInTheDocument();
    expect(screen.queryByText("Some finished flows are not listed")).not.toBeInTheDocument();
  });

  it("shows the protocol mix and the top talkers, each with a table behind the chart", async () => {
    await openSession({
      session: () =>
        makeSessionDetail({
          protocols: [
            { protocol: "tcp", packets: 30, bytes: 1_800 },
            { protocol: "udp", packets: 8, bytes: 500 },
            { protocol: "icmp", packets: 2, bytes: 120 },
          ],
          top_sources: [
            { address: SCANNER_IP, packets: 30, bytes: 1_800 },
            { address: "198.51.100.7", packets: 10, bytes: 600 },
          ],
          top_destinations: [{ address: HOST_IP, packets: 40, bytes: 2_400 }],
        }),
    });
    const protocols = panel("Protocol distribution");
    const talkers = panel("Top talkers");

    expect(within(protocols).getByLabelText("TCP: 30 packets, 75%")).toBeInTheDocument();
    expect(within(protocols).getByLabelText("UDP: 8 packets, 20%")).toBeInTheDocument();
    expect(cellTexts(within(protocols).getByRole("table", { name: "Packets and data by protocol", hidden: true }))).toEqual([
      ["Protocol", "Packets", "Data"],
      ["TCP", "30", "1.76 KB"],
      ["UDP", "8", "500 B"],
      ["ICMP", "2", "120 B"],
    ]);
    expect(within(talkers).getByRole("heading", { level: 3, name: "Top source IPs" })).toBeInTheDocument();
    expect(within(talkers).getByRole("heading", { level: 3, name: "Top destination IPs" })).toBeInTheDocument();
    expect(
      cellTexts(within(talkers).getByRole("table", { name: "Top source IPs, with packets and data", hidden: true })),
    ).toEqual([
      ["Address", "Packets", "Data"],
      [SCANNER_IP, "30", "1.76 KB"],
      ["198.51.100.7", "10", "600 B"],
    ]);
    expect(
      cellTexts(
        within(talkers).getByRole("table", { name: "Top destination IPs, with packets and data", hidden: true }),
      ),
    ).toEqual([
      ["Address", "Packets", "Data"],
      [HOST_IP, "40", "2.34 KB"],
    ]);
  });

  it("says what an empty session means, without calling it safe", async () => {
    await openSession({
      session: () =>
        makeSessionDetail({
          alerts_total: 0,
          alerts_by_rule: {},
          protocols: [],
          top_sources: [],
          top_destinations: [],
          external_ips: [],
          enrichment: NO_LOOKUPS,
        }),
      ...NO_TRAFFIC,
    });

    expect(await screen.findByText("No alerts were raised in this session. That says only that no rule fired: it is not a statement that the traffic is safe.")).toBeInTheDocument();
    expect(await screen.findByText("No finished flows to list yet.")).toBeInTheDocument();
    expect(within(panel("External IP addresses")).getByText("No public addresses were seen in this session's traffic.")).toBeInTheDocument();
    expect(within(panel("Protocol distribution")).getByText("No packets have been analysed yet.")).toBeInTheDocument();
    expect(within(panel("Top talkers")).getByText("No source addresses yet.")).toBeInTheDocument();
    expect(within(panel("Top talkers")).getByText("No destination addresses yet.")).toBeInTheDocument();
  });

  it("leaves a picked session with Clear selection", async () => {
    const user = userEvent.setup();
    await openSession();

    await user.click(screen.getByRole("button", { name: "Clear selection" }));

    expect(address()).toBe("/network");
    expect(await screen.findByText("No session is open yet.")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { level: 2, name: "Session summary" })).not.toBeInTheDocument();
  });

  it("offers the way back to the live capture when another session was picked", async () => {
    const user = userEvent.setup();
    await openSession(
      {
        status: () => runningStatus(),
        session: ({ id }) =>
          id === SESSION_ID ? liveSession() : makeSessionDetail({ id: OTHER_SESSION_ID, source_label: "old.pcap" }),
        ...NO_TRAFFIC,
      },
      `/network?session=${OTHER_SESSION_ID}`,
    );
    expect(screen.getByText("You are looking at a session you picked, not at your live capture.")).toBeInTheDocument();
    expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("Capture file: old.pcap");

    await user.click(screen.getByRole("button", { name: "Back to the live capture" }));

    expect(address()).toBe("/network");
    await waitFor(() => expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("Live capture: eth0"));
  });

  it("ignores an address it does not understand, and says so", async () => {
    const fetchMock = await openPage({}, "/network?session=not-a-session");

    expect(screen.getByText("That session link was not understood")).toBeInTheDocument();
    expect(screen.getByText("No session is open yet.")).toBeInTheDocument();
    expect(requested(fetchMock).some((url) => url.startsWith(`${API}/sessions/`))).toBe(false);
  });

  it("explains a session that does not exist, and lets go of it", async () => {
    const user = userEvent.setup();
    await openPage({ session: () => apiError(404, "session_not_found") }, SESSION_LINK);
    await screen.findByRole("heading", { level: 2, name: "Session" });
    const workspace = panel("Session");

    expect(await within(workspace).findByRole("alert")).toHaveTextContent(
      "That session no longer exists, or it belongs to another account.",
    );
    await user.click(within(workspace).getByRole("button", { name: "Clear selection" }));

    expect(address()).toBe("/network");
    expect(await screen.findByText("No session is open yet.")).toBeInTheDocument();
  });

  it("explains how to get started when there is nothing to show yet", async () => {
    await openPage({ sessions: () => makeSessionPage([]) });

    expect(
      await screen.findByText("No sessions yet. Start a live capture or analyse a PCAP file, and it will be listed here."),
    ).toBeInTheDocument();
    const workspace = panel("Session");
    expect(within(workspace).getByText("No session is open yet.")).toBeInTheDocument();
    expect(
      within(workspace).getByText(/Start a live capture on one of the interfaces above, or analyse a PCAP or PCAPNG file\./),
    ).toBeInTheDocument();
  });
});

describe("NetworkPage: the alerts", () => {
  const ALERTS = `${SESSION_URL}/alerts`;

  function suspiciousPorts() {
    return makeAlert({
      id: OTHER_ALERT_ID,
      rule_id: "NET-006",
      rule_name: "suspicious_port",
      title: "Repeated connections to suspicious ports",
      severity: "critical",
      explanation: `${SCANNER_IP} tried port 445 on ${HOST_IP} 31 times.`,
      observed_value: 31,
      threshold: 25,
      unit: "attempts",
      dst_port: 445,
      enrichment: makeEnrichment({ status: "not_applicable" }),
    });
  }

  it("lists each alert with its severity in words, the numbers behind it and the traffic", async () => {
    await openSession({ alerts: () => makeAlertPage([makeAlert(), suspiciousPorts()]) });

    const scan = await alertItem("Port scan");
    expect(within(scan).getByText("High")).toBeInTheDocument();
    expect(within(scan).getByText("NET-001")).toBeInTheDocument();
    expect(
      within(scan).getByText(`${SCANNER_IP} tried 40 different destination ports within 60 seconds.`),
    ).toBeInTheDocument();
    expect(
      within(scan).getByText("Observed 40 ports against a threshold of 20 ports, within 60 seconds."),
    ).toBeInTheDocument();
    expect(valueOf(scan, "Source").textContent).toBe(SCANNER_IP);
    expect(valueOf(scan, "Destination").textContent).toBe(HOST_IP);
    expect(valueOf(scan, "Protocol").textContent).toBe("TCP");
    expect(valueOf(scan, "First observed")).toHaveTextContent("20-05-2026 02:00:05 PM IST");
    expect(valueOf(scan, "Last observed")).toHaveTextContent("20-05-2026 02:00:45 PM IST");

    const ports = await alertItem("Repeated connections to suspicious ports");
    expect(within(ports).getByText("Critical")).toBeInTheDocument();
    expect(within(ports).getByText("NET-006")).toBeInTheDocument();
    expect(
      within(ports).getByText("Observed 31 attempts against a threshold of 25 attempts, within 60 seconds."),
    ).toBeInTheDocument();
    expect(valueOf(ports, "Destination").textContent).toBe(`${HOST_IP}:445`);

    const alerts = panel("Alerts");
    expect(within(alerts).getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent)).toEqual([
      "Port scan",
      "Repeated connections to suspicious ports",
    ]);
    expect(within(alerts).getByText("Showing 1–2 of 2")).toBeInTheDocument();
  });

  it("opens the evidence of an alert as a list of facts, and closes it again", async () => {
    const user = userEvent.setup();
    await openSession();
    const item = await alertItem();
    const toggle = within(item).getByRole("button", { name: "Evidence for rule NET-001" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(within(item).queryByText("Distinct ports")).not.toBeInTheDocument();

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(valueOf(item, "Distinct ports").textContent).toBe("40");
    expect(valueOf(item, "Sample ports").textContent).toBe("1, 2, 3");

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(within(item).queryByText("Distinct ports")).not.toBeInTheDocument();
  });

  it("shows what the server sent as text, never as markup", async () => {
    const user = userEvent.setup();
    const hostile = "<img src=x onerror=alert(1)>";
    await openSession({
      alerts: () =>
        makeAlertPage([makeAlert({ explanation: hostile, evidence: { note: "<script>alert(2)</script>" } })]),
    });
    const item = await alertItem();

    expect(within(item).getByText(hostile)).toBeInTheDocument();
    await user.click(within(item).getByRole("button", { name: "Evidence for rule NET-001" }));

    expect(valueOf(item, "Note").textContent).toBe("<script>alert(2)</script>");
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
  });

  it("asks only for the severities and the rule that were chosen", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession({
      alerts: ({ url }) =>
        url.searchParams.has("severity") || url.searchParams.has("rule") ? makeAlertPage([]) : makeAlertPage(),
    });
    await alertItem();
    const alerts = panel("Alerts");
    const critical = within(alerts).getByRole("button", { name: "Critical" });
    expect(critical).toHaveAttribute("aria-pressed", "false");
    expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?limit=25&offset=0`);

    await user.click(critical);

    expect(critical).toHaveAttribute("aria-pressed", "true");
    expect(await within(alerts).findByText("No alerts match these filters.")).toBeInTheDocument();
    expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?severity=critical&limit=25&offset=0`);

    const rule = within(alerts).getByRole("combobox", { name: "Rule" });
    await within(rule).findByRole("option", { name: "NET-001 - Port scan" });
    await user.selectOptions(rule, "NET-001");

    await waitFor(() =>
      expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?severity=critical&rule=NET-001&limit=25&offset=0`),
    );

    await user.click(within(alerts).getByRole("button", { name: "High" }));

    await waitFor(() =>
      expect(lastRead(fetchMock, ALERTS)).toBe(
        `${ALERTS}?severity=high&severity=critical&rule=NET-001&limit=25&offset=0`,
      ),
    );
    expect(within(alerts).getByRole("button", { name: "High" })).toHaveAttribute("aria-pressed", "true");
    expect(within(alerts).getByRole("button", { name: "Low" })).toHaveAttribute("aria-pressed", "false");
  });

  it("clears the filters in one step", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession({
      alerts: ({ url }) => (url.searchParams.has("severity") ? makeAlertPage([]) : makeAlertPage()),
    });
    await alertItem();
    const alerts = panel("Alerts");
    expect(within(alerts).queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
    await user.click(within(alerts).getByRole("button", { name: "Medium" }));
    expect(await within(alerts).findByText("No alerts match these filters.")).toBeInTheDocument();

    await user.click(within(alerts).getByRole("button", { name: "Clear filters" }));

    expect(await alertItem()).toBeInTheDocument();
    expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?limit=25&offset=0`);
    expect(within(alerts).getByRole("button", { name: "Medium" })).toHaveAttribute("aria-pressed", "false");
    expect(within(alerts).queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("pages through the alerts 25 at a time", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession({
      alerts: ({ url }) =>
        url.searchParams.get("offset") === "25"
          ? { ...makeAlertPage([suspiciousPorts()], 60), offset: 25 }
          : makeAlertPage([makeAlert()], 60),
    });
    await alertItem();
    const alerts = panel("Alerts");
    expect(within(alerts).getByText("Showing 1–25 of 60")).toBeInTheDocument();
    expect(within(alerts).getByRole("button", { name: "Previous" })).toBeDisabled();

    await user.click(within(alerts).getByRole("button", { name: "Next" }));

    expect(await alertItem("Repeated connections to suspicious ports")).toBeInTheDocument();
    expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?limit=25&offset=25`);
    expect(within(alerts).getByText("Showing 26–50 of 60")).toBeInTheDocument();

    await user.click(within(alerts).getByRole("button", { name: "Previous" }));

    expect(await alertItem("Port scan")).toBeInTheDocument();
    expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?limit=25&offset=0`);
  });

  it("explains an alert list that cannot be read, and tries again on request", async () => {
    const user = userEvent.setup();
    let failing = true;
    await openSession({
      alerts: () => (failing ? apiError(500, "internal_error", "The alerts are unavailable.") : makeAlertPage()),
    });
    const alerts = panel("Alerts");
    expect(await within(alerts).findByRole("alert")).toHaveTextContent("The alerts are unavailable.");
    expect(within(panel("Session summary")).getByText("Completed")).toBeInTheDocument();

    failing = false;
    await user.click(within(alerts).getByRole("button", { name: "Try again" }));

    expect(await alertItem()).toBeInTheDocument();
    expect(within(alerts).queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("NetworkPage: looking an address up", () => {
  const LOOKUP = "Look up address for rule NET-001";
  const ENRICH = `${API}/alerts/${ALERT_ID}/enrich`;

  const NO_DATA = makeCompletedEnrichment({
    risk_score: null,
    classification: null,
    assessed: false,
    providers: [{ provider: "abuseipdb", display_name: "AbuseIPDB", status: "no_data", verdict: null }],
  });

  it("looks the address up on request and shows the answer in the same alert", async () => {
    const user = userEvent.setup();
    let looked = false;
    const answer = () => makeAlert({ enrichment: makeCompletedEnrichment() });
    const fetchMock = await openSession({
      alerts: () => makeAlertPage([looked ? answer() : makeAlert()]),
      enrich: () => {
        looked = true;
        return answer();
      },
      session: () =>
        makeSessionDetail({
          external_ips: [
            makeExternalIp({
              enrichment: looked ? makeCompletedEnrichment() : makeEnrichment({ address: SCANNER_IP }),
            }),
          ],
          enrichment: { ...NO_LOOKUPS, total: 1, completed: looked ? 1 : 0 },
        }),
    });
    const item = await alertItem();
    expect(within(item).getByText("Not looked up")).toBeInTheDocument();
    expect(valueOf(panel("External IP addresses"), "Looked up").textContent).toBe("0");

    await user.click(within(item).getByRole("button", { name: LOOKUP }));

    expect(await within(item).findByText("Risk score 72 of 100")).toBeInTheDocument();
    expect(sentTo(fetchMock, ENRICH)?.method).toBe("POST");
    expect(within(item).getByText(/^Classification/)).toBeInTheDocument();
    expect(
      within(item).getByText(
        "Providers answered. The score summarises what they reported; it is a signal, not a verdict.",
      ),
    ).toBeInTheDocument();
    expect(within(item).getByText("AbuseIPDB: Answered, verdict malicious")).toBeInTheDocument();
    expect(within(item).getByText("AlienVault OTX: No data")).toBeInTheDocument();
    expect(within(item).queryByRole("button", { name: LOOKUP })).not.toBeInTheDocument();
    await waitFor(() =>
      expect(valueOf(panel("External IP addresses"), "Looked up").textContent).toBe("1"),
    );
  });

  it("only sends the one alert that was asked about", async () => {
    const user = userEvent.setup();
    const other = makeAlert({ id: OTHER_ALERT_ID, rule_id: "NET-002", title: "High connection rate" });
    const fetchMock = await openSession({
      alerts: () => makeAlertPage([makeAlert(), other]),
      enrich: ({ id }) => makeAlert({ id: id ?? "", rule_id: "NET-002", title: "High connection rate" }),
    });
    const item = await alertItem("High connection rate");

    await user.click(within(item).getByRole("button", { name: "Look up address for rule NET-002" }));

    await waitFor(() => expect(sentTo(fetchMock, `${API}/alerts/${OTHER_ALERT_ID}/enrich`)).toBeDefined());
    expect(sentTo(fetchMock, ENRICH)).toBeUndefined();
  });

  it("does not turn an answer without data into a statement that the address is safe", async () => {
    await openSession({
      alerts: () => makeAlertPage([makeAlert({ enrichment: NO_DATA })]),
    });
    const item = await alertItem();

    expect(
      within(item).getByText("No provider returned data. This is not evidence the address is safe."),
    ).toBeInTheDocument();
    expect(within(item).queryByText(/Risk score/)).not.toBeInTheDocument();
    expect(within(item).queryByText(/^Classification/)).not.toBeInTheDocument();
    expect(within(item).getByText("AbuseIPDB: No data")).toBeInTheDocument();
    expect(within(item).queryByRole("button", { name: LOOKUP })).not.toBeInTheDocument();
  });

  it.each<[string, Enrichment, string, string, boolean]>([
    [
      "not looked up",
      makeEnrichment({ address: SCANNER_IP }),
      "Not looked up",
      "This address has not been looked up. Nothing was sent to any provider.",
      true,
    ],
    [
      "being looked up",
      makeEnrichment({ status: "pending", address: SCANNER_IP }),
      "Looking up",
      "The lookup is waiting for the providers.",
      false,
    ],
    [
      "looked up with a score",
      makeCompletedEnrichment(),
      "Looked up",
      "Providers answered. The score summarises what they reported; it is a signal, not a verdict.",
      false,
    ],
    [
      "looked up without data",
      NO_DATA,
      "Looked up",
      "No provider returned data. This is not evidence the address is safe.",
      false,
    ],
    [
      "a failed lookup",
      makeEnrichment({ status: "failed", address: SCANNER_IP, message: "The providers did not answer in time." }),
      "Lookup failed",
      "The providers did not answer in time.",
      true,
    ],
    [
      "unavailable",
      makeEnrichment({ status: "unavailable", address: SCANNER_IP }),
      "Lookup unavailable",
      "No provider could be asked for this address right now.",
      true,
    ],
    [
      "over the lookup limit",
      makeEnrichment({ status: "skipped_budget", address: SCANNER_IP }),
      "Lookup limit reached",
      "Not looked up: this session reached its limit on lookups.",
      true,
    ],
    [
      "switched off",
      makeEnrichment({ status: "disabled" }),
      "Enrichment off",
      "External enrichment is switched off on this server.",
      false,
    ],
    [
      "not a public address",
      makeEnrichment({ status: "not_applicable" }),
      "No public address",
      "The traffic involves no public address, so there is nothing to look up.",
      false,
    ],
  ])("shows an alert whose address is %s", async (_state, enrichment, label, note, canLookUp) => {
    await openSession({ alerts: () => makeAlertPage([makeAlert({ enrichment })]) });
    const item = await alertItem();

    expect(within(item).getAllByText(label).length).toBeGreaterThan(0);
    expect(within(item).getByText(note)).toBeInTheDocument();
    expect(within(item).queryByRole("button", { name: LOOKUP }) !== null).toBe(canLookUp);
  });

  it("offers no lookup at all when the server has external lookups switched off", async () => {
    await openSession({
      status: () => makeNetworkStatus({ enrichment_enabled: false }),
      alerts: () => makeAlertPage([makeAlert({ enrichment: makeEnrichment({ address: SCANNER_IP }) })]),
    });
    const item = await alertItem();

    expect(within(item).getByText("Not looked up")).toBeInTheDocument();
    expect(within(item).queryByRole("button", { name: LOOKUP })).not.toBeInTheDocument();
  });

  it("shows the busy state while the providers are asked, and ignores a second press", async () => {
    const user = userEvent.setup();
    let looked = false;
    let release: (answer: Response) => void = () => undefined;
    const answer = () => makeAlert({ enrichment: makeCompletedEnrichment() });
    const fetchMock = await openSession({
      // The answer ends the lookup, and the list read again afterwards holds it, as a real server's would.
      alerts: () => makeAlertPage([looked ? answer() : makeAlert()]),
      enrich: () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    });
    const item = await alertItem();

    await user.click(within(item).getByRole("button", { name: LOOKUP }));
    const busy = await within(item).findByRole("button", { name: "Looking up… for rule NET-001" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await user.click(busy);

    expect(requested(fetchMock, "POST").filter((url) => url === ENRICH)).toHaveLength(1);
    looked = true;
    release(jsonResponse(answer()));
    expect(await within(item).findByText("Risk score 72 of 100")).toBeInTheDocument();
  });

  it.each<[number, string, HeadersInit | undefined, string]>([
    [
      409,
      "enrichment_disabled",
      undefined,
      "External enrichment is switched off on this server, so addresses cannot be looked up.",
    ],
    [
      422,
      "address_not_public",
      undefined,
      "This alert involves no public address. Private addresses are never looked up or sent to a provider.",
    ],
    [404, "alert_not_found", undefined, "That alert no longer exists. Its session may have been deleted."],
    [429, "rate_limited", { "Retry-After": "30" }, "The server asked for a pause. Try again in 30 seconds."],
  ])("explains a refused lookup (%i %s) in the alert, and lets it be tried again", async (status, code, headers, text) => {
    const user = userEvent.setup();
    await openSession({ enrich: () => apiError(status, code, undefined, headers) });
    const item = await alertItem();

    await user.click(within(item).getByRole("button", { name: LOOKUP }));

    expect(await within(item).findByRole("alert")).toHaveTextContent(text);
    const again = within(item).getByRole("button", { name: LOOKUP });
    expect(again).not.toHaveAttribute("aria-disabled");
    expect(within(item).getByText("Not looked up")).toBeInTheDocument();
  });
});

describe("NetworkPage: the external IP addresses", () => {
  const OTHER_IP = "198.51.100.7";
  const NO_DATA_NOTE = "No provider returned data. This is not evidence the address is safe.";

  function quietAddress() {
    return makeExternalIp({
      address: OTHER_IP,
      first_seen: "2026-05-20T08:30:10Z",
      last_seen: "2026-05-20T08:30:30Z",
      packets: 5,
      bytes: 600,
      sent_to: true,
      alerted: false,
      peers: [HOST_IP],
      ports: [53],
      protocols: ["udp"],
      enrichment: makeCompletedEnrichment({
        address: OTHER_IP,
        risk_score: null,
        classification: null,
        assessed: false,
        providers: [{ provider: "abuseipdb", display_name: "AbuseIPDB", status: "no_data", verdict: null }],
      }),
    });
  }

  function twoAddresses(): SessionDetail {
    return makeSessionDetail({
      external_ips: [makeExternalIp(), quietAddress()],
      enrichment: { enabled: true, total: 2, completed: 1, pending: 0, failed: 0, unavailable: 0, skipped: 1 },
    });
  }

  it("says that only public addresses are looked up, and only once each", async () => {
    await openSession();

    expect(
      within(panel("External IP addresses")).getByText(
        /Only deduplicated public addresses are ever looked up, never every packet, and never private addresses\./,
      ),
    ).toBeInTheDocument();
  });

  it("counts the lookups of the session", async () => {
    await openSession({ session: twoAddresses });
    const summary = within(panel("External IP addresses")).getByLabelText("Lookup summary");

    expect(valueOf(summary, "Public addresses").textContent).toBe("2");
    expect(valueOf(summary, "Looked up").textContent).toBe("1");
    expect(valueOf(summary, "Pending").textContent).toBe("0");
    expect(valueOf(summary, "Failed").textContent).toBe("0");
    expect(valueOf(summary, "Unavailable").textContent).toBe("0");
    expect(valueOf(summary, "Skipped or not looked up").textContent).toBe("1");
  });

  it("lists each public address with what the traffic did and what the providers said", async () => {
    await openSession({ session: twoAddresses });
    const addresses = panel("External IP addresses");
    const list = within(addresses).getByRole("list", { name: "External IP addresses" });
    const labelled = (card: HTMLElement, label: string) =>
      within(within(card).getByRole("list", { name: label }))
        .getAllByRole("listitem")
        .map((chip) => chip.textContent);

    const scanner = itemOf(within(list).getByRole("heading", { level: 3, name: SCANNER_IP }));
    expect(valueOf(scanner, "First seen")).toHaveTextContent("20-05-2026 02:00:05 PM IST");
    expect(valueOf(scanner, "Last seen")).toHaveTextContent("20-05-2026 02:00:50 PM IST");
    expect(valueOf(scanner, "Packets").textContent).toBe("40");
    expect(valueOf(scanner, "Data").textContent).toBe("2.34 KB");
    expect(valueOf(scanner, "Traffic sent to it").textContent).toBe("No");
    expect(valueOf(scanner, "Raised an alert").textContent).toBe("Yes");
    expect(labelled(scanner, `Ports seen with ${SCANNER_IP}`)).toEqual(["22", "80", "443"]);
    expect(labelled(scanner, `Protocols seen with ${SCANNER_IP}`)).toEqual(["TCP"]);
    expect(labelled(scanner, `Peers of ${SCANNER_IP}`)).toEqual([HOST_IP]);
    expect(within(scanner).getByText("Not looked up")).toBeInTheDocument();

    const quiet = itemOf(within(list).getByRole("heading", { level: 3, name: OTHER_IP }));
    expect(valueOf(quiet, "Packets").textContent).toBe("5");
    expect(valueOf(quiet, "Data").textContent).toBe("600 B");
    expect(valueOf(quiet, "Traffic sent to it").textContent).toBe("Yes");
    expect(valueOf(quiet, "Raised an alert").textContent).toBe("No");
    expect(labelled(quiet, `Ports seen with ${OTHER_IP}`)).toEqual(["53"]);
    expect(labelled(quiet, `Protocols seen with ${OTHER_IP}`)).toEqual(["UDP"]);
    expect(within(quiet).getByText(NO_DATA_NOTE)).toBeInTheDocument();
    expect(within(quiet).queryByText(/Risk score/)).not.toBeInTheDocument();
    expect(within(quiet).getByText("AbuseIPDB: No data")).toBeInTheDocument();
  });

  it("offers no lookup for an address that no alert is about", async () => {
    await openSession({ session: twoAddresses, alerts: () => makeAlertPage([]) });

    const addresses = panel("External IP addresses");
    expect(within(addresses).queryByRole("button", { name: /Look up/ })).not.toBeInTheDocument();
  });

  it("still lists the addresses when external lookups are switched off, and says nothing is sent", async () => {
    await openSession({
      status: () => makeNetworkStatus({ enrichment_enabled: false }),
      session: () =>
        makeSessionDetail({
          external_ips: [makeExternalIp({ enrichment: makeEnrichment({ status: "disabled" }) })],
          enrichment: { ...NO_LOOKUPS, enabled: false, total: 1 },
        }),
    });
    const addresses = panel("External IP addresses");

    expect(within(addresses).getByText("External enrichment is switched off on this server")).toBeInTheDocument();
    expect(
      within(addresses).getByText("The addresses below are still listed, but none is looked up or sent to any provider."),
    ).toBeInTheDocument();
    expect(within(addresses).queryByLabelText("Lookup summary")).not.toBeInTheDocument();
    expect(within(addresses).getByRole("heading", { level: 3, name: SCANNER_IP })).toBeInTheDocument();
    expect(within(addresses).getByText("Enrichment off")).toBeInTheDocument();
  });
});

describe("NetworkPage: the flows", () => {
  const FLOWS = `${SESSION_URL}/flows`;

  const closed = () =>
    makeFlow({
      id: 1,
      duration_seconds: 12.4,
      packets_out: 12,
      packets_in: 8,
      bytes_out: 2_048,
      bytes_in: 60,
      tcp_flag_names: ["SYN", "ACK"],
      close_reason: "closed",
    });
  const quiet = () =>
    makeFlow({
      id: 2,
      protocol: "udp",
      src_port: 5_353,
      dst_port: 53,
      duration_seconds: 0.5,
      packets_out: 1,
      packets_in: 1,
      bytes_out: 120,
      bytes_in: 500,
      tcp_flags: null,
      tcp_flag_names: [],
      close_reason: "idle",
    });

  /** The cells of the row of one conversation, after the row header. */
  function flowCells(table: HTMLElement, source: string): string[] {
    const row = within(table).getByText(source).closest("tr");
    if (row === null) throw new Error(`"${source}" is not in a table row.`);
    return Array.from(row.querySelectorAll("td"), (cell) => (cell.textContent ?? "").trim());
  }

  it("lists the finished flows with who talked to whom, how much, and how each ended", async () => {
    await openSession({ flows: () => makeFlowPage([closed(), quiet()]) });
    const table = await within(panel("Flows")).findByRole("table", { name: "Finished flows of this session" });

    expect(cellTexts(table)[0]).toEqual([
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

    const [protocol, first, last, duration, packets, data, flags, ended] = flowCells(table, `${SCANNER_IP}:40001`);
    expect(protocol).toBe("TCP");
    expect(first).toContain("20-05-2026 02:00:05 PM IST");
    expect(last).toContain("20-05-2026 02:00:06 PM IST");
    expect(duration).toBe("12 s");
    expect(packets).toBe("12 / 8");
    expect(data).toBe("2.00 KB / 60 B");
    expect(flags).toBe("SYN ACK");
    expect(ended).toBe("Closed");

    const [udp, , , udpDuration, udpPackets, udpData, udpFlags, udpEnded] = flowCells(table, `${SCANNER_IP}:5353`);
    expect(udp).toBe("UDP");
    expect(udpDuration).toBe("0.5 s");
    expect(udpPackets).toBe("1 / 1");
    expect(udpData).toBe("120 B / 500 B");
    expect(udpFlags).toBe("Not TCP");
    expect(udpEnded).toBe("Idle");
    expect(within(panel("Flows")).getByText("Showing 1–2 of 2")).toBeInTheDocument();
  });

  it("explains what a flow is and when it is listed", async () => {
    await openSession();

    expect(
      within(panel("Flows")).getByText(/A flow is the packets of one conversation between two endpoints\./),
    ).toBeInTheDocument();
  });

  it("pages through the flows 25 at a time", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession({
      flows: ({ url }) =>
        url.searchParams.get("offset") === "25"
          ? { ...makeFlowPage([quiet()], 60), offset: 25 }
          : makeFlowPage([closed()], 60),
    });
    const flows = panel("Flows");
    const table = await within(flows).findByRole("table", { name: "Finished flows of this session" });
    expect(within(table).getByText(`${SCANNER_IP}:40001`)).toBeInTheDocument();
    expect(within(flows).getByText("Showing 1–25 of 60")).toBeInTheDocument();

    await user.click(within(flows).getByRole("button", { name: "Next" }));

    expect(await within(flows).findByText(`${SCANNER_IP}:5353`)).toBeInTheDocument();
    expect(lastRead(fetchMock, FLOWS)).toBe(`${FLOWS}?limit=25&offset=25`);
    expect(within(flows).getByText("Showing 26–50 of 60")).toBeInTheDocument();
  });

  it("explains a flow list that cannot be read, and tries again on request", async () => {
    const user = userEvent.setup();
    let failing = true;
    await openSession({
      flows: () => (failing ? apiError(500, "internal_error", "The flows are unavailable.") : makeFlowPage()),
    });
    const flows = panel("Flows");
    expect(await within(flows).findByRole("alert")).toHaveTextContent("The flows are unavailable.");

    failing = false;
    await user.click(within(flows).getByRole("button", { name: "Try again" }));

    expect(await within(flows).findByRole("table", { name: "Finished flows of this session" })).toBeInTheDocument();
    expect(within(flows).queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("NetworkPage: the detection rules", () => {
  async function rulesList(): Promise<HTMLElement> {
    return within(panel("Detection rules")).findByRole("list", { name: "Detection rules" });
  }

  it("lists the seven rules in order, with what each looks for", async () => {
    await openPage();
    const list = await rulesList();

    expect(within(list).getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent)).toEqual([
      "Port scan",
      "High connection rate",
      "Abnormal SYN rate",
      "High traffic volume",
      "Communication with a known malicious address",
      "Repeated connections to suspicious ports",
      "Unexpected protocol",
    ]);
    const ids = within(list)
      .getAllByRole("heading", { level: 3 })
      .map((heading) => itemOf(heading).textContent?.match(/NET-\d{3}/)?.[0]);
    expect(ids).toEqual(["NET-001", "NET-002", "NET-003", "NET-004", "NET-005", "NET-006", "NET-007"]);
  });

  it("shows the threshold, the time window and how the severity grows", async () => {
    await openPage();
    const list = await rulesList();

    const scan = itemOf(within(list).getByRole("heading", { level: 3, name: "Port scan" }));
    expect(within(scan).getByText("Description of port_scan.")).toBeInTheDocument();
    expect(valueOf(scan, "Threshold").textContent).toBe("20 ports");
    expect(valueOf(scan, "Time window").textContent).toBe("60 seconds");
    expect(
      within(scan).getByRole("list", { name: "Severity of NET-001 by multiple of the threshold" }),
    ).toHaveTextContent(/At 1×.*Medium.*At 3×.*High.*At 10×.*Critical/);
    expect(within(scan).getByText("Active")).toBeInTheDocument();

    const protocol = itemOf(within(list).getByRole("heading", { level: 3, name: "Unexpected protocol" }));
    expect(valueOf(protocol, "Time window").textContent).toBe("No time window");
    expect(within(protocol).getByText("Expected: icmp, icmpv6, igmp, tcp, udp")).toBeInTheDocument();
    expect(
      within(protocol).getByRole("list", { name: "Severity of NET-007 by multiple of the threshold" }),
    ).toHaveTextContent(/At 1×.*Low.*At 3×.*Low.*At 10×.*Low/);
  });

  it("says that a rule is a lead to look into, not proof either way", async () => {
    await openPage();
    await rulesList();

    expect(
      within(panel("Detection rules")).getByText(/not proof of an attack, and no alert is not proof that traffic is safe/),
    ).toBeInTheDocument();
  });

  it("says why a rule cannot fire when external lookups are switched off", async () => {
    await openPage({
      status: () => makeNetworkStatus({ enrichment_enabled: false }),
      rules: () => makeRules().map((rule) => (rule.rule_id === "NET-005" ? { ...rule, active: false } : rule)),
    });
    const list = await rulesList();

    const card = itemOf(
      within(list).getByRole("heading", { level: 3, name: "Communication with a known malicious address" }),
    );
    expect(within(card).getAllByText("Inactive").length).toBeGreaterThan(0);
    expect(
      within(card).getByText(
        "This rule needs external enrichment, which is switched off on this server, so it cannot fire.",
      ),
    ).toBeInTheDocument();
    expect(within(card).getByText(/Needs external enrichment: only addresses that were looked up can raise it\./)).toBeInTheDocument();
    expect(within(list).getAllByText("Active")).toHaveLength(6);
  });

  it("keeps the rest of the page when the rules cannot be read, and offers another try", async () => {
    const user = userEvent.setup();
    let failing = true;
    await openPage({
      rules: () => (failing ? apiError(500, "internal_error", "The rules are unavailable.") : makeRules()),
    });
    const rules = panel("Detection rules");
    expect(await within(rules).findByRole("alert")).toHaveTextContent("The rules are unavailable.");
    expect(panel("Live capture")).toBeInTheDocument();

    failing = false;
    await user.click(within(rules).getByRole("button", { name: "Try again" }));

    expect(await rulesList()).toBeInTheDocument();
    expect(within(rules).queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("NetworkPage: accessibility", () => {
  const ALERTS = `${SESSION_URL}/alerts`;

  /** The page with a session open and every panel filled, so that all of it can be inspected. */
  async function openFull(): Promise<NetworkFetch> {
    const fetchMock = await openSession();
    await screen.findByRole("combobox", { name: "Interface" });
    await alertItem();
    await within(panel("Flows")).findByRole("table", { name: "Finished flows of this session" });
    await within(panel("Session history")).findByRole("table", { name: "Capture sessions, newest first" });
    await within(panel("Detection rules")).findByRole("list", { name: "Detection rules" });
    return fetchMock;
  }

  it("has one page heading, and the panels below it in reading order without skipping a level", async () => {
    await openFull();

    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    // Each panel title is preceded by the code of the panel, such as "CAP-01".
    const titles = screen
      .getAllByRole("heading", { level: 2 })
      .map((heading) => (heading.textContent ?? "").replace(/^[A-Z]+-\d{2}/, ""));
    expect(titles).toEqual([
      "Live capture",
      "Analyse a capture file",
      "Session history",
      "Session summary",
      "Protocol distribution",
      "Top talkers",
      "Alerts",
      "External IP addresses",
      "Flows",
      "Detection rules",
    ]);
    const levels = screen.getAllByRole("heading").map((heading) => Number(heading.tagName.slice(1)));
    levels.forEach((level, index) => {
      expect(level - (levels[index - 1] ?? 0)).toBeLessThanOrEqual(1);
    });
  });

  it("labels the fields and the filters", async () => {
    await openFull();

    expect(screen.getByRole("combobox", { name: "Interface" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Rule" })).toBeInTheDocument();
    const file = screen.getByLabelText("Capture file");
    expect(file).toHaveAttribute("type", "file");
    expect(file).toHaveAccessibleDescription(/^Files ending in \.pcap, \.pcapng or \.cap, up to 50 MB\./);
    const severity = screen.getByRole("group", { name: "Severity" });
    for (const name of ["Low", "Medium", "High", "Critical"]) {
      expect(within(severity).getByRole("button", { name })).toHaveAttribute("aria-pressed", "false");
    }
  });

  it("gives every button, field, table and navigation a name", async () => {
    await openFull();
    const named = [
      ...screen.getAllByRole("button"),
      ...screen.getAllByRole("combobox"),
      ...screen.getAllByRole("table", { hidden: true }),
      ...screen.queryAllByRole("navigation"),
    ];

    expect(named.length).toBeGreaterThan(15);
    for (const element of named) expect(element).toHaveAccessibleName();
    for (const name of ["Alerts", "External IP addresses", "Detection rules"]) {
      expect(screen.getByRole("list", { name })).toBeInTheDocument();
    }
  });

  it("announces what changes in polite live regions", async () => {
    await openFull();
    const regions = screen.getAllByRole("status");

    expect(regions.length).toBeGreaterThanOrEqual(2);
    for (const region of regions) expect(region).toHaveAttribute("aria-live", "polite");
    expect(within(panel("Live capture")).getByRole("status")).toHaveTextContent(
      "Ready. Choose an interface and press Start.",
    );
    expect(within(panel("Analyse a capture file")).getByRole("status")).toBeInTheDocument();
  });

  it("hides the decorative pictures from assistive technology and names the others", async () => {
    await openFull();
    const pictures = Array.from(document.querySelectorAll("svg"));
    const unnamed = pictures.filter((picture) => {
      const decoration = picture.closest('[aria-hidden="true"]') !== null;
      const named = picture.getAttribute("role") === "img" && (picture.getAttribute("aria-label") ?? "") !== "";
      return !decoration && !named;
    });

    expect(pictures.length).toBeGreaterThan(0);
    expect(unnamed.map((picture) => picture.outerHTML.slice(0, 120))).toEqual([]);
  });

  it("keeps every table in a container that scrolls sideways, so the page itself does not", async () => {
    await openFull();
    const tables = screen.getAllByRole("table", { hidden: true });
    const loose = tables.filter((table) => table.closest(".overflow-x-auto") === null);

    expect(tables.length).toBeGreaterThanOrEqual(4);
    expect(loose.map((table) => table.querySelector("caption")?.textContent)).toEqual([]);
  });

  it("offers every chart as a table too", async () => {
    await openFull();

    expect(within(panel("Protocol distribution")).getAllByText("Table view", { selector: "summary" })).toHaveLength(1);
    expect(within(panel("Top talkers")).getAllByText("Table view", { selector: "summary" })).toHaveLength(2);
  });

  it("opens and closes the evidence of an alert from the keyboard", async () => {
    const user = userEvent.setup();
    await openFull();
    const toggle = within(await alertItem()).getByRole("button", { name: "Evidence for rule NET-001" });
    toggle.focus();

    await user.keyboard("{Enter}");

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const evidence = document.getElementById(toggle.getAttribute("aria-controls") ?? "");
    expect(evidence).not.toBeNull();
    expect(evidence).toBeVisible();

    await user.keyboard(" ");

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(evidence).not.toBeVisible();
  });

  it("filters the alerts by severity from the keyboard", async () => {
    const user = userEvent.setup();
    const fetchMock = await openFull();
    const high = within(screen.getByRole("group", { name: "Severity" })).getByRole("button", { name: "High" });
    high.focus();

    await user.keyboard("{Enter}");

    expect(high).toHaveAttribute("aria-pressed", "true");
    await waitFor(() => expect(lastRead(fetchMock, ALERTS)).toBe(`${ALERTS}?severity=high&limit=25&offset=0`));
  });

  it("reaches Start capture by tabbing, and starts the capture with the Enter key", async () => {
    const user = userEvent.setup();
    const fetchMock = await openCapture();
    const start = screen.getByRole("button", { name: "Start capture" });
    for (let presses = 0; presses < 40 && document.activeElement !== start; presses += 1) await user.tab();
    expect(start).toHaveFocus();

    await user.keyboard("{Enter}");

    await waitFor(() => expect(sentTo(fetchMock, `${API}/capture/start`)).toBeDefined());
    expect(sentTo(fetchMock, `${API}/capture/start`)?.body).toBe(JSON.stringify({ interface: "eth0" }));
  });
});

