import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { NetworkStatus } from "../../types/network";
import { apiError, networkApi, requested, runningStatus } from "../../test/networkApi";
import {
  makeBackend,
  makeInterface,
  makeInterfaces,
  makeNetworkStatus,
} from "../../test/networkFixtures";
import CaptureControl from "./CaptureControl";

async function setup(status: NetworkStatus = makeNetworkStatus(), handlers: Parameters<typeof networkApi>[0] = {}) {
  const fetchMock = networkApi(handlers);
  const onSettled = vi.fn();
  const view = render(<CaptureControl status={status} onSettled={onSettled} />);
  await screen.findByRole("combobox", { name: "Interface" });
  return { fetchMock, onSettled, ...view };
}

const start = () => screen.getByRole("button", { name: "Start capture" });
const stop = () => screen.getByRole("button", { name: "Stop capture" });

describe("CaptureControl: choosing an interface", () => {
  it("offers every interface by name and description, with the first one chosen", async () => {
    await setup();

    const select = screen.getByRole("combobox", { name: "Interface" });
    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual([
      "eth0 - Ethernet adapter",
      "lo - Loopback",
    ]);
    expect(select).toHaveValue("eth0");
    expect(screen.getByText("Addresses: 192.0.2.10")).toBeInTheDocument();
  });

  it("follows the choice in the small line of addresses under the list", async () => {
    await setup();

    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Interface" }), "lo");

    expect(screen.getByText("Addresses: 127.0.0.1")).toBeInTheDocument();
    expect(screen.queryByText("Addresses: 192.0.2.10")).not.toBeInTheDocument();
  });

  it("says so when no interface is found, and cannot start", async () => {
    await setup(makeNetworkStatus(), { interfaces: () => makeInterfaces([]) });

    expect(screen.getByRole("combobox", { name: "Interface" })).toBeDisabled();
    expect(screen.getByText("No capture interfaces found. Refresh the list after connecting or enabling one.")).toBeInTheDocument();
    expect(start()).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("There is no interface to capture on.")).toBeInTheDocument();
  });

  it("looks at the machine again when asked, and shows what turned up", async () => {
    const lists = [makeInterfaces(), makeInterfaces([makeInterface({ id: "wlan0", name: "wlan0", description: "Wi-Fi" })])];
    const { fetchMock } = await setup(makeNetworkStatus(), { interfaces: () => lists.shift() ?? makeInterfaces() });

    await userEvent.click(screen.getByRole("button", { name: "Refresh interfaces" }));

    await screen.findByRole("option", { name: "wlan0 - Wi-Fi" });
    expect(screen.queryByRole("option", { name: "lo - Loopback" })).not.toBeInTheDocument();
    expect(requested(fetchMock)).toEqual([
      "/api/v1/network/interfaces",
      "/api/v1/network/interfaces?refresh=true",
    ]);
  });

  it("shows a loading note first, then the list", async () => {
    networkApi();
    render(<CaptureControl status={makeNetworkStatus()} onSettled={vi.fn()} />);

    expect(screen.getByText("Looking for capture interfaces…")).toBeInTheDocument();
    await screen.findByRole("combobox", { name: "Interface" });
    expect(screen.queryByText("Looking for capture interfaces…")).not.toBeInTheDocument();
  });

  it("offers a retry when the list cannot be read", async () => {
    let failing = true;
    networkApi({ interfaces: () => (failing ? apiError(500, "internal_error", "The list broke.") : makeInterfaces()) });
    render(<CaptureControl status={makeNetworkStatus()} onSettled={vi.fn()} />);

    expect(await screen.findByRole("alert")).toHaveTextContent("The list broke.");
    failing = false;
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("combobox", { name: "Interface" })).toBeInTheDocument();
  });
});

describe("CaptureControl: starting", () => {
  it("sends the chosen interface and then shows the capture running", async () => {
    const { fetchMock, onSettled } = await setup(makeNetworkStatus(), {
      start: () => runningStatus({ interface: "lo" }),
    });

    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Interface" }), "lo");
    await userEvent.click(start());

    await screen.findByText("Capturing on lo. The figures below update as packets arrive.");
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(post?.[0]).toBe("/api/v1/network/capture/start");
    expect(JSON.parse(String(post?.[1]?.body))).toEqual({ interface: "lo" });
    expect(onSettled).toHaveBeenCalledWith("started");
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("holds the controls while the request is under way and ignores a second press", async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { fetchMock } = await setup(makeNetworkStatus(), {
      start: async () => {
        await gate;
        return runningStatus();
      },
    });

    await userEvent.click(start());
    const busy = await screen.findByRole("button", { name: "Starting…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(busy);
    release?.();

    await screen.findByText(/Capturing on eth0/);
    expect(requested(fetchMock, "POST")).toEqual(["/api/v1/network/capture/start"]);
  });

  it("explains a refusal in calm words and reports that the start failed", async () => {
    const { onSettled } = await setup(makeNetworkStatus(), {
      start: () => apiError(503, "capture_permission_denied"),
    });

    await userEvent.click(start());

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Packet capture not permitted");
    expect(alert).toHaveTextContent("docs/network-monitoring.md");
    expect(onSettled).toHaveBeenCalledWith("failed");
    expect(screen.getByText("Ready. Choose an interface and press Start.")).toBeInTheDocument();
  });

  it("explains that a capture is already running when the server says so", async () => {
    await setup(makeNetworkStatus(), { start: () => apiError(409, "capture_already_running") });

    await userEvent.click(start());

    expect(await screen.findByRole("alert")).toHaveTextContent("A capture is already running");
  });
});

describe("CaptureControl: stopping", () => {
  it("stops a running capture and then says it is stopped", async () => {
    const { fetchMock, onSettled } = await setup(runningStatus());

    expect(stop()).not.toHaveAttribute("aria-disabled");
    await userEvent.click(stop());

    await screen.findByText("The capture is stopped.");
    expect(requested(fetchMock, "POST")).toEqual(["/api/v1/network/capture/stop"]);
    expect(onSettled).toHaveBeenCalledWith("stopped");
    expect(screen.getByText("Capture stopped")).toBeInTheDocument();
  });

  it("reports a refusal to stop", async () => {
    const { onSettled } = await setup(runningStatus(), { stop: () => apiError(409, "capture_not_running") });

    await userEvent.click(stop());

    expect(await screen.findByRole("alert")).toHaveTextContent("No capture to stop");
    expect(onSettled).toHaveBeenCalledWith("failed");
  });

  it("has nothing to stop when no capture is running, and ignores the press", async () => {
    const { fetchMock } = await setup();

    expect(stop()).toHaveAttribute("aria-disabled", "true");
    await userEvent.click(stop());

    expect(requested(fetchMock, "POST")).toEqual([]);
  });
});

describe("CaptureControl: states", () => {
  it("locks the interface and Start while a capture runs, and names the interface in use", async () => {
    const { fetchMock } = await setup(runningStatus({ interface: "lo" }));

    expect(screen.getByRole("combobox", { name: "Interface" })).toBeDisabled();
    expect(screen.getByRole("combobox", { name: "Interface" })).toHaveValue("lo");
    expect(start()).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("A capture is already running. Stop it to start another.")).toBeInTheDocument();
    expect(screen.getByText("Capturing on lo. The figures below update as packets arrive.")).toBeInTheDocument();
    await userEvent.click(start());
    expect(requested(fetchMock, "POST")).toEqual([]);
  });

  it("still names a running capture's interface when it is no longer in the list", async () => {
    await setup(runningStatus({ interface: "usb0" }));

    expect(screen.getByRole("option", { name: "usb0" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Interface" })).toHaveValue("__unlisted__");
  });

  it("explains that another capture holds the single slot, and cannot start", async () => {
    const { fetchMock } = await setup(makeNetworkStatus({ busy: true }));

    expect(start()).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Another capture holds the single capture slot.")).toBeInTheDocument();
    expect(screen.getByText("Another capture is running")).toBeInTheDocument();
    expect(screen.getByText(/You can still analyse a PCAP file/)).toBeInTheDocument();
    await userEvent.click(start());
    expect(requested(fetchMock, "POST")).toEqual([]);
  });

  it("guides the analyst when the operating system refused packet capture", async () => {
    await setup(makeNetworkStatus({ state: "permission_denied" }));

    expect(screen.getByText("Permission denied")).toBeInTheDocument();
    expect(screen.getByText("The operating system refused packet capture")).toBeInTheDocument();
    expect(screen.getByText(/account that runs the CipherForge API/)).toBeInTheDocument();
    expect(screen.getByText(/differ by platform/)).toBeInTheDocument();
    expect(screen.getByText(/docs\/network-monitoring\.md/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /network-monitoring/ })).not.toBeInTheDocument();
  });

  it("says that live capture is unavailable when no capture library is installed", async () => {
    await setup(makeNetworkStatus({ state: "not_configured", backend: makeBackend({ name: "none", available: false }) }));

    expect(screen.getByText("Live capture is not available")).toBeInTheDocument();
    expect(screen.getByText(/Npcap on Windows, or libpcap on Linux and macOS/)).toBeInTheDocument();
    expect(screen.getByText(/Analysing a saved PCAP file may still work/)).toBeInTheDocument();
    expect(screen.getByText("Not available")).toBeInTheDocument();
    expect(start()).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Live capture is not available on this server.", { selector: "p[id]" })).toBeInTheDocument();
  });

  it("shows why a failed capture failed, using the message the server gave", async () => {
    await setup(
      makeNetworkStatus({ state: "failed", error_code: "capture_failed", message: "The interface went away." }),
    );

    const note = screen.getByRole("note");
    expect(note).toHaveTextContent("The last capture failed");
    expect(note).toHaveTextContent("The interface went away.");
    expect(screen.getAllByText("The interface went away.")).toHaveLength(1);
  });

  it("lets a failed or stopped capture be started again", async () => {
    await setup(makeNetworkStatus({ state: "stopped", interface: "eth0", session_id: null }));

    expect(start()).not.toHaveAttribute("aria-disabled");
    expect(screen.getByText("Capture stopped")).toBeInTheDocument();
  });

  it("names the backend and says that nothing of the payload is kept", async () => {
    await setup();

    expect(screen.getByText("npcap")).toBeInTheDocument();
    expect(screen.getByText("Available")).toBeInTheDocument();
    expect(screen.getByText(/Packet payloads are never stored/)).toBeInTheDocument();
  });

  it("announces its state politely, in words as well as with a lamp", async () => {
    await setup(runningStatus());

    const live = screen.getAllByRole("status").find((node) => node.getAttribute("aria-live") === "polite");
    expect(live).toHaveTextContent("Capturing on eth0");
    expect(screen.getByText("Running")).toBeInTheDocument();
  });

  it("waits for the next poll before it trusts the status again after a command", async () => {
    const { rerender, onSettled } = await setup(makeNetworkStatus());
    await userEvent.click(start());
    await screen.findByText(/Capturing on eth0/);

    rerender(<CaptureControl status={runningStatus({ message: null })} onSettled={onSettled} />);

    await waitFor(() => expect(screen.getByText(/Capturing on eth0/)).toBeInTheDocument());
  });
});
