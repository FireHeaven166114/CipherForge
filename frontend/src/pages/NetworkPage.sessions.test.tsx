import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { PCAP_POLL_MS } from "../features/network/polling";
import { jsonResponse } from "../test/http";
import { type NetworkHandlers, apiError, networkApi, requested } from "../test/networkApi";
import {
  OTHER_SESSION_ID,
  SESSION_ID,
  makeAlert,
  makeAlertPage,
  makeFlow,
  makeFlowPage,
  makeNetworkStatus,
  makeSession,
  makeSessionDetail,
  makeSessionPage,
} from "../test/networkFixtures";
import {
  API,
  NO_LOOKUPS,
  NO_TRAFFIC,
  SESSION_LINK,
  type NetworkFetch,
  address,
  flush,
  openPage,
  openSession,
  panel,
  reads,
  renderPage,
  sentTo,
  valueOf,
  withFakeClock,
} from "../test/networkPage";
import type { AnalysisStatus, CaptureSession, SessionDetail } from "../types/network";

const PCAP_URL = `${API}/pcap`;
const OTHER_LINK = `/network?session=${OTHER_SESSION_ID}`;

// The picker's own filter is only a hint, and people can always choose "All files".
const person = () => userEvent.setup({ applyAccept: false });

function capture(name = "capture.pcap", bytes = 2_048): File {
  return new File([new Uint8Array(bytes)], name);
}

function analysis(overrides: Partial<AnalysisStatus> = {}): AnalysisStatus {
  return { running: false, session_id: null, max_upload_mb: 50, ...overrides };
}

const uploadPanel = () => panel("Analyse a capture file");
const fileInput = () => screen.getByLabelText("Capture file");
const analyseButton = () => within(uploadPanel()).getByRole("button", { name: /^(Analyse file|Uploading…)$/ });
const uploadStatus = () => within(uploadPanel()).getByRole("status");

/** A capture file that is still being read: some of its packets are in, and no alert yet. */
function reading(packets: number): SessionDetail {
  return makeSessionDetail({
    source_label: "capture.pcap",
    status: "running",
    ended_at: null,
    duration_seconds: 3,
    packets_total: packets,
    bytes_total: packets * 60,
    flows_total: 2,
    active_flows: 0,
    alerts_total: 0,
    alerts_by_rule: {},
    external_ips: [],
    enrichment: NO_LOOKUPS,
  });
}

/** The same file once it was read to the end. */
const analysed = () => makeSessionDetail({ source_label: "capture.pcap" });

/** How far the server is with the capture file: not received yet, being read, or analysed. */
interface Server {
  stage: "idle" | "reading" | "done";
}

/**
 * An API that takes a capture file, reads it for a while and then has the results. The test moves
 * the stage, and every answer follows it. `ended` is how the analysis ends.
 */
function uploadServer(server: Server, ended: SessionDetail = analysed()): NetworkHandlers {
  return {
    status: () =>
      makeNetworkStatus({
        analysis: analysis(server.stage === "reading" ? { running: true, session_id: SESSION_ID } : {}),
      }),
    pcap: () => {
      server.stage = "reading";
      return jsonResponse(reading(10), { status: 202 });
    },
    session: () => (server.stage === "done" ? ended : reading(25)),
    sessions: () =>
      makeSessionPage(
        server.stage === "idle"
          ? []
          : [
              makeSession({
                source_label: "capture.pcap",
                status: server.stage === "reading" ? "running" : ended.status,
              }),
            ],
      ),
    alerts: () => makeAlertPage(server.stage === "done" ? [makeAlert()] : []),
    flows: () => makeFlowPage(server.stage === "done" ? [makeFlow()] : []),
  };
}

describe("NetworkPage: analysing a capture file", () => {
  withFakeClock();

  async function open(server: Server, ended?: SessionDetail): Promise<NetworkFetch> {
    const fetchMock = networkApi(uploadServer(server, ended));
    renderPage();
    await flush();
    // An analysis found running is asked about by a timer that only exists once the status is in.
    await flush();
    return fetchMock;
  }

  async function send(file: File): Promise<void> {
    fireEvent.change(fileInput(), { target: { files: [file] } });
    await act(async () => {
      fireEvent.click(analyseButton());
    });
    await flush();
  }

  it("sends the file, follows the analysis, and opens the session when it is complete", async () => {
    const server: Server = { stage: "idle" };
    const fetchMock = await open(server);
    expect(screen.getByText(/^No sessions yet\./)).toBeInTheDocument();
    expect(fileInput()).toBeEnabled();
    expect(analyseButton()).toHaveAttribute("aria-disabled", "true");

    const file = capture("capture.pcap");
    await send(file);

    const sent = sentTo(fetchMock, PCAP_URL);
    expect(sent?.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-File-Name": "capture.pcap",
    });
    expect(sent?.body).toBe(file);
    expect(address()).toBe(SESSION_LINK);
    expect(uploadStatus()).toHaveTextContent(
      "Analysis in progress. 10 packets and 600 B read so far, 2 flows, 0 alerts.",
    );
    expect(fileInput()).toBeDisabled();
    expect(analyseButton()).toHaveAttribute("aria-disabled", "true");
    expect(within(panel("Session summary")).getByText("Running")).toBeInTheDocument();
    expect(within(panel("Session history")).getByText("capture.pcap")).toBeInTheDocument();

    await flush(PCAP_POLL_MS);
    expect(uploadStatus()).toHaveTextContent(
      "Analysis in progress. 25 packets and 1.46 KB read so far, 2 flows, 0 alerts.",
    );
    expect(valueOf(panel("Session summary"), "Packets")).toHaveTextContent(/^25$/);

    server.stage = "done";
    await flush(PCAP_POLL_MS);

    expect(uploadStatus()).toHaveTextContent("✓ Analysis complete: 40 packets, 1 alert.");
    expect(fileInput()).toBeEnabled();
    expect(address()).toBe(SESSION_LINK);
    const summary = panel("Session summary");
    expect(within(summary).getByText("Completed")).toBeInTheDocument();
    expect(valueOf(summary, "Packets")).toHaveTextContent(/^40$/);
    expect(within(panel("Alerts")).getByRole("heading", { level: 3, name: "Port scan" })).toBeInTheDocument();
    expect(
      within(panel("Session history")).getByRole("button", { name: "Viewing session capture.pcap" }),
    ).toHaveAttribute("aria-current", "true");
  });

  it("follows an analysis of its own that was running when the page opened, and opens its results", async () => {
    const server: Server = { stage: "reading" };
    const fetchMock = await open(server);

    expect(address()).toBe("/network");
    expect(screen.getByText("No session is open yet.")).toBeInTheDocument();
    expect(uploadStatus()).toHaveTextContent(
      "Analysis in progress. 25 packets and 1.46 KB read so far, 2 flows, 0 alerts.",
    );
    expect(fileInput()).toBeDisabled();
    expect(requested(fetchMock, "POST")).toEqual([]);

    server.stage = "done";
    await flush(PCAP_POLL_MS);

    expect(address()).toBe(SESSION_LINK);
    expect(uploadStatus()).toHaveTextContent("✓ Analysis complete: 40 packets, 1 alert.");
    expect(within(panel("Session summary")).getByText("Completed")).toBeInTheDocument();
    expect(fileInput()).toBeEnabled();
  });

  it("does not open an analysis that failed, but offers the partial results", async () => {
    const server: Server = { stage: "reading" };
    await open(
      server,
      makeSessionDetail({
        source_label: "capture.pcap",
        status: "failed",
        error_code: "analysis_timeout",
        message: "Stopped after the limit.",
        packets_total: 12,
      }),
    );

    server.stage = "done";
    await flush(PCAP_POLL_MS);

    const outcome = within(uploadStatus()).getByRole("note");
    expect(outcome).toHaveTextContent("Analysis timed out");
    expect(outcome).toHaveTextContent("12 packets were read before it stopped, and they are kept.");
    expect(address()).toBe("/network");

    fireEvent.click(within(outcome).getByRole("button", { name: "Open partial results" }));
    await flush();

    expect(address()).toBe(SESSION_LINK);
    const summary = panel("Session summary");
    expect(within(summary).getByText("Failed")).toBeInTheDocument();
    expect(valueOf(summary, "Source")).toHaveTextContent("Capture file: capture.pcap");
    expect(within(summary).getByText("Analysis timed out")).toBeInTheDocument();
  });
});

describe("NetworkPage: a capture file that is not sent", () => {
  it.each<[string, File, string]>([
    [
      "a file of another kind",
      capture("notes.txt"),
      '"notes.txt" is not a capture file. Choose a file that ends in .pcap, .pcapng or .cap.',
    ],
    ["a file over the limit", capture("big.pcap", 2 * 1024 * 1024), '"big.pcap" is 2.00 MB, over the 1 MB limit.'],
  ])("says so for %s, and sends nothing", async (_name, file, reason) => {
    const user = person();
    const fetchMock = await openPage({ status: () => makeNetworkStatus({ analysis: analysis({ max_upload_mb: 1 }) }) });
    expect(fileInput()).toHaveAccessibleDescription(/, up to 1 MB\./);

    await user.upload(fileInput(), file);
    await user.click(analyseButton());

    const notice = within(uploadPanel()).getByRole("alert");
    expect(notice).toHaveTextContent("The file was not sent");
    expect(notice).toHaveTextContent(reason);
    expect(requested(fetchMock, "POST")).toEqual([]);
    expect(address()).toBe("/network");
  });

  it.each<[string, number, string, string, string]>([
    [
      "a file that is not a capture",
      422,
      "invalid_capture_file",
      "Not a readable capture file",
      "not a readable PCAP or PCAPNG capture",
    ],
    [
      "a file over the server's limit",
      413,
      "file_too_large",
      "File too large",
      "The file is larger than the 50 MB upload limit.",
    ],
    [
      "an upload while another analysis runs",
      409,
      "analysis_already_running",
      "Another analysis is in progress",
      "A capture file is being analysed right now.",
    ],
    [
      "an account without the role",
      403,
      "forbidden",
      "Security analyst role needed",
      "Network monitoring needs the security analyst role.",
    ],
  ])("says so calmly when the server refuses %s", async (_name, status, code, title, wording) => {
    const user = person();
    const fetchMock = await openPage({ pcap: () => apiError(status, code) });

    await user.upload(fileInput(), capture());
    await user.click(analyseButton());

    const notice = await within(uploadPanel()).findByRole("alert");
    expect(notice).toHaveTextContent(title);
    expect(notice).toHaveTextContent(wording);
    expect(requested(fetchMock, "POST")).toEqual([PCAP_URL]);
    expect(address()).toBe("/network");
    expect(screen.getByText("No session is open yet.")).toBeInTheDocument();
  });

  it("reads the status again when the server says another analysis is running, and pauses uploads", async () => {
    const user = person();
    let busy = false;
    const fetchMock = await openPage({
      status: () => makeNetworkStatus({ analysis: analysis({ running: busy }) }),
      pcap: () => {
        busy = true;
        return apiError(409, "analysis_already_running");
      },
    });
    expect(reads(fetchMock, `${API}/status`)).toBe(1);
    expect(fileInput()).toBeEnabled();

    await user.upload(fileInput(), capture());
    await user.click(analyseButton());

    await waitFor(() => expect(fileInput()).toBeDisabled());
    expect(reads(fetchMock, `${API}/status`)).toBe(2);
    expect(within(uploadPanel()).getByRole("alert")).toHaveTextContent("Another analysis is in progress");
    expect(uploadStatus()).toHaveTextContent(
      "Analysis in progress. A capture file is being analysed by someone else, in another tab or by another user. Uploads are paused until it finishes.",
    );
  });

  it("pauses uploads while an analysis of someone else runs, and sends nothing", async () => {
    const fetchMock = await openPage({
      status: () => makeNetworkStatus({ analysis: analysis({ running: true }) }),
    });

    expect(fileInput()).toBeDisabled();
    expect(analyseButton()).toHaveAttribute("aria-disabled", "true");
    expect(uploadStatus()).toHaveTextContent(
      "Analysis in progress. A capture file is being analysed by someone else, in another tab or by another user. Uploads are paused until it finishes.",
    );
    fireEvent.click(analyseButton());
    expect(requested(fetchMock, "POST")).toEqual([]);
  });
});

describe("NetworkPage: the session history", () => {
  const SAMPLE = makeSession({ alerts_total: 0 });
  const OTHER = makeSession({
    id: OTHER_SESSION_ID,
    source_label: "other.pcapng",
    started_at: "2026-05-19T09:00:00Z",
    ended_at: "2026-05-19T09:02:00Z",
    duration_seconds: 120,
    packets_total: 1_234,
    bytes_total: 90_000,
    flows_total: 20,
    alerts_total: 0,
  });
  const LIVE = makeSession({
    source_kind: "live",
    interface: "eth0",
    source_label: "eth0",
    status: "stopped",
    alerts_total: 0,
  });

  /** An API that keeps these sessions, and forgets one when told to delete it. */
  function keeping(...sessions: CaptureSession[]): NetworkHandlers {
    let kept = sessions;
    return {
      ...NO_TRAFFIC,
      sessions: () => makeSessionPage(kept),
      session: ({ id }) => {
        const found = kept.find((candidate) => candidate.id === id);
        if (found === undefined) return apiError(404, "session_not_found");
        return makeSessionDetail({ ...found, alerts_by_rule: {}, external_ips: [], enrichment: NO_LOOKUPS });
      },
      remove: ({ id }) => {
        kept = kept.filter((candidate) => candidate.id !== id);
        return null;
      },
    };
  }

  const askToDelete = (user: UserEvent, area: HTMLElement, name = "Delete session") =>
    user.click(within(area).getByRole("button", { name }));
  const dialog = () => screen.getByRole("dialog", { name: "Delete this session?" });
  const noDialog = () => waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

  it("opens the session picked from the history, and marks it as the one on show", async () => {
    const user = userEvent.setup();
    await openPage(keeping(SAMPLE, OTHER));
    expect(screen.getByText("No session is open yet.")).toBeInTheDocument();
    const history = panel("Session history");

    await user.click(await within(history).findByRole("button", { name: "View session other.pcapng" }));

    expect(address()).toBe(OTHER_LINK);
    await waitFor(() => expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("other.pcapng"));
    expect(valueOf(panel("Session summary"), "Packets")).toHaveTextContent(/^1,234$/);
    expect(screen.getByText("You are looking at a session you picked.")).toBeInTheDocument();
    expect(within(history).getByRole("button", { name: "Viewing session other.pcapng" })).toHaveAttribute(
      "aria-current",
      "true",
    );
    expect(within(history).getByRole("button", { name: "View session sample.pcap" })).not.toHaveAttribute(
      "aria-current",
    );

    await user.click(within(history).getByRole("button", { name: "View session sample.pcap" }));

    expect(address()).toBe(SESSION_LINK);
    await waitFor(() => expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("sample.pcap"));
  });

  it("deletes the session on show after a confirmation, and leaves it", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession(keeping(SAMPLE, OTHER), OTHER_LINK);

    await askToDelete(user, panel("Session summary"));

    const confirmation = dialog();
    expect(within(confirmation).getByText("other.pcapng")).toBeInTheDocument();
    expect(within(confirmation).getByText("19-05-2026 02:30:00 PM IST")).toBeInTheDocument();
    expect(within(confirmation).getByText(/1,234 packets, 20 flows,\s+0 alerts/)).toBeInTheDocument();
    expect(requested(fetchMock, "DELETE")).toEqual([]);

    await user.click(within(confirmation).getByRole("button", { name: "Delete session" }));
    await noDialog();

    expect(requested(fetchMock, "DELETE")).toEqual([`${API}/sessions/${OTHER_SESSION_ID}`]);
    expect(await screen.findByText("No session is open yet.")).toBeInTheDocument();
    expect(address()).toBe("/network");
    const history = panel("Session history");
    await waitFor(() => expect(within(history).queryByText("other.pcapng")).not.toBeInTheDocument());
    expect(within(history).getByText("sample.pcap")).toBeInTheDocument();
  });

  it("deletes another session from the history without leaving the one on show", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession(keeping(SAMPLE, OTHER));

    const history = await screen.findByRole("table", { name: "Capture sessions, newest first" });
    await askToDelete(user, history, "Delete session other.pcapng");
    expect(within(dialog()).getByText("other.pcapng")).toBeInTheDocument();
    await user.click(within(dialog()).getByRole("button", { name: "Delete session" }));
    await noDialog();

    expect(requested(fetchMock, "DELETE")).toEqual([`${API}/sessions/${OTHER_SESSION_ID}`]);
    expect(address()).toBe(SESSION_LINK);
    expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("sample.pcap");
    await waitFor(() => expect(within(panel("Session history")).queryByText("other.pcapng")).not.toBeInTheDocument());
  });

  it.each<[string, (user: UserEvent) => Promise<void>]>([
    ["the Cancel button", (user) => user.click(within(dialog()).getByRole("button", { name: "Cancel" }))],
    ["the Escape key", (user) => user.keyboard("{Escape}")],
  ])("keeps the session when the dialog is closed with %s", async (_how, close) => {
    const user = userEvent.setup();
    const fetchMock = await openSession(keeping(SAMPLE, OTHER));
    await askToDelete(user, panel("Session summary"));
    expect(dialog()).toBeInTheDocument();

    await close(user);
    await noDialog();

    expect(requested(fetchMock, "DELETE")).toEqual([]);
    expect(address()).toBe(SESSION_LINK);
    expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("sample.pcap");
    expect(within(panel("Session history")).getByText("other.pcapng")).toBeInTheDocument();
  });

  it("keeps the dialog open and explains when the server says the session is still running", async () => {
    const user = userEvent.setup();
    const fetchMock = await openSession({
      ...keeping(SAMPLE, OTHER),
      remove: () => apiError(409, "session_running", "Still running."),
    });
    await askToDelete(user, panel("Session summary"));

    await user.click(within(dialog()).getByRole("button", { name: "Delete session" }));

    const notice = await within(dialog()).findByRole("alert");
    expect(notice).toHaveTextContent("Session still running");
    expect(notice).toHaveTextContent(
      "That session is still running. Stop the capture, or wait for the analysis to finish, before deleting it.",
    );
    expect(requested(fetchMock, "DELETE")).toEqual([`${API}/sessions/${SESSION_ID}`]);
    expect(address()).toBe(SESSION_LINK);
    expect(within(dialog()).getByRole("button", { name: "Delete session" })).toBeInTheDocument();
    expect(within(panel("Session history")).getByText("sample.pcap")).toBeInTheDocument();

    await user.click(within(dialog()).getByRole("button", { name: "Cancel" }));
    await noDialog();
    await askToDelete(user, panel("Session summary"));

    expect(within(dialog()).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("does not bring a deleted capture back while the status still names it", async () => {
    const user = userEvent.setup();
    const stopped = makeNetworkStatus({ state: "stopped", interface: "eth0", session_id: LIVE.id });
    const fetchMock = await openSession({ ...keeping(LIVE, OTHER), status: () => stopped }, "/network");
    expect(valueOf(panel("Session summary"), "Source")).toHaveTextContent("Live capture: eth0");

    await askToDelete(user, panel("Session summary"));
    await user.click(within(dialog()).getByRole("button", { name: "Delete session" }));
    await noDialog();

    expect(requested(fetchMock, "DELETE")).toEqual([`${API}/sessions/${LIVE.id}`]);
    expect(await screen.findByText("No session is open yet.")).toBeInTheDocument();
    const history = panel("Session history");
    await waitFor(() => expect(within(history).queryByText("eth0")).not.toBeInTheDocument());
    expect(within(history).getByText("other.pcapng")).toBeInTheDocument();
    expect(screen.queryByText("Session not found")).not.toBeInTheDocument();
    expect(address()).toBe("/network");
  });
});
