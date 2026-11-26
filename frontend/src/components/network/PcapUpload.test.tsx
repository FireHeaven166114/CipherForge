import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PCAP_MAX_POLL_FAILURES, PCAP_POLL_MS } from "../../features/network/polling";
import { jsonResponse } from "../../test/http";
import { apiError, networkApi, requested } from "../../test/networkApi";
import { SESSION_ID, makeSessionDetail } from "../../test/networkFixtures";
import type { AnalysisStatus, SessionDetail } from "../../types/network";
import PcapUpload from "./PcapUpload";

type Handlers = Parameters<typeof networkApi>[0];

const PCAP_URL = "/api/v1/network/pcap";
const SESSION_URL = `/api/v1/network/sessions/${SESSION_ID}`;

function capture(name = "sample.pcap", bytes = 2048): File {
  return new File([new Uint8Array(bytes)], name);
}

function running(packets = 10, overrides: Partial<SessionDetail> = {}): SessionDetail {
  return makeSessionDetail({
    status: "running",
    ended_at: null,
    packets_total: packets,
    bytes_total: packets * 60,
    flows_total: 2,
    alerts_total: 0,
    ...overrides,
  });
}

const accepted = (session: SessionDetail) => jsonResponse(session, { status: 202 });

/** Answers each request with the next session, and keeps giving the last one once they run out. */
function inOrder(...sessions: SessionDetail[]): () => SessionDetail {
  let index = 0;
  return () => {
    const next = sessions[Math.min(index, sessions.length - 1)];
    index += 1;
    if (next === undefined) throw new Error("No answer was given for the session.");
    return next;
  };
}

function deferred() {
  let release: (response: Response) => void = () => undefined;
  const response = new Promise<Response>((resolve) => {
    release = resolve;
  });
  return { response, release };
}

function setup(analysis: Partial<AnalysisStatus> = {}, handlers: Handlers = {}) {
  const fetchMock = networkApi(handlers);
  const callbacks = { onStarted: vi.fn(), onFinished: vi.fn(), onRefused: vi.fn(), onOpen: vi.fn() };
  render(
    <PcapUpload analysis={{ running: false, session_id: null, max_upload_mb: 50, ...analysis }} {...callbacks} />,
  );
  return { fetchMock, ...callbacks };
}

const fileInput = () => screen.getByLabelText("Capture file");
const analyseButton = () => screen.getByRole("button", { name: /^(Analyse file|Uploading…)$/ });
const posts = (fetchMock: ReturnType<typeof networkApi>) => requested(fetchMock, "POST");
const sessionReads = (fetchMock: ReturnType<typeof networkApi>) =>
  requested(fetchMock, "GET").filter((address) => address === SESSION_URL);

// The picker's own filter is only a hint, and people can always choose "All files".
function person(): UserEvent {
  return userEvent.setup({ applyAccept: false });
}

async function send(user: UserEvent, file: File): Promise<void> {
  await user.upload(fileInput(), file);
  await user.click(analyseButton());
}

describe("PcapUpload: the form", () => {
  it("says what it takes: the file types, the size limit, and that the server has the last word", () => {
    setup();

    expect(screen.getByRole("heading", { level: 2, name: "Analyse a capture file" })).toBeInTheDocument();
    expect(fileInput()).toHaveAttribute("type", "file");
    expect(fileInput()).toHaveAttribute("accept", ".pcap,.pcapng,.cap");
    expect(fileInput()).toHaveAccessibleDescription(
      "Files ending in .pcap, .pcapng or .cap, up to 50 MB. This page checks the name and size first to save you an upload; the server checks again and has the last word.",
    );
    expect(screen.getByText(/The server keeps the results, not the file\./)).toBeInTheDocument();
  });

  it("names the limit the server announced, and none when the server announced none", () => {
    const { unmount } = render(
      <PcapUpload
        analysis={{ running: false, session_id: null, max_upload_mb: 5 }}
        onStarted={vi.fn()}
        onFinished={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    expect(fileInput()).toHaveAccessibleDescription(/, up to 5 MB\./);
    unmount();

    render(
      <PcapUpload
        analysis={{ running: false, session_id: null, max_upload_mb: 0 }}
        onStarted={vi.fn()}
        onFinished={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    expect(fileInput()).toHaveAccessibleDescription(/^Files ending in \.pcap, \.pcapng or \.cap\. This page checks/);
  });

  it("shows the chosen file with its size, as text", async () => {
    setup();

    await person().upload(fileInput(), capture("capture.pcap", 2048));

    expect(screen.getByText(/^Selected:/)).toHaveTextContent("Selected: capture.pcap (2.00 KB)");
  });

  it("never reads a file name as markup", async () => {
    setup();
    const name = "<img src=x onerror=alert(1)>.pcap";

    await person().upload(fileInput(), capture(name));

    expect(screen.getByText(name)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("does nothing until a file has been chosen", async () => {
    const { fetchMock } = setup();
    const user = person();

    expect(analyseButton()).toHaveAttribute("aria-disabled", "true");
    await user.click(analyseButton());

    expect(posts(fetchMock)).toEqual([]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("can be reached and used from the keyboard", async () => {
    setup();
    const user = person();

    await user.tab();
    expect(fileInput()).toHaveFocus();
    await user.tab();
    expect(analyseButton()).toHaveFocus();
  });

  it("announces what happens in a polite live region", () => {
    setup();

    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
  });
});

describe("PcapUpload: a file this page will not send", () => {
  it("refuses a file of the wrong kind, says why, and sends nothing", async () => {
    const { fetchMock, onRefused } = setup();

    await send(person(), capture("notes.txt"));

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent("The file was not sent");
    expect(notice).toHaveTextContent('"notes.txt" is not a capture file. Choose a file that ends in .pcap, .pcapng or .cap.');
    expect(posts(fetchMock)).toEqual([]);
    expect(onRefused).not.toHaveBeenCalled();
  });

  it("refuses an empty file", async () => {
    const { fetchMock } = setup();

    await send(person(), capture("empty.pcap", 0));

    expect(await screen.findByRole("alert")).toHaveTextContent('"empty.pcap" is empty, so there is nothing to analyse.');
    expect(posts(fetchMock)).toEqual([]);
  });

  it("refuses a file over the limit the server announced, naming both sizes", async () => {
    const { fetchMock } = setup({ max_upload_mb: 1 });

    await send(person(), capture("big.pcap", 2 * 1024 * 1024));

    expect(await screen.findByRole("alert")).toHaveTextContent('"big.pcap" is 2.00 MB, over the 1 MB limit.');
    expect(posts(fetchMock)).toEqual([]);
  });

  it("lets the server decide on size when it announced no limit", async () => {
    const { fetchMock } = setup({ max_upload_mb: 0 }, { pcap: () => accepted(running()) });

    await send(person(), capture("big.pcap", 2 * 1024 * 1024));

    expect(await screen.findByText(/Analysis in progress\./)).toBeInTheDocument();
    expect(posts(fetchMock)).toEqual([PCAP_URL]);
  });

  it.each(["TRACE.PCAPNG", "Trace.PcAp", "trace.cap"])(
    "sends %s, because the extension is a capture one in any letter case",
    async (name) => {
      const { fetchMock } = setup({}, { pcap: () => accepted(running()) });

      await send(person(), capture(name));
      await screen.findByText(/Analysis in progress\./);

      expect(posts(fetchMock)).toEqual([PCAP_URL]);
    },
  );

  it("clears the message with Dismiss", async () => {
    setup();
    const user = person();
    await send(user, capture("notes.txt"));
    await screen.findByRole("alert");

    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("clears the message when another file is chosen", async () => {
    setup();
    const user = person();
    await send(user, capture("notes.txt"));
    await screen.findByRole("alert");

    await user.upload(fileInput(), capture("trace.pcap"));

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText(/^Selected:/)).toHaveTextContent("Selected: trace.pcap");
  });
});

describe("PcapUpload: sending the file", () => {
  it("sends the bytes as they are with the name in a header, then tells the page", async () => {
    const { fetchMock, onStarted } = setup({}, { pcap: () => accepted(running(10)) });
    const file = capture("my capture.pcap");

    await send(person(), file);

    expect(await screen.findByText(/Analysis in progress\./)).toHaveTextContent(
      "Analysis in progress. 10 packets and 600 B read so far, 2 flows, 0 alerts.",
    );
    const [, init] = fetchMock.mock.calls.find(([address]) => String(address) === PCAP_URL) ?? [];
    expect(init?.method).toBe("POST");
    expect(init?.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-File-Name": "my%20capture.pcap",
    });
    expect(init?.body).toBe(file);
    expect(onStarted).toHaveBeenCalledTimes(1);
    expect(onStarted).toHaveBeenCalledWith(expect.objectContaining({ id: SESSION_ID, status: "running" }));
  });

  it("clears the chosen file once the server has taken it", async () => {
    setup({}, { pcap: () => accepted(running()) });

    await send(person(), capture());
    await screen.findByText(/Analysis in progress\./);

    expect(screen.queryByText(/^Selected:/)).not.toBeInTheDocument();
    expect(fileInput()).toHaveValue("");
  });

  it("shows that the file is on its way and ignores a second press meanwhile", async () => {
    const held = deferred();
    const { fetchMock } = setup({}, { pcap: () => held.response });
    const user = person();

    await send(user, capture("sample.pcap"));

    expect(screen.getByRole("status")).toHaveTextContent("Uploading sample.pcap…");
    expect(analyseButton()).toHaveTextContent("Uploading…");
    expect(analyseButton()).toHaveAttribute("aria-disabled", "true");
    expect(fileInput()).toBeDisabled();
    await user.click(analyseButton());
    expect(posts(fetchMock)).toEqual([PCAP_URL]);

    await act(async () => {
      held.release(accepted(running()));
    });
    expect(await screen.findByText(/Analysis in progress\./)).toBeInTheDocument();
    expect(analyseButton()).toHaveTextContent("Analyse file");
  });
});

describe("PcapUpload: a file the server refuses", () => {
  const cases: ReadonlyArray<[string, Response, string]> = [
    [
      "a file that is not a capture",
      apiError(422, "invalid_capture_file", "Not a capture."),
      "Not a readable capture file",
    ],
    [
      "a file over the server's limit",
      apiError(413, "file_too_large", "Too big."),
      "The file is larger than the 50 MB upload limit.",
    ],
    [
      "an upload while another analysis runs",
      apiError(409, "analysis_already_running", "Busy."),
      "A capture file is being analysed right now.",
    ],
    [
      "an account without the role",
      apiError(403, "forbidden", "No."),
      "Network monitoring needs the security analyst role.",
    ],
    [
      "too many requests",
      apiError(429, "rate_limited", "Slow down.", { "Retry-After": "30" }),
      "Try again in 30 seconds.",
    ],
    [
      "an upload cut short",
      apiError(400, "upload_interrupted", "Cut."),
      "The upload stopped before the whole file arrived.",
    ],
  ];

  it.each(cases)("says so calmly for %s, and tells the page", async (_name, response, wording) => {
    const { fetchMock, onRefused } = setup({}, { pcap: () => response.clone() });

    await send(person(), capture());

    const notice = await screen.findByRole("alert");
    expect(notice).toHaveTextContent(wording);
    expect(within(notice).queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
    expect(sessionReads(fetchMock)).toEqual([]);
    expect(screen.queryByText(/Analysis in progress/)).not.toBeInTheDocument();
    expect(onRefused).toHaveBeenCalledTimes(1);
  });

  it("keeps the API's own message for a failure it has no wording for", async () => {
    setup({}, { pcap: () => apiError(500, "internal_error", "The disk is full.") });

    await send(person(), capture());

    expect(await screen.findByRole("alert")).toHaveTextContent("The disk is full.");
  });

  it("clears the refusal when the next file is sent", async () => {
    let calls = 0;
    setup({}, { pcap: () => (++calls === 1 ? apiError(422, "invalid_capture_file") : accepted(running())) });
    const user = person();
    await send(user, capture("bad.pcap"));
    await screen.findByRole("alert");

    await send(user, capture("good.pcap"));

    expect(await screen.findByText(/Analysis in progress\./)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("names the limit the page was told about when the server says the file is too large", async () => {
    setup({ max_upload_mb: 12 }, { pcap: () => apiError(413, "file_too_large") });

    await send(person(), capture());

    expect(await screen.findByRole("alert")).toHaveTextContent("The file is larger than the 12 MB upload limit.");
  });
});

describe("PcapUpload: following the analysis", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function flush(ms = 0): Promise<void> {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
      for (let pass = 0; pass < 5; pass += 1) await vi.advanceTimersByTimeAsync(0);
    });
  }

  async function upload(file: File = capture()): Promise<void> {
    fireEvent.change(fileInput(), { target: { files: [file] } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Analyse file" }));
    });
    await flush();
  }

  it("asks again every second and a half, and ends with a summary of the analysis", async () => {
    const { fetchMock, onFinished } = setup(
      {},
      {
        pcap: () => accepted(running(10)),
        session: inOrder(running(25), makeSessionDetail({ status: "completed", packets_total: 40, alerts_total: 1 })),
      },
    );
    await upload();
    expect(screen.getByRole("status")).toHaveTextContent("Analysis in progress. 10 packets and 600 B read so far");
    expect(fileInput()).toBeDisabled();

    await flush(PCAP_POLL_MS - 1);
    expect(sessionReads(fetchMock)).toHaveLength(0);
    await flush(1);
    expect(sessionReads(fetchMock)).toHaveLength(1);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Analysis in progress. 25 packets and 1.46 KB read so far, 2 flows, 0 alerts.",
    );
    expect(onFinished).not.toHaveBeenCalled();

    await flush(PCAP_POLL_MS);

    expect(screen.getByRole("status")).toHaveTextContent("✓ Analysis complete: 40 packets, 1 alert.");
    expect(screen.queryByText(/Analysis in progress/)).not.toBeInTheDocument();
    expect(onFinished).toHaveBeenCalledTimes(1);
    expect(onFinished).toHaveBeenCalledWith(expect.objectContaining({ status: "completed", packets_total: 40 }));
    expect(fileInput()).toBeEnabled();
    await flush(PCAP_POLL_MS * 3);
    expect(sessionReads(fetchMock)).toHaveLength(2);
  });

  it("says when the analysis ended with a note, such as a capture that was cut short", async () => {
    setup(
      {},
      {
        pcap: () => accepted(running()),
        session: () => makeSessionDetail({ status: "completed", error_code: "capture_truncated", packets_total: 30 }),
      },
    );
    await upload();
    await flush(PCAP_POLL_MS);

    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("✓ Analysis complete: 30 packets, 1 alert.");
    expect(within(status).getByRole("note")).toHaveTextContent("Capture file cut short");
    expect(within(status).getByRole("note")).toHaveTextContent("Everything before that point was analysed.");
  });

  it("reports a failed analysis, what was kept, and opens the partial results on request", async () => {
    const { onOpen } = setup(
      {},
      {
        pcap: () => accepted(running()),
        session: () =>
          makeSessionDetail({
            status: "failed",
            error_code: "analysis_timeout",
            message: "Stopped after the limit.",
            packets_total: 12,
          }),
      },
    );
    await upload();
    await flush(PCAP_POLL_MS);

    const notice = within(screen.getByRole("status")).getByRole("note");
    expect(notice).toHaveTextContent("Analysis timed out");
    expect(notice).toHaveTextContent("The analysis took too long and was stopped.");
    expect(notice).toHaveTextContent("12 packets were read before it stopped, and they are kept.");
    fireEvent.click(within(notice).getByRole("button", { name: "Open partial results" }));
    expect(onOpen).toHaveBeenCalledWith(SESSION_ID);
  });

  it("offers no partial results when nothing was read, and falls back to the server's own message", async () => {
    setup(
      {},
      {
        pcap: () => accepted(running()),
        session: () =>
          makeSessionDetail({
            status: "failed",
            error_code: null,
            message: "The file ended at once.",
            packets_total: 0,
          }),
      },
    );
    await upload();
    await flush(PCAP_POLL_MS);

    const notice = within(screen.getByRole("status")).getByRole("note");
    expect(notice).toHaveTextContent("The analysis failed");
    expect(notice).toHaveTextContent("The file ended at once.");
    expect(within(notice).queryByRole("button", { name: "Open partial results" })).not.toBeInTheDocument();
  });

  it("says 'packet' for a single packet that was kept", async () => {
    setup(
      {},
      {
        pcap: () => accepted(running()),
        session: () => makeSessionDetail({ status: "failed", error_code: "analysis_failed", packets_total: 1 }),
      },
    );
    await upload();
    await flush(PCAP_POLL_MS);

    expect(screen.getByRole("status")).toHaveTextContent("1 packet was read before it stopped, and it is kept.");
  });

  it("clears the outcome with Dismiss", async () => {
    setup(
      {},
      { pcap: () => accepted(running()), session: () => makeSessionDetail({ status: "completed" }) },
    );
    await upload();
    await flush(PCAP_POLL_MS);
    expect(screen.getByRole("status")).toHaveTextContent("Analysis complete");

    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.getByRole("status")).toBeEmptyDOMElement();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("gives up after repeated failures to check, and follows again when the reader asks", async () => {
    let failing = true;
    const { fetchMock, onFinished } = setup(
      {},
      {
        pcap: () => accepted(running()),
        session: () =>
          failing ? apiError(503, "internal_error", "The server is down.") : makeSessionDetail({ status: "completed" }),
      },
    );
    await upload();

    await flush(PCAP_POLL_MS * PCAP_MAX_POLL_FAILURES);

    expect(sessionReads(fetchMock)).toHaveLength(PCAP_MAX_POLL_FAILURES);
    const notice = screen.getByRole("alert");
    expect(notice).toHaveTextContent("The server is down.");
    failing = false;
    fireEvent.click(within(notice).getByRole("button", { name: "Try again" }));
    await flush(PCAP_POLL_MS);

    expect(screen.getByRole("status")).toHaveTextContent("Analysis complete");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(onFinished).toHaveBeenCalledTimes(1);
  });
});

describe("PcapUpload: an analysis that is already running", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  async function flush(ms = 0): Promise<void> {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
      for (let pass = 0; pass < 5; pass += 1) await vi.advanceTimersByTimeAsync(0);
    });
  }

  it("pauses uploads while an analysis from another tab or user runs, and does not follow it", async () => {
    const { fetchMock } = setup({ running: true, session_id: null });
    await flush(PCAP_POLL_MS * 2);

    expect(fileInput()).toBeDisabled();
    expect(analyseButton()).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("status")).toHaveTextContent(
      "Analysis in progress. A capture file is being analysed by someone else, in another tab or by another user. Uploads are paused until it finishes.",
    );
    expect(sessionReads(fetchMock)).toEqual([]);
    expect(posts(fetchMock)).toEqual([]);
  });

  it("does not send a file while an analysis runs, even when the button is pressed", async () => {
    const { fetchMock } = setup({ running: true, session_id: null });

    fireEvent.click(analyseButton());
    await flush();

    expect(posts(fetchMock)).toEqual([]);
  });

  it("follows the caller's own analysis at once, as after reloading the page, and reports its end", async () => {
    const { fetchMock, onFinished } = setup(
      { running: true, session_id: SESSION_ID },
      { session: inOrder(running(5), makeSessionDetail({ status: "completed", packets_total: 9 })) },
    );
    expect(screen.getByRole("status")).toHaveTextContent("Waiting for the first progress report…");

    await flush();
    expect(sessionReads(fetchMock)).toHaveLength(1);
    expect(screen.getByRole("status")).toHaveTextContent("Analysis in progress. 5 packets and 300 B read so far");
    expect(fileInput()).toBeDisabled();

    await flush(PCAP_POLL_MS);

    expect(screen.getByRole("status")).toHaveTextContent("✓ Analysis complete: 9 packets, 1 alert.");
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it("is open for a file again when no analysis runs", () => {
    setup();

    expect(fileInput()).toBeEnabled();
    expect(screen.queryByText(/Uploads are paused/)).not.toBeInTheDocument();
  });
});
