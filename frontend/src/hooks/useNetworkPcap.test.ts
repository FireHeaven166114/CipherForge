import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PCAP_MAX_POLL_FAILURES, PCAP_POLL_MS } from "../features/network/polling";
import { jsonResponse, stubFetch } from "../test/http";
import { SESSION_ID, makeSessionDetail } from "../test/networkFixtures";
import type { SessionDetail } from "../types/network";
import { type PcapOptions, useNetworkPcap } from "./useNetworkPcap";

const PCAP_URL = "/api/v1/network/pcap";
const SESSION_URL = `/api/v1/network/sessions/${SESSION_ID}`;

function capture(name = "sample.pcap", bytes = 64): File {
  return new File([new Uint8Array(bytes)], name);
}

const running = (packets: number): SessionDetail =>
  makeSessionDetail({ status: "running", ended_at: null, packets_total: packets });

function failure(status: number, code: string) {
  return jsonResponse({ error: { code, message: `The API said ${code}.` } }, { status });
}

/** Lets the timers due within `ms` fire and everything they started settle. */
async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
    await vi.advanceTimersByTimeAsync(0);
  });
}

async function send(action: () => Promise<void>): Promise<void> {
  await act(async () => {
    const pending = action();
    await vi.advanceTimersByTimeAsync(0);
    await pending;
  });
}

function setup(options: Partial<PcapOptions> = {}) {
  const onStarted = vi.fn();
  const onFinished = vi.fn();
  const onRefused = vi.fn();
  const view = renderHook(
    (props: Partial<PcapOptions>) =>
      useNetworkPcap({ maxUploadMb: 50, followSessionId: null, onStarted, onFinished, onRefused, ...props }),
    { initialProps: options },
  );
  return { ...view, onStarted, onFinished, onRefused };
}

describe("useNetworkPcap", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends the file as it is, then follows the analysis until it completes", async () => {
    const answers = [running(25), makeSessionDetail({ status: "completed", packets_total: 40 })];
    const fetchMock = stubFetch((_url, init) =>
      init?.method === "POST" ? jsonResponse(running(10), { status: 202 }) : jsonResponse(answers.shift()),
    );
    const { result, onStarted, onFinished } = setup();
    expect(result.current.phase).toBe("idle");

    const file = capture();
    await send(() => result.current.upload(file));

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(PCAP_URL);
    expect(init?.method).toBe("POST");
    expect(init?.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-File-Name": "sample.pcap",
    });
    expect(init?.body).toBe(file);
    expect(result.current.phase).toBe("analysing");
    expect(result.current.session?.packets_total).toBe(10);
    expect(onStarted).toHaveBeenCalledTimes(1);

    await advance(PCAP_POLL_MS - 1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(fetchMock.mock.calls[1]?.[0]).toBe(SESSION_URL);
    expect(result.current.phase).toBe("analysing");
    expect(result.current.session?.packets_total).toBe(25);
    expect(onFinished).not.toHaveBeenCalled();

    await advance(PCAP_POLL_MS);
    expect(result.current.phase).toBe("completed");
    expect(result.current.session).toMatchObject({ status: "completed", packets_total: 40 });
    expect(onFinished).toHaveBeenCalledTimes(1);
    expect(onFinished).toHaveBeenCalledWith(expect.objectContaining({ id: SESSION_ID, status: "completed" }));

    await advance(PCAP_POLL_MS * 4);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("shows the uploading phase, with the file name, while the file is on its way", async () => {
    let accept: (response: Response) => void = () => undefined;
    stubFetch(
      () =>
        new Promise<Response>((resolve) => {
          accept = resolve;
        }),
    );
    const { result } = setup();

    let pending: Promise<void> = Promise.resolve();
    act(() => {
      pending = result.current.upload(capture("trace.pcapng"));
    });
    expect(result.current.phase).toBe("uploading");
    expect(result.current.fileName).toBe("trace.pcapng");

    await act(async () => {
      accept(jsonResponse(running(0), { status: 202 }));
      await pending;
    });
    expect(result.current.phase).toBe("analysing");
    expect(result.current.fileName).toBeNull();
  });

  it("sends one file at a time", async () => {
    let accept: (response: Response) => void = () => undefined;
    const fetchMock = stubFetch(
      () =>
        new Promise<Response>((resolve) => {
          accept = resolve;
        }),
    );
    const { result } = setup();

    let first: Promise<void> = Promise.resolve();
    act(() => {
      first = result.current.upload(capture());
    });
    await act(async () => {
      await result.current.upload(capture("second.pcap"));
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await act(async () => {
      accept(jsonResponse(running(0), { status: 202 }));
      await first;
    });
  });

  it("refuses a file of the wrong kind or size without sending anything", async () => {
    const fetchMock = stubFetch(() => jsonResponse(running(0), { status: 202 }));
    const { result, onRefused } = setup({ maxUploadMb: 1 });

    await send(() => result.current.upload(capture("notes.txt")));
    expect(result.current.rejection).toContain(".pcap, .pcapng or .cap");
    expect(result.current.phase).toBe("idle");

    await send(() => result.current.upload(capture("big.pcap", 1024 * 1024 + 1)));
    expect(result.current.rejection).toContain("over the 1 MB limit");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(onRefused).not.toHaveBeenCalled();

    await send(() => result.current.upload(capture("small.pcap")));
    expect(result.current.rejection).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the server's refusal, tells the page, and follows nothing", async () => {
    const fetchMock = stubFetch(() => failure(422, "invalid_capture_file"));
    const { result, onStarted, onRefused } = setup();

    await send(() => result.current.upload(capture()));

    expect(result.current.error).toMatchObject({ status: 422, code: "invalid_capture_file" });
    expect(result.current.canRetry).toBe(false);
    expect(result.current.phase).toBe("idle");
    expect(onStarted).not.toHaveBeenCalled();
    expect(onRefused).toHaveBeenCalledTimes(1);
    await advance(PCAP_POLL_MS * 4);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    act(() => result.current.dismiss());
    expect(result.current.error).toBeNull();
  });

  it("reports an analysis that failed, with what the server recorded", async () => {
    stubFetch((_url, init) =>
      init?.method === "POST"
        ? jsonResponse(running(3), { status: 202 })
        : jsonResponse(
            makeSessionDetail({
              status: "failed",
              error_code: "capture_truncated",
              message: "The capture ends in the middle of a packet.",
            }),
          ),
    );
    const { result, onFinished } = setup();

    await send(() => result.current.upload(capture()));
    await advance(PCAP_POLL_MS);

    expect(result.current.phase).toBe("failed");
    expect(result.current.session).toMatchObject({ status: "failed", error_code: "capture_truncated" });
    expect(onFinished).toHaveBeenCalledWith(expect.objectContaining({ status: "failed" }));
  });

  it("is done at once when the server already has the result", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse(makeSessionDetail({ status: "completed" }), { status: 202 }),
    );
    const { result, onStarted, onFinished } = setup();

    await send(() => result.current.upload(capture()));

    expect(result.current.phase).toBe("completed");
    expect(onStarted).toHaveBeenCalledTimes(1);
    expect(onFinished).toHaveBeenCalledTimes(1);
    await advance(PCAP_POLL_MS * 3);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("puts up with a failed check or two, and gives up on the third in a row", async () => {
    let polls = 0;
    stubFetch((_url, init) => {
      if (init?.method === "POST") return jsonResponse(running(1), { status: 202 });
      polls += 1;
      return polls <= 2 || polls > 3 ? failure(503, "unavailable") : jsonResponse(running(7));
    });
    const { result } = setup();

    await send(() => result.current.upload(capture()));
    await advance(PCAP_POLL_MS * 2);
    expect(result.current.error).toBeNull();

    await advance(PCAP_POLL_MS);
    expect(result.current.session?.packets_total).toBe(7);

    for (let failed = 0; failed < PCAP_MAX_POLL_FAILURES; failed += 1) {
      expect(result.current.canRetry).toBe(false);
      await advance(PCAP_POLL_MS);
    }
    expect(result.current.phase).toBe("analysing");
    expect(result.current.canRetry).toBe(true);
    expect(result.current.error).toMatchObject({ status: 503 });

    const calls = polls;
    await advance(PCAP_POLL_MS * 3);
    expect(polls).toBe(calls);
  });

  it("follows the analysis again when asked after it was lost", async () => {
    let healthy = false;
    stubFetch((_url, init) => {
      if (init?.method === "POST") return jsonResponse(running(1), { status: 202 });
      return healthy ? jsonResponse(makeSessionDetail({ status: "completed" })) : failure(503, "unavailable");
    });
    const { result, onFinished } = setup();

    await send(() => result.current.upload(capture()));
    await advance(PCAP_POLL_MS * PCAP_MAX_POLL_FAILURES);
    expect(result.current.canRetry).toBe(true);

    healthy = true;
    act(() => result.current.retry());
    expect(result.current.error).toBeNull();
    await advance(PCAP_POLL_MS);

    expect(result.current.phase).toBe("completed");
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it("stops at once when the session is gone", async () => {
    let polls = 0;
    stubFetch((_url, init) => {
      if (init?.method === "POST") return jsonResponse(running(1), { status: 202 });
      polls += 1;
      return failure(404, "session_not_found");
    });
    const { result, onFinished } = setup();

    await send(() => result.current.upload(capture()));
    await advance(PCAP_POLL_MS);

    expect(polls).toBe(1);
    expect(result.current.error).toMatchObject({ status: 404, code: "session_not_found" });
    expect(result.current.canRetry).toBe(false);
    expect(result.current.phase).toBe("idle");
    expect(onFinished).not.toHaveBeenCalled();
    await advance(PCAP_POLL_MS * 3);
    expect(polls).toBe(1);
  });

  it("follows an analysis the server reports as the caller's own, asking at once", async () => {
    const answers = [running(5), makeSessionDetail({ status: "completed" })];
    const fetchMock = stubFetch(() => jsonResponse(answers.shift()));
    const { result, rerender, onStarted, onFinished } = setup({ followSessionId: SESSION_ID });
    expect(result.current.phase).toBe("analysing");
    expect(result.current.session).toBeNull();

    await advance(0);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(SESSION_URL);
    expect(result.current.session?.packets_total).toBe(5);

    await advance(PCAP_POLL_MS);
    expect(result.current.phase).toBe("completed");
    expect(onFinished).toHaveBeenCalledTimes(1);
    expect(onStarted).not.toHaveBeenCalled();

    // The status may still name the finished analysis for a moment: it is not followed again.
    rerender({ followSessionId: SESSION_ID });
    await advance(PCAP_POLL_MS * 3);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("stops following when the server no longer reports the analysis as running", async () => {
    const fetchMock = stubFetch(() => jsonResponse(running(5)));
    const { result, rerender } = setup({ followSessionId: SESSION_ID });
    await advance(0);
    expect(result.current.phase).toBe("analysing");

    rerender({ followSessionId: null });
    expect(result.current.phase).toBe("idle");
    await advance(PCAP_POLL_MS * 3);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("clears the outcome of the last analysis on request", async () => {
    stubFetch(() => jsonResponse(makeSessionDetail({ status: "completed" }), { status: 202 }));
    const { result } = setup();
    await send(() => result.current.upload(capture()));
    expect(result.current.phase).toBe("completed");

    act(() => result.current.dismiss());

    expect(result.current.phase).toBe("idle");
    expect(result.current.session).toBeNull();
  });
});
