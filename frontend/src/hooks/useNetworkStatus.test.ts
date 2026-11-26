import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { IDLE_POLL_MS, LIVE_POLL_MS } from "../features/network/polling";
import { jsonResponse, stubFetch } from "../test/http";
import { SESSION_ID, makeNetworkStatus, makeSessionDetail } from "../test/networkFixtures";
import type { CaptureState, SessionStatus } from "../types/network";
import { useNetworkSession, useNetworkStatus } from "./useNetworkStatus";

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe("useNetworkStatus and useNetworkSession", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("asks for the status at a relaxed pace, then every 2 seconds once a capture runs", async () => {
    let state: CaptureState = "ready";
    const fetchMock = stubFetch(() => jsonResponse(makeNetworkStatus({ state })));

    const { result } = renderHook(() => useNetworkStatus());
    await advance(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.current.state).toMatchObject({ status: "ready", data: { state: "ready" } });

    state = "running";
    await advance(IDLE_POLL_MS - 1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await advance(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.current.state).toMatchObject({ data: { state: "running" } });

    await advance(LIVE_POLL_MS);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    await advance(LIVE_POLL_MS);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("goes back to the relaxed pace when the capture has stopped", async () => {
    let state: CaptureState = "running";
    const fetchMock = stubFetch(() => jsonResponse(makeNetworkStatus({ state })));

    renderHook(() => useNetworkStatus());
    await advance(0);
    state = "stopped";
    await advance(LIVE_POLL_MS);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await advance(LIVE_POLL_MS * 3);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await advance(IDLE_POLL_MS);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("polls a session fast while it runs and slowly once it is complete", async () => {
    let status: SessionStatus = "running";
    const fetchMock = stubFetch((url) => {
      expect(url).toBe(`/api/v1/network/sessions/${SESSION_ID}`);
      return jsonResponse(makeSessionDetail({ status }));
    });

    const { result } = renderHook(() => useNetworkSession(SESSION_ID));
    await advance(0);
    expect(result.current.intervalMs).toBe(LIVE_POLL_MS);
    expect(result.current.resource.state).toMatchObject({ status: "ready" });

    status = "completed";
    await advance(LIVE_POLL_MS);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.current.intervalMs).toBe(IDLE_POLL_MS);

    await advance(LIVE_POLL_MS * 3);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("starts over, with no old answer on screen, when another session is chosen", async () => {
    const OTHER = "0d4c3b2a-9e8f-4a7b-8c6d-5e4f3a2b1c0d";
    stubFetch((url) =>
      jsonResponse(makeSessionDetail({ id: url.endsWith(OTHER) ? OTHER : SESSION_ID })),
    );

    const { result, rerender } = renderHook(({ id }) => useNetworkSession(id), {
      initialProps: { id: SESSION_ID },
    });
    await advance(0);
    expect(result.current.resource.state).toMatchObject({ data: { id: SESSION_ID } });

    rerender({ id: OTHER });
    expect(result.current.resource.state).toEqual({ status: "loading" });
    await advance(0);
    expect(result.current.resource.state).toMatchObject({ data: { id: OTHER } });
  });
});
