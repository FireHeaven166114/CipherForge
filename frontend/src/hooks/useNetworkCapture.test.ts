import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { makeNetworkStatus } from "../test/networkFixtures";
import { useNetworkCapture } from "./useNetworkCapture";

/** A fetch that answers when the test says so. */
function deferredFetch() {
  let answer: (response: Response) => void = () => undefined;
  const fetchMock = stubFetch(
    () =>
      new Promise<Response>((resolve) => {
        answer = resolve;
      }),
  );
  return { fetchMock, answer: (response: Response) => answer(response) };
}

describe("useNetworkCapture", () => {
  it("starts the chosen interface and hands back the status the API reports", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useNetworkCapture());
    expect(result.current.busy).toBeNull();

    let outcome: Promise<unknown> = Promise.resolve();
    act(() => {
      outcome = result.current.start("eth0");
    });
    expect(result.current.busy).toBe("start");

    const started = makeNetworkStatus({ state: "running", interface: "eth0" });
    answer(jsonResponse(started));
    await expect(outcome).resolves.toEqual(started);
    await waitFor(() => expect(result.current.busy).toBeNull());

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/network/capture/start");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({ interface: "eth0" });
  });

  it("stops the capture", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useNetworkCapture());

    let outcome: Promise<unknown> = Promise.resolve();
    act(() => {
      outcome = result.current.stop();
    });
    expect(result.current.busy).toBe("stop");

    answer(jsonResponse(makeNetworkStatus({ state: "stopped" })));
    await expect(outcome).resolves.toMatchObject({ state: "stopped" });
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/network/capture/stop");
  });

  it("allows one command at a time", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useNetworkCapture());

    let first: Promise<unknown> = Promise.resolve();
    act(() => {
      first = result.current.start("eth0");
    });
    let second: unknown = "unset";
    await act(async () => {
      second = await result.current.stop();
    });

    expect(second).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    answer(jsonResponse(makeNetworkStatus({ state: "running" })));
    await first;
  });

  it("keeps the API's reason when a command is refused, until reset", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "capture_already_running", message: "A capture is already running." } },
        { status: 409 },
      ),
    );
    const { result } = renderHook(() => useNetworkCapture());

    let outcome: unknown = "unset";
    await act(async () => {
      outcome = await result.current.start("eth0");
    });

    expect(outcome).toBeNull();
    expect(result.current.error).toMatchObject({ status: 409, code: "capture_already_running" });
    expect(result.current.busy).toBeNull();

    act(() => result.current.reset());
    expect(result.current.error).toBeNull();
  });
});
