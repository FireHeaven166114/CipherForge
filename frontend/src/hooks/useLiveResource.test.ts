import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../services/apiClient";
import { useLiveResource } from "./useLiveResource";

function setVisibility(value: DocumentVisibilityState): void {
  vi.spyOn(document, "visibilityState", "get").mockReturnValue(value);
}

async function flush(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
  });
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe("useLiveResource", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-14T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("is loading, then ready with the data and when it arrived", async () => {
    const load = vi.fn().mockResolvedValue({ answer: 42 });

    const { result } = renderHook(() => useLiveResource(load));
    expect(result.current.state).toEqual({ status: "loading" });
    await flush();

    expect(result.current.state).toEqual({
      status: "ready",
      data: { answer: 42 },
      updatedAt: Date.parse("2026-05-14T12:00:00Z"),
      refreshing: false,
      refreshError: null,
    });
  });

  it("reports a failure of the first request, then recovers on refresh", async () => {
    const apiError = new ApiError({ message: "Down.", status: 503, code: "unavailable" });
    const load = vi.fn().mockRejectedValueOnce(apiError).mockResolvedValue("back");

    const { result } = renderHook(() => useLiveResource(load));
    await flush();
    expect(result.current.state).toEqual({ status: "error", error: apiError });

    act(() => result.current.refresh());
    expect(result.current.state).toEqual({ status: "loading" });
    await flush();

    expect(result.current.state).toMatchObject({ status: "ready", data: "back" });
  });

  it("keeps the old data on screen while a refresh is in flight", async () => {
    const resolvers: Array<(value: number) => void> = [];
    const load = vi.fn(
      () =>
        new Promise<number>((resolve) => {
          resolvers.push(resolve);
        }),
    );

    const { result } = renderHook(() => useLiveResource(load));
    await act(async () => resolvers[0]?.(1));
    expect(result.current.state).toMatchObject({ status: "ready", data: 1, refreshing: false });

    act(() => result.current.refresh());
    expect(result.current.state).toMatchObject({ status: "ready", data: 1, refreshing: true });

    await act(async () => resolvers[1]?.(2));
    expect(result.current.state).toMatchObject({ status: "ready", data: 2, refreshing: false });
  });

  it("keeps the old data and says why when a refresh fails", async () => {
    const apiError = new ApiError({ message: "Slow.", status: 504, code: "timeout" });
    const load = vi.fn().mockResolvedValueOnce("first").mockRejectedValueOnce(apiError);

    const { result } = renderHook(() => useLiveResource(load));
    await flush();
    act(() => result.current.refresh());
    await flush();

    expect(result.current.state).toMatchObject({
      status: "ready",
      data: "first",
      refreshing: false,
      refreshError: apiError,
    });
  });

  it("asks again on its own once the interval passes", async () => {
    setVisibility("visible");
    const load = vi.fn().mockResolvedValueOnce(1).mockResolvedValue(2);

    const { result } = renderHook(() => useLiveResource(load, 10_000));
    await flush();
    expect(load).toHaveBeenCalledTimes(1);

    await advance(10_000);

    expect(load).toHaveBeenCalledTimes(2);
    expect(result.current.state).toMatchObject({ status: "ready", data: 2 });
  });

  it("does not poll while the tab is hidden, and catches up when it returns", async () => {
    setVisibility("hidden");
    const load = vi.fn().mockResolvedValue(1);

    renderHook(() => useLiveResource(load, 10_000));
    await flush();
    await advance(30_000);
    expect(load).toHaveBeenCalledTimes(1);

    setVisibility("visible");
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
    });

    expect(load).toHaveBeenCalledTimes(2);
  });

  it("does not poll when the interval is zero", async () => {
    setVisibility("visible");
    const load = vi.fn().mockResolvedValue(1);

    renderHook(() => useLiveResource(load, 0));
    await flush();
    await advance(600_000);

    expect(load).toHaveBeenCalledTimes(1);
  });

  it("drops the old data when the loader changes", async () => {
    const first = vi.fn().mockResolvedValue("one");
    const second = vi.fn(() => new Promise<string>(() => {}));

    const { result, rerender } = renderHook(({ load }) => useLiveResource(load), {
      initialProps: { load: first as (signal: AbortSignal) => Promise<string> },
    });
    await flush();
    expect(result.current.state).toMatchObject({ status: "ready", data: "one" });

    rerender({ load: second });

    expect(result.current.state).toEqual({ status: "loading" });
  });

  it("cancels the request and stops the timer on unmount", async () => {
    setVisibility("visible");
    let signal: AbortSignal | undefined;
    const load = vi.fn((s: AbortSignal) => {
      signal = s;
      return new Promise<never>(() => {});
    });

    const { unmount } = renderHook(() => useLiveResource(load, 10_000));
    unmount();
    await advance(60_000);

    expect(signal?.aborted).toBe(true);
    expect(load).toHaveBeenCalledTimes(1);
  });
});
