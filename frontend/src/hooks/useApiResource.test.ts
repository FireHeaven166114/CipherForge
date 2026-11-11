import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../services/apiClient";
import { useApiResource } from "./useApiResource";

describe("useApiResource", () => {
  it("is loading until the request settles, then holds the data", async () => {
    const load = vi.fn().mockResolvedValue({ answer: 42 });

    const { result } = renderHook(() => useApiResource(load));

    expect(result.current.state).toEqual({ status: "loading" });
    await waitFor(() =>
      expect(result.current.state).toEqual({ status: "success", data: { answer: 42 } }),
    );
  });

  it("keeps an ApiError as it is and wraps anything else", async () => {
    const apiError = new ApiError({ message: "Nope.", status: 403, code: "forbidden" });
    const failing = vi.fn().mockRejectedValue(apiError);
    const throwing = vi.fn().mockRejectedValue(new TypeError("boom"));

    const first = renderHook(() => useApiResource(failing));
    const second = renderHook(() => useApiResource(throwing));

    await waitFor(() => expect(first.result.current.state.status).toBe("error"));
    await waitFor(() => expect(second.result.current.state.status).toBe("error"));
    expect(first.result.current.state).toEqual({ status: "error", error: apiError });
    const wrapped = second.result.current.state;
    expect(wrapped.status === "error" && wrapped.error.code).toBe("unexpected_error");
  });

  it("starts over when the loader changes and ignores the cancelled request", async () => {
    const signals: AbortSignal[] = [];
    const resolvers: Array<(value: string) => void> = [];
    const makeLoader = () =>
      vi.fn(
        (signal: AbortSignal) =>
          new Promise<string>((resolve) => {
            signals.push(signal);
            resolvers.push(resolve);
          }),
      );
    const first = makeLoader();
    const second = makeLoader();

    const { result, rerender } = renderHook(({ load }) => useApiResource(load), {
      initialProps: { load: first },
    });
    rerender({ load: second });

    // The change shows "loading" at once; the old request is cancelled.
    expect(result.current.state).toEqual({ status: "loading" });
    expect(signals[0]?.aborted).toBe(true);
    expect(signals[1]?.aborted).toBe(false);

    // A late answer to the cancelled request must not replace the current state.
    await act(async () => {
      resolvers[0]?.("stale");
      resolvers[1]?.("current");
    });
    expect(result.current.state).toEqual({ status: "success", data: "current" });
  });

  it("shows loading again while reload asks for a new answer", async () => {
    let calls = 0;
    const load = vi.fn(() => Promise.resolve(++calls));

    const { result } = renderHook(() => useApiResource(load));
    await waitFor(() => expect(result.current.state).toEqual({ status: "success", data: 1 }));

    act(() => result.current.reload());

    expect(result.current.state).toEqual({ status: "loading" });
    await waitFor(() => expect(result.current.state).toEqual({ status: "success", data: 2 }));
  });

  it("cancels the request when the component goes away", () => {
    let signal: AbortSignal | undefined;
    const load = vi.fn((s: AbortSignal) => {
      signal = s;
      return new Promise<never>(() => {});
    });

    const { unmount } = renderHook(() => useApiResource(load));
    expect(signal?.aborted).toBe(false);
    unmount();

    expect(signal?.aborted).toBe(true);
  });
});
