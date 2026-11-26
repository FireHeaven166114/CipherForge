import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../services/apiClient";
import { useNetworkAction } from "./useNetworkAction";

/** A promise the test settles when it says so. */
function deferred<T>() {
  let resolve: (value: T) => void = () => undefined;
  let reject: (reason: unknown) => void = () => undefined;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("useNetworkAction", () => {
  it("is busy, with the arguments it was given, until the action answers", async () => {
    const pending = deferred<string>();
    const action = vi.fn((name: string) => pending.promise.then((value) => `${value} ${name}`));
    const { result } = renderHook(() => useNetworkAction(action));
    expect(result.current.busy).toBe(false);
    expect(result.current.pending).toBeNull();

    let outcome: Promise<string | null> = Promise.resolve(null);
    act(() => {
      outcome = result.current.run("eth0");
    });
    expect(result.current.busy).toBe(true);
    expect(result.current.pending).toEqual(["eth0"]);

    pending.resolve("done");
    await expect(outcome).resolves.toBe("done eth0");
    await waitFor(() => expect(result.current.busy).toBe(false));
    expect(result.current.pending).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("starts nothing while a run is under way", async () => {
    const pending = deferred<string>();
    const action = vi.fn((name: string) => pending.promise.then((value) => `${value} ${name}`));
    const { result } = renderHook(() => useNetworkAction(action));

    let first: Promise<string | null> = Promise.resolve(null);
    act(() => {
      first = result.current.run("one");
    });
    let second: string | null = "unset";
    await act(async () => {
      second = await result.current.run("two");
    });

    expect(second).toBeNull();
    expect(action).toHaveBeenCalledTimes(1);
    pending.resolve("done");
    await first;
  });

  it("keeps the failure as an API error until it is reset or the next run starts", async () => {
    const failure = new ApiError({ message: "Nope.", status: 409, code: "capture_already_running" });
    const action = vi.fn().mockRejectedValueOnce(failure).mockResolvedValue("ok");
    const { result } = renderHook(() => useNetworkAction(action));

    let outcome: unknown = "unset";
    await act(async () => {
      outcome = await result.current.run();
    });
    expect(outcome).toBeNull();
    expect(result.current.error).toBe(failure);
    expect(result.current.busy).toBe(false);

    act(() => result.current.reset());
    expect(result.current.error).toBeNull();

    await act(async () => {
      await result.current.run();
    });
    expect(result.current.error).toBeNull();
  });

  it("turns anything that is not an API error into a generic one", async () => {
    const action = vi.fn().mockRejectedValue(new TypeError("boom"));
    const { result } = renderHook(() => useNetworkAction(action));

    await act(async () => {
      await result.current.run();
    });

    expect(result.current.error).toMatchObject({ code: "unexpected_error", status: 0 });
  });

  it("lets a run finish after the screen has gone, but hands the result to no one", async () => {
    const pending = deferred<string>();
    const action = vi.fn(() => pending.promise);
    const { result, unmount } = renderHook(() => useNetworkAction(action));

    let outcome: Promise<string | null> = Promise.resolve("unset");
    act(() => {
      outcome = result.current.run();
    });
    unmount();

    pending.resolve("done");
    await expect(outcome).resolves.toBeNull();
    expect(action).toHaveBeenCalledTimes(1);
  });
});
