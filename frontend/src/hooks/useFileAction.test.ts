import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ApiError } from "../services/apiClient";
import { useFileAction } from "./useFileAction";

function deferred<T>() {
  let resolve: (value: T) => void = () => undefined;
  let reject: (reason: unknown) => void = () => undefined;
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

const FAILURE = new ApiError({ message: "No.", status: 500, code: "internal_error" });

describe("useFileAction", () => {
  it("is busy while the call runs and then hands back its answer", async () => {
    const call = deferred<string>();
    const { result } = renderHook(() => useFileAction());
    expect(result.current.busy).toBe(false);

    let outcome: Promise<string | null> = Promise.resolve(null);
    act(() => {
      outcome = result.current.run(() => call.promise);
    });
    expect(result.current.busy).toBe(true);

    call.resolve("made");
    await expect(outcome).resolves.toBe("made");
    await waitFor(() => expect(result.current.busy).toBe(false));
    expect(result.current.error).toBeNull();
  });

  it("starts nothing while a call is already running", async () => {
    const call = deferred<string>();
    const { result } = renderHook(() => useFileAction());

    let first: Promise<string | null> = Promise.resolve(null);
    act(() => {
      first = result.current.run(() => call.promise);
    });
    let second: string | null = "unset";
    let started = false;
    await act(async () => {
      second = await result.current.run(() => {
        started = true;
        return Promise.resolve("again");
      });
    });

    expect(second).toBeNull();
    expect(started).toBe(false);
    call.resolve("made");
    await first;
  });

  it("keeps a failure until it is reset or the next call starts", async () => {
    const { result } = renderHook(() => useFileAction());

    let outcome: string | null = "unset";
    await act(async () => {
      outcome = await result.current.run(() => Promise.reject<string>(FAILURE));
    });
    expect(outcome).toBeNull();
    expect(result.current.error).toBe(FAILURE);
    expect(result.current.busy).toBe(false);

    act(() => result.current.reset());
    expect(result.current.error).toBeNull();

    await act(async () => {
      await result.current.run(() => Promise.reject<string>(FAILURE));
    });
    expect(result.current.error).toBe(FAILURE);

    await act(async () => {
      outcome = await result.current.run(() => Promise.resolve("made"));
    });
    expect(outcome).toBe("made");
    expect(result.current.error).toBeNull();
  });

  it("turns anything that is thrown into an ApiError", async () => {
    const { result } = renderHook(() => useFileAction());
    await act(async () => {
      await result.current.run(() => Promise.reject<string>(new Error("boom")));
    });
    expect(result.current.error).toBeInstanceOf(ApiError);
  });

  it("answers undefined, not null, for a call that returns nothing, so success can be told from failure", async () => {
    const { result } = renderHook(() => useFileAction());
    let outcome: void | null = null;
    await act(async () => {
      outcome = await result.current.run(() => Promise.resolve());
    });
    expect(outcome).toBeUndefined();
  });

  it("lets a confirmed call finish after the screen has gone, but hands the answer to no one", async () => {
    const call = deferred<string>();
    const { result, unmount } = renderHook(() => useFileAction());

    let outcome: Promise<string | null> = Promise.resolve("unset");
    act(() => {
      outcome = result.current.run(() => call.promise);
    });
    unmount();

    call.resolve("made");
    await expect(outcome).resolves.toBeNull();
  });
});
