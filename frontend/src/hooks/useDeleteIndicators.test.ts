import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { useDeleteIndicators } from "./useDeleteIndicators";

const ID = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";
const DELETED = { deleted: [ID], not_found: [], observations_removed: 2 };

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

describe("useDeleteIndicators", () => {
  it("is busy while the API works and then hands back what was removed", async () => {
    const { answer } = deferredFetch();
    const { result } = renderHook(() => useDeleteIndicators());
    expect(result.current.busy).toBe(false);

    let outcome: Promise<unknown> = Promise.resolve();
    act(() => {
      outcome = result.current.run([ID]);
    });

    expect(result.current.busy).toBe(true);
    answer(jsonResponse(DELETED));
    await expect(outcome).resolves.toEqual(DELETED);
    await waitFor(() => expect(result.current.busy).toBe(false));
    expect(result.current.error).toBeNull();
  });

  it("starts nothing while a deletion is already running", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useDeleteIndicators());

    let first: Promise<unknown> = Promise.resolve();
    act(() => {
      first = result.current.run([ID]);
    });
    let second: unknown = "unset";
    await act(async () => {
      second = await result.current.run([ID]);
    });

    expect(second).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    answer(jsonResponse(DELETED));
    await first;
  });

  it("keeps the failure until it is reset or the next attempt starts", async () => {
    let failing = true;
    stubFetch(() =>
      failing
        ? jsonResponse({ error: { code: "internal_error", message: "Failed." } }, { status: 500 })
        : jsonResponse(DELETED),
    );
    const { result } = renderHook(() => useDeleteIndicators());

    let outcome: unknown = "unset";
    await act(async () => {
      outcome = await result.current.run([ID]);
    });

    expect(outcome).toBeNull();
    expect(result.current.error).toMatchObject({ status: 500 });
    expect(result.current.busy).toBe(false);

    act(() => result.current.reset());
    expect(result.current.error).toBeNull();

    await act(async () => {
      await result.current.run([ID]);
    });
    expect(result.current.error).toMatchObject({ status: 500 });

    failing = false;
    await act(async () => {
      outcome = await result.current.run([ID]);
    });
    expect(outcome).toEqual(DELETED);
    expect(result.current.error).toBeNull();
  });

  it("lets a confirmed deletion finish after the screen has gone, but hands the result to no one", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result, unmount } = renderHook(() => useDeleteIndicators());

    let outcome: Promise<unknown> = Promise.resolve();
    act(() => {
      outcome = result.current.run([ID]);
    });
    unmount();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(false);
    answer(jsonResponse(DELETED));
    await expect(outcome).resolves.toBeNull();
  });
});
