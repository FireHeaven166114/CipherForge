import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { makeStoredFile } from "../test/filesFixtures";
import type { StoredFile } from "../types/files";
import { useFileUpload } from "./useFileUpload";

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

const NOTE = new File(["hello"], "note.txt", { type: "text/plain" });

describe("useFileUpload", () => {
  it("is busy while the file is sent and then holds the file the server stored", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useFileUpload());
    expect(result.current.busy).toBe(false);

    let outcome: Promise<StoredFile | null> = Promise.resolve(null);
    act(() => {
      outcome = result.current.start(NOTE);
    });
    expect(result.current.busy).toBe(true);

    const stored = makeStoredFile({ name: "note.txt", size_bytes: 5 });
    answer(jsonResponse(stored, { status: 201 }));
    await expect(outcome).resolves.toEqual(stored);
    await waitFor(() => expect(result.current.busy).toBe(false));
    expect(result.current.uploaded).toEqual(stored);
    expect(result.current.error).toBeNull();

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe("/api/v1/files");
    expect(init?.method).toBe("POST");
  });

  it("starts nothing while an upload is already running", async () => {
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useFileUpload());

    let first: Promise<StoredFile | null> = Promise.resolve(null);
    act(() => {
      first = result.current.start(NOTE);
    });
    let second: StoredFile | null = makeStoredFile();
    await act(async () => {
      second = await result.current.start(NOTE);
    });

    expect(second).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    answer(jsonResponse(makeStoredFile(), { status: 201 }));
    await first;
  });

  it("keeps the failure, and no stored file, until the next upload or a reset", async () => {
    let failing = true;
    stubFetch(() =>
      failing
        ? jsonResponse({ error: { code: "empty_file", message: "Empty." } }, { status: 422 })
        : jsonResponse(makeStoredFile(), { status: 201 }),
    );
    const { result } = renderHook(() => useFileUpload());

    await act(async () => {
      await result.current.start(NOTE);
    });
    expect(result.current.error).toMatchObject({ status: 422, code: "empty_file" });
    expect(result.current.uploaded).toBeNull();
    expect(result.current.busy).toBe(false);

    act(() => result.current.reset());
    expect(result.current.error).toBeNull();

    failing = false;
    await act(async () => {
      await result.current.start(NOTE);
    });
    expect(result.current.error).toBeNull();
    expect(result.current.uploaded).not.toBeNull();

    act(() => result.current.reset());
    expect(result.current.uploaded).toBeNull();
  });

  it("clears the previous success when the next upload starts", async () => {
    const { answer } = deferredFetch();
    const { result } = renderHook(() => useFileUpload());

    act(() => {
      void result.current.start(NOTE);
    });
    answer(jsonResponse(makeStoredFile({ name: "first.txt" }), { status: 201 }));
    await waitFor(() => expect(result.current.uploaded?.name).toBe("first.txt"));

    act(() => {
      void result.current.start(NOTE);
    });
    expect(result.current.uploaded).toBeNull();
    expect(result.current.busy).toBe(true);
  });

  it("cancels an upload that is still being sent when the page is left", () => {
    const { fetchMock } = deferredFetch();
    const { result, unmount } = renderHook(() => useFileUpload());

    act(() => {
      void result.current.start(NOTE);
    });
    unmount();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
});
