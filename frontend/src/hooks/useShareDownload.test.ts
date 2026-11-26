import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SHARE_TOKEN, stubBlobDownload } from "../test/filesFixtures";
import { jsonResponse, stubFetch } from "../test/http";
import { useShareDownload } from "./useShareDownload";

const DISPOSITION = `attachment; filename="report.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`;

function fileResponse(disposition: string | null = DISPOSITION): Response {
  const headers = new Headers({ "Content-Type": "application/octet-stream" });
  if (disposition !== null) headers.set("Content-Disposition", disposition);
  return new Response("hello", { status: 200, headers });
}

function failure(status: number, code: string, headers: Record<string, string> = {}): Response {
  return jsonResponse({ error: { code, message: "Refused.", correlation_id: "corr-1" } }, { status, headers });
}

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

describe("useShareDownload", () => {
  it("saves the file under the name the server sent and reports it done", async () => {
    const saved = stubBlobDownload();
    const fetchMock = stubFetch(() => fileResponse());
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));
    expect(result.current.phase).toEqual({ kind: "idle" });

    await act(async () => {
      await result.current.submit(null);
    });

    expect(result.current.phase).toEqual({ kind: "done", fileName: "résumé.pdf", saved: true });
    expect(saved.clicks).toEqual([{ download: "résumé.pdf", href: "blob:cipherforge-test" }]);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`/api/v1/shares/${SHARE_TOKEN}/download`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });

  it("sends the password in the request body, and only when there is one", async () => {
    stubBlobDownload();
    const fetchMock = stubFetch(() => fileResponse());
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    await act(async () => {
      await result.current.submit("correct horse");
    });

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).not.toContain("correct");
    expect(init?.body).toBe(JSON.stringify({ password: "correct horse" }));
  });

  it("falls back to a neutral name when the response names nothing", async () => {
    const saved = stubBlobDownload();
    stubFetch(() => fileResponse(null));
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    await act(async () => {
      await result.current.submit(null);
    });

    expect(saved.clicks[0]?.download).toBe("download");
  });

  it("sorts a refusal into what the recipient can do about it", async () => {
    let answer = failure(403, "invalid_password");
    stubFetch(() => answer);
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    await act(async () => {
      await result.current.submit("wrong");
    });
    expect(result.current.phase).toMatchObject({
      kind: "failed",
      failure: { kind: "wrong_password", reference: "corr-1" },
      retryAt: null,
    });

    answer = failure(410, "share_revoked");
    await act(async () => {
      await result.current.submit(null);
    });
    expect(result.current.phase).toMatchObject({ kind: "failed", failure: { kind: "revoked" } });
  });

  it("asks the recipient to wait as long as the server says, or a short while when it does not", async () => {
    let answer = failure(429, "too_many_attempts", { "Retry-After": "30" });
    stubFetch(() => answer);
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    const before = Date.now();
    await act(async () => {
      await result.current.submit("wrong");
    });
    const phase = result.current.phase;
    expect(phase.kind).toBe("failed");
    if (phase.kind !== "failed") return;
    expect(phase.retryAt).toBeGreaterThanOrEqual(before + 30_000);
    expect(phase.retryAt).toBeLessThanOrEqual(Date.now() + 30_000);

    answer = failure(429, "rate_limited");
    const again = Date.now();
    await act(async () => {
      await result.current.submit("wrong");
    });
    const next = result.current.phase;
    expect(next.kind === "failed" ? next.retryAt : null).toBeGreaterThanOrEqual(again + 10_000);
  });

  it("does nothing while a download is already running, so a double click uses one download", async () => {
    stubBlobDownload();
    const { fetchMock, answer } = deferredFetch();
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    act(() => {
      void result.current.submit(null);
    });
    expect(result.current.phase).toEqual({ kind: "downloading" });
    await act(async () => {
      await result.current.submit(null);
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    answer(fileResponse());
    await waitFor(() => expect(result.current.phase.kind).toBe("done"));
  });

  it("offers the fetched file again without using another download", async () => {
    const saved = stubBlobDownload();
    const fetchMock = stubFetch(() => fileResponse());
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));
    await act(async () => {
      await result.current.submit(null);
    });

    act(() => result.current.saveAgain());

    expect(saved.clicks).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("says when the browser would not start the save, and lets the recipient try again", async () => {
    const saved = stubBlobDownload();
    saved.createObjectURL.mockImplementation(() => {
      throw new Error("blocked");
    });
    stubFetch(() => fileResponse());
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    await act(async () => {
      await result.current.submit(null);
    });
    expect(result.current.phase).toEqual({ kind: "done", fileName: "résumé.pdf", saved: false });

    saved.createObjectURL.mockImplementation(() => "blob:cipherforge-test");
    act(() => result.current.saveAgain());
    expect(result.current.phase).toEqual({ kind: "done", fileName: "résumé.pdf", saved: true });
  });

  it("does nothing when asked to save again before any file was fetched", () => {
    const saved = stubBlobDownload();
    const { result } = renderHook(() => useShareDownload(SHARE_TOKEN));

    act(() => result.current.saveAgain());

    expect(result.current.phase).toEqual({ kind: "idle" });
    expect(saved.clicks).toHaveLength(0);
  });

  it("cancels a download that is still running when the page is left", () => {
    const { fetchMock } = deferredFetch();
    const { result, unmount } = renderHook(() => useShareDownload(SHARE_TOKEN));

    act(() => {
      void result.current.submit(null);
    });
    unmount();

    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
  });
});
