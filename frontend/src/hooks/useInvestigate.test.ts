import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { makeInvestigation } from "../test/fixtures";
import { hangingFetch, jsonResponse, stubFetch } from "../test/http";
import { useInvestigate } from "./useInvestigate";

describe("useInvestigate", () => {
  it("goes from idle to loading to the investigation, sending the refresh flag", async () => {
    const investigation = makeInvestigation();
    const fetchMock = stubFetch(() => jsonResponse(investigation));

    const { result } = renderHook(() => useInvestigate());
    expect(result.current.state).toEqual({ status: "idle" });

    act(() => result.current.run("203.0.113.9", true));

    expect(result.current.state).toEqual({ status: "loading", indicator: "203.0.113.9" });
    await waitFor(() => expect(result.current.state.status).toBe("success"));
    expect(result.current.state).toEqual({ status: "success", investigation });
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe("/api/v1/intel/investigate");
    expect(JSON.parse(String(init?.body))).toEqual({ indicator: "203.0.113.9", refresh: true });
  });

  it("reports a rejected request as an error", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "rate_limited", message: "Too many investigations.", correlation_id: "c-1" } },
        { status: 429, headers: { "Content-Type": "application/json", "Retry-After": "30" } },
      ),
    );

    const { result } = renderHook(() => useInvestigate());
    act(() => result.current.run("203.0.113.9", false));

    await waitFor(() => expect(result.current.state.status).toBe("error"));
    const state = result.current.state;
    expect(state.status === "error" && state.error.status).toBe(429);
    expect(state.status === "error" && state.error.retryAfterSeconds).toBe(30);
  });

  it("cancels a request in flight when a new one starts", async () => {
    const second = makeInvestigation();
    let calls = 0;
    stubFetch((url, init) => {
      calls += 1;
      return calls === 1 ? (hangingFetch()(url, init) as Promise<Response>) : jsonResponse(second);
    });

    const { result } = renderHook(() => useInvestigate());
    act(() => result.current.run("203.0.113.1", false));
    act(() => result.current.run("203.0.113.2", false));

    await waitFor(() => expect(result.current.state.status).toBe("success"));
    expect(result.current.state).toEqual({ status: "success", investigation: second });
  });

  it("starts the lookup straight away when given an initial request, and only once", async () => {
    const investigation = makeInvestigation();
    const fetchMock = stubFetch(() => jsonResponse(investigation));

    const { result, rerender } = renderHook(
      ({ indicator }) => useInvestigate({ indicator, refresh: false }),
      { initialProps: { indicator: "203.0.113.9" } },
    );
    expect(result.current.state).toEqual({ status: "loading", indicator: "203.0.113.9" });

    await waitFor(() => expect(result.current.state.status).toBe("success"));
    // The initial request is read once; changing it later does not start another lookup.
    rerender({ indicator: "203.0.113.10" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      indicator: "203.0.113.9",
      refresh: false,
    });
  });

  it("never mistakes an earlier result for a new request after reset", async () => {
    const first = makeInvestigation();
    let calls = 0;
    stubFetch((url, init) => {
      calls += 1;
      return calls === 1 ? jsonResponse(first) : (hangingFetch()(url, init) as Promise<Response>);
    });

    const { result } = renderHook(() => useInvestigate());
    act(() => result.current.run("203.0.113.9", false));
    await waitFor(() => expect(result.current.state.status).toBe("success"));

    act(() => result.current.reset());
    expect(result.current.state).toEqual({ status: "idle" });

    // If request ids were reused after reset, the old result would reappear here.
    act(() => result.current.run("203.0.113.10", false));
    expect(result.current.state).toEqual({ status: "loading", indicator: "203.0.113.10" });
  });
});
