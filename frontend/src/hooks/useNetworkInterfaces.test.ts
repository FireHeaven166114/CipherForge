import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { makeInterface, makeInterfaces } from "../test/networkFixtures";
import { useNetworkInterfaces } from "./useNetworkInterfaces";

describe("useNetworkInterfaces", () => {
  it("reads the interface list once, from the server's cached list", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInterfaces()));
    const { result } = renderHook(() => useNetworkInterfaces());

    expect(result.current.state.status).toBe("loading");
    await waitFor(() => expect(result.current.state.status).toBe("ready"));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/network/interfaces");
  });

  it("asks the server to look at the machine again on refresh, and only then", async () => {
    const lists = [makeInterfaces(), makeInterfaces([makeInterface(), makeInterface({ id: "wlan0", name: "wlan0" })])];
    const fetchMock = stubFetch(() => jsonResponse(lists.shift() ?? makeInterfaces()));
    const { result } = renderHook(() => useNetworkInterfaces());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));

    act(() => result.current.refresh());
    await waitFor(() => {
      const state = result.current.state;
      expect(state.status === "ready" && state.data.interfaces.length).toBe(2);
    });

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/v1/network/interfaces",
      "/api/v1/network/interfaces?refresh=true",
    ]);
  });

  it("keeps the old list on screen while the rescan runs, and when it fails", async () => {
    let calls = 0;
    stubFetch(() => {
      calls += 1;
      return calls === 1
        ? jsonResponse(makeInterfaces())
        : jsonResponse({ error: { code: "rate_limited", message: "Slow down." } }, { status: 429 });
    });
    const { result } = renderHook(() => useNetworkInterfaces());
    await waitFor(() => expect(result.current.state.status).toBe("ready"));

    act(() => result.current.refresh());

    await waitFor(() => {
      const state = result.current.state;
      expect(state.status === "ready" && state.refreshError?.status).toBe(429);
    });
    const state = result.current.state;
    expect(state.status === "ready" && state.data.interfaces).toHaveLength(2);
  });
});
