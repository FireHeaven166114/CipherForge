import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { SESSION_ID } from "../test/networkFixtures";
import { useNetworkDelete } from "./useNetworkDelete";

describe("useNetworkDelete", () => {
  it("deletes the session and says so", async () => {
    const fetchMock = stubFetch(() => new Response(null, { status: 204 }));
    const { result } = renderHook(() => useNetworkDelete());

    let outcome: unknown = null;
    await act(async () => {
      outcome = await result.current.remove(SESSION_ID);
    });

    expect(outcome).toBe(true);
    expect(result.current.error).toBeNull();
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(`/api/v1/network/sessions/${SESSION_ID}`);
    expect(init?.method).toBe("DELETE");
  });

  it("keeps the API's reason when a running session cannot be deleted", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "session_running", message: "The session is still running." } },
        { status: 409 },
      ),
    );
    const { result } = renderHook(() => useNetworkDelete());

    let outcome: unknown = "unset";
    await act(async () => {
      outcome = await result.current.remove(SESSION_ID);
    });

    expect(outcome).toBeNull();
    expect(result.current.error).toMatchObject({ status: 409, code: "session_running" });
    expect(result.current.busy).toBe(false);
  });
});
