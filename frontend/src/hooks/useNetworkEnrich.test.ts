import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import { ALERT_ID, SCANNER_IP, makeAlert, makeCompletedEnrichment } from "../test/networkFixtures";
import { useNetworkEnrich } from "./useNetworkEnrich";

describe("useNetworkEnrich", () => {
  it("looks the alert's address up and hands back the alert with its new enrichment", async () => {
    const enriched = makeAlert({ enrichment: makeCompletedEnrichment() });
    const fetchMock = stubFetch(() => jsonResponse(enriched));
    const { result } = renderHook(() => useNetworkEnrich());

    let outcome: unknown = null;
    await act(async () => {
      outcome = await result.current.lookUp(ALERT_ID);
    });

    expect(outcome).toEqual(enriched);
    expect(result.current.busy).toBe(false);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(`/api/v1/network/alerts/${ALERT_ID}/enrich`);
    expect(init?.method).toBe("POST");
    expect(enriched.enrichment.address).toBe(SCANNER_IP);
  });

  it("keeps why the lookup was refused", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "enrichment_disabled", message: "External enrichment is switched off." } },
        { status: 409 },
      ),
    );
    const { result } = renderHook(() => useNetworkEnrich());

    let outcome: unknown = "unset";
    await act(async () => {
      outcome = await result.current.lookUp(ALERT_ID);
    });

    expect(outcome).toBeNull();
    expect(result.current.error).toMatchObject({ status: 409, code: "enrichment_disabled" });
    act(() => result.current.reset());
    expect(result.current.error).toBeNull();
  });
});
