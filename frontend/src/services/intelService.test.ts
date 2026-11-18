import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import {
  INDICATOR_ID,
  makeInvestigation,
  makeOverview,
  makePage,
  makeStats,
} from "../test/fixtures";
import {
  deleteIndicator,
  deleteIndicators,
  deleteSelected,
  getIndicator,
  getOverview,
  getStats,
  investigateIndicator,
  listIndicators,
} from "./intelService";

const OTHER_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

function notFound() {
  return jsonResponse(
    { error: { code: "not_found", message: "Indicator not found." } },
    { status: 404 },
  );
}

describe("deleteIndicator", () => {
  it("sends DELETE to the indicator's own address, with no body, and returns what was removed", async () => {
    const result = { deleted: [INDICATOR_ID], not_found: [], observations_removed: 2 };
    const fetchMock = stubFetch(() => jsonResponse(result));

    await expect(deleteIndicator(INDICATOR_ID)).resolves.toEqual(result);

    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(url).toBe(`/api/v1/intel/indicators/${INDICATOR_ID}`);
    expect(init?.method).toBe("DELETE");
    expect(init?.body).toBeUndefined();
  });

  it("encodes the id so it can never change the path", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse({ deleted: [], not_found: [], observations_removed: 0 }),
    );

    await deleteIndicator("../stats?x=1");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/intel/indicators/..%2Fstats%3Fx%3D1");
  });

  it("reports a response that is not a deletion result as invalid", async () => {
    stubFetch(() => jsonResponse({ deleted: "yes" }));

    await expect(deleteIndicator(INDICATOR_ID)).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("deleteIndicators", () => {
  it("posts the ids to the bulk address", async () => {
    const result = { deleted: [INDICATOR_ID, OTHER_ID], not_found: [], observations_removed: 5 };
    const fetchMock = stubFetch(() => jsonResponse(result));

    await expect(deleteIndicators([INDICATOR_ID, OTHER_ID])).resolves.toEqual(result);

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/intel/indicators/bulk-delete",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ indicator_ids: [INDICATOR_ID, OTHER_ID] }),
      }),
    );
  });
});

describe("deleteSelected", () => {
  it("deletes a single indicator through its own address", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse({ deleted: [INDICATOR_ID], not_found: [], observations_removed: 1 }),
    );

    await deleteSelected([INDICATOR_ID]);

    expect(fetchMock.mock.calls).toHaveLength(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/api/v1/intel/indicators/${INDICATOR_ID}`);
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe("DELETE");
  });

  it("deletes several in one request", async () => {
    const fetchMock = stubFetch(() =>
      jsonResponse({ deleted: [INDICATOR_ID, OTHER_ID], not_found: [], observations_removed: 0 }),
    );

    await deleteSelected([INDICATOR_ID, OTHER_ID]);

    expect(fetchMock.mock.calls).toHaveLength(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/intel/indicators/bulk-delete");
  });

  it("treats a single indicator that is already gone as a result, not a failure", async () => {
    stubFetch(notFound);

    await expect(deleteSelected([INDICATOR_ID])).resolves.toEqual({
      deleted: [],
      not_found: [INDICATOR_ID],
      observations_removed: 0,
    });
  });

  it("still fails on any other error", async () => {
    stubFetch(() =>
      jsonResponse({ error: { code: "internal_error", message: "Failed." } }, { status: 500 }),
    );

    await expect(deleteSelected([INDICATOR_ID])).rejects.toMatchObject({ status: 500 });
  });
});

describe("investigateIndicator", () => {
  it("posts the indicator and the refresh flag as JSON and returns the investigation", async () => {
    const investigation = makeInvestigation();
    const fetchMock = stubFetch(() => jsonResponse(investigation));

    await expect(
      investigateIndicator({ indicator: "203.0.113.9", refresh: true }),
    ).resolves.toEqual(investigation);

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/intel/investigate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ indicator: "203.0.113.9", refresh: true }),
      }),
    );
  });

  it("does not ask for a refresh unless told to", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));

    await investigateIndicator({ indicator: "example.test" });

    const init = fetchMock.mock.calls[0]?.[1];
    expect(JSON.parse(String(init?.body))).toEqual({ indicator: "example.test", refresh: false });
  });

  it("reports a response that is not an investigation as invalid", async () => {
    stubFetch(() => jsonResponse({ indicator: "203.0.113.9" }));

    await expect(investigateIndicator({ indicator: "203.0.113.9" })).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
});

describe("getIndicator", () => {
  it("reads a stored indicator by id", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));

    await getIndicator(INDICATOR_ID);

    expect(fetchMock).toHaveBeenCalledWith(
      `/api/v1/intel/indicators/${INDICATOR_ID}`,
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("encodes the id so it can never change the path", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));

    await getIndicator("../stats?x=1");

    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/intel/indicators/..%2Fstats%3Fx%3D1");
  });
});

describe("listIndicators", () => {
  it("asks for the default page when there are no filters", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makePage([])));

    await listIndicators();

    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/intel/indicators");
  });

  it("sends only the filters that are set, URL-encoded", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makePage([])));

    await listIndicators({
      type: "domain",
      classification: ["high"],
      q: "a&b=c d",
      sort: "risk",
      limit: 25,
      offset: 50,
    });

    const url = new URL(String(fetchMock.mock.calls[0]?.[0]), "http://localhost");
    expect(url.pathname).toBe("/api/v1/intel/indicators");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      type: "domain",
      classification: "high",
      q: "a&b=c d",
      sort: "risk",
      limit: "25",
      offset: "50",
    });
  });

  it("repeats the classification for several bands and says whether a provider answered", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makePage([])));

    await listIndicators({ classification: ["high", "critical"], assessed: true });
    await listIndicators({ assessed: false });

    const first = new URL(String(fetchMock.mock.calls[0]?.[0]), "http://localhost");
    expect(first.searchParams.getAll("classification")).toEqual(["high", "critical"]);
    expect(first.searchParams.get("assessed")).toBe("true");
    const second = new URL(String(fetchMock.mock.calls[1]?.[0]), "http://localhost");
    expect(second.searchParams.has("classification")).toBe(false);
    expect(second.searchParams.get("assessed")).toBe("false");
  });

  it("keeps an offset of zero and leaves out an empty search", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makePage([])));

    await listIndicators({ q: "", offset: 0 });

    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/intel/indicators?offset=0");
  });
});

describe("getStats", () => {
  it("returns the overview counts", async () => {
    const stats = makeStats();
    stubFetch(() => jsonResponse(stats));

    await expect(getStats()).resolves.toEqual(stats);
  });

  it("rejects counts of the wrong type", async () => {
    stubFetch(() => jsonResponse({ ...makeStats(), total_indicators: "many" }));

    await expect(getStats()).rejects.toMatchObject({ code: "invalid_response" });
  });
});

describe("getOverview", () => {
  it("reads the aggregated dashboard payload", async () => {
    const overview = makeOverview();
    const fetchMock = stubFetch(() => jsonResponse(overview));

    await expect(getOverview()).resolves.toEqual(overview);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/intel/overview",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("rejects a payload with a missing section", async () => {
    // JSON drops undefined, so the response has no "series" at all.
    stubFetch(() => jsonResponse({ ...makeOverview(), series: undefined }));

    await expect(getOverview()).rejects.toMatchObject({ code: "invalid_response" });
  });
});
