import { afterEach, describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import {
  ALERT_ID,
  SESSION_ID,
  makeAlert,
  makeAlertPage,
  makeFlowPage,
  makeInterfaces,
  makeNetworkStatus,
  makeRules,
  makeSessionDetail,
  makeSessionPage,
} from "../test/networkFixtures";
import { setTokenProvider } from "./apiClient";
import {
  analysePcap,
  deleteSession,
  enrichAlert,
  getNetworkStatus,
  getSession,
  listAlerts,
  listFlows,
  listInterfaces,
  listRules,
  listSessions,
  startCapture,
  stopCapture,
} from "./networkService";

afterEach(() => {
  setTokenProvider(null);
});

function firstCall(fetchMock: ReturnType<typeof stubFetch>): [string, RequestInit | undefined] {
  const call = fetchMock.mock.calls[0];
  if (!call) throw new Error("fetch was not called");
  return [String(call[0]), call[1]];
}

describe("reading", () => {
  it("asks for the status with the signed-in token and validates the answer", async () => {
    const status = makeNetworkStatus();
    const fetchMock = stubFetch(() => jsonResponse(status));
    setTokenProvider(() => "token-1");

    await expect(getNetworkStatus()).resolves.toEqual(status);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe("/api/v1/network/status");
    expect(init?.method ?? "GET").toBe("GET");
    expect(init?.headers).toMatchObject({ Authorization: "Bearer token-1" });
  });

  it("reports an answer of the wrong shape as invalid instead of passing it on", async () => {
    stubFetch(() => jsonResponse({ state: "ready" }));

    await expect(getNetworkStatus()).rejects.toMatchObject({ code: "invalid_response" });
  });

  it("only asks the server to look at the interfaces again when told to", async () => {
    const interfaces = makeInterfaces();
    const fetchMock = stubFetch(() => jsonResponse(interfaces));

    await listInterfaces();
    await listInterfaces(true);

    expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
      "/api/v1/network/interfaces",
      "/api/v1/network/interfaces?refresh=true",
    ]);
  });

  it("returns the rule catalogue as a list", async () => {
    const rules = makeRules();
    const fetchMock = stubFetch(() => jsonResponse(rules));

    await expect(listRules()).resolves.toEqual(rules);

    expect(firstCall(fetchMock)[0]).toBe("/api/v1/network/rules");
  });

  it("adds paging only when it was given", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeSessionPage()));

    await listSessions();
    await listSessions({ limit: 10, offset: 20 });
    await listSessions({ offset: 0 });

    expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
      "/api/v1/network/sessions",
      "/api/v1/network/sessions?limit=10&offset=20",
      "/api/v1/network/sessions?offset=0",
    ]);
  });

  it("encodes a session id so it can never change the path", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeSessionDetail()));

    await getSession("../status?x=1");

    expect(firstCall(fetchMock)[0]).toBe("/api/v1/network/sessions/..%2Fstatus%3Fx%3D1");
  });

  it("lists the flows of one session with paging", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeFlowPage()));

    await listFlows(SESSION_ID, { limit: 50, offset: 100 });

    expect(firstCall(fetchMock)[0]).toBe(
      `/api/v1/network/sessions/${SESSION_ID}/flows?limit=50&offset=100`,
    );
  });

  it("repeats the severity parameter for every chosen severity and adds the rule and paging", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeAlertPage()));

    await listAlerts(SESSION_ID, {
      severity: ["high", "critical"],
      rule: "NET-001",
      limit: 5,
      offset: 10,
    });
    await listAlerts(SESSION_ID);

    expect(fetchMock.mock.calls.map((call) => String(call[0]))).toEqual([
      `/api/v1/network/sessions/${SESSION_ID}/alerts?severity=high&severity=critical&rule=NET-001&limit=5&offset=10`,
      `/api/v1/network/sessions/${SESSION_ID}/alerts`,
    ]);
  });
});

describe("capture control", () => {
  it("starts a capture on the chosen interface id", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeNetworkStatus()));

    await startCapture("eth-1");

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe("/api/v1/network/capture/start");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(JSON.stringify({ interface: "eth-1" }));
  });

  it("stops the capture with a POST that has no body", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeNetworkStatus()));

    await stopCapture();

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe("/api/v1/network/capture/stop");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });

  it("surfaces the server's reason when a capture cannot start", async () => {
    stubFetch(() =>
      jsonResponse(
        { error: { code: "capture_permission_denied", message: "Run with more privileges." } },
        { status: 403 },
      ),
    );

    await expect(startCapture("eth-1")).rejects.toMatchObject({
      status: 403,
      code: "capture_permission_denied",
    });
  });
});

describe("analysing a capture file", () => {
  it("uploads the raw bytes with the name percent-encoded and returns the new session", async () => {
    const session = makeSessionDetail({ status: "running" });
    const fetchMock = stubFetch(() => jsonResponse(session, { status: 202 }));
    const file = new File(["pcap"], "lab capture #1.pcap");

    await expect(analysePcap(file)).resolves.toEqual(session);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe("/api/v1/network/pcap");
    expect(init?.method).toBe("POST");
    expect(init?.body).toBe(file);
    expect(init?.headers).toMatchObject({
      "Content-Type": "application/octet-stream",
      "X-File-Name": encodeURIComponent("lab capture #1.pcap"),
    });
  });

  it("refuses an answer that is not a session", async () => {
    stubFetch(() => jsonResponse({ id: 1 }, { status: 202 }));

    await expect(analysePcap(new File(["x"], "a.pcap"))).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
});

describe("changing data", () => {
  it("deletes a session with a DELETE that has no body and resolves on 204", async () => {
    const fetchMock = stubFetch(() => new Response(null, { status: 204 }));

    await expect(deleteSession(SESSION_ID)).resolves.toBeUndefined();

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe(`/api/v1/network/sessions/${SESSION_ID}`);
    expect(init?.method).toBe("DELETE");
    expect(init?.body).toBeUndefined();
  });

  it("reports a running session as one that cannot be deleted yet", async () => {
    stubFetch(() =>
      jsonResponse({ error: { code: "session_running", message: "Stop it first." } }, { status: 409 }),
    );

    await expect(deleteSession(SESSION_ID)).rejects.toMatchObject({
      status: 409,
      code: "session_running",
    });
  });

  it("enriches one alert with a POST and returns the updated alert", async () => {
    const alert = makeAlert();
    const fetchMock = stubFetch(() => jsonResponse(alert));

    await expect(enrichAlert(ALERT_ID)).resolves.toEqual(alert);

    const [url, init] = firstCall(fetchMock);
    expect(url).toBe(`/api/v1/network/alerts/${ALERT_ID}/enrich`);
    expect(init?.method).toBe("POST");
    expect(init?.body).toBeUndefined();
  });
});
