import type {
  AlertPage,
  AlertQuery,
  FlowPage,
  InterfaceList,
  DetectionRule,
  NetworkAlert,
  NetworkStatus,
  PageQuery,
  SessionDetail,
  SessionPage,
} from "../types/network";
import { request, requestNoContent, uploadFile } from "./apiClient";
import {
  isAlertPage,
  isFlowPage,
  isInterfaceList,
  isNetworkAlert,
  isNetworkStatus,
  isRuleList,
  isSessionDetail,
  isSessionPage,
} from "./networkGuards";

const BASE = "/api/v1/network";

// Looking an address up asks every configured provider, each for up to the server's own timeout.
const ENRICH_TIMEOUT_MS = 30_000;
// Starting a capture opens the interface and waits for the first packets to be read.
const START_TIMEOUT_MS = 20_000;

function withQuery(path: string, params: URLSearchParams): string {
  const search = params.toString();
  return search ? `${path}?${search}` : path;
}

function pageParams(query: PageQuery, params = new URLSearchParams()): URLSearchParams {
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset !== undefined) params.set("offset", String(query.offset));
  return params;
}

export function getNetworkStatus(signal?: AbortSignal): Promise<NetworkStatus> {
  return request(`${BASE}/status`, { signal, guard: isNetworkStatus });
}

/** `refresh` asks the server to look at the machine's interfaces again instead of its cached list. */
export function listInterfaces(refresh = false, signal?: AbortSignal): Promise<InterfaceList> {
  return request(`${BASE}/interfaces${refresh ? "?refresh=true" : ""}`, {
    signal,
    guard: isInterfaceList,
  });
}

export function listRules(signal?: AbortSignal): Promise<DetectionRule[]> {
  return request(`${BASE}/rules`, { signal, guard: isRuleList });
}

/** `interfaceId` is an `id` from `listInterfaces`; the server rejects any other value. */
export function startCapture(interfaceId: string, signal?: AbortSignal): Promise<NetworkStatus> {
  return request(`${BASE}/capture/start`, {
    method: "POST",
    body: { interface: interfaceId },
    signal,
    timeoutMs: START_TIMEOUT_MS,
    guard: isNetworkStatus,
  });
}

export function stopCapture(signal?: AbortSignal): Promise<NetworkStatus> {
  return request(`${BASE}/capture/stop`, {
    method: "POST",
    signal,
    timeoutMs: START_TIMEOUT_MS,
    guard: isNetworkStatus,
  });
}

/** Analyses a saved capture (`.pcap`, `.pcapng` or `.cap`). The bytes go to the server as they are. */
export function analysePcap(file: File, signal?: AbortSignal): Promise<SessionDetail> {
  return uploadFile(`${BASE}/pcap`, file, {
    fileName: file.name,
    signal,
    guard: isSessionDetail,
  });
}

export function listSessions(query: PageQuery = {}, signal?: AbortSignal): Promise<SessionPage> {
  return request(withQuery(`${BASE}/sessions`, pageParams(query)), {
    signal,
    guard: isSessionPage,
  });
}

export function getSession(sessionId: string, signal?: AbortSignal): Promise<SessionDetail> {
  return request(`${BASE}/sessions/${encodeURIComponent(sessionId)}`, {
    signal,
    guard: isSessionDetail,
  });
}

export function listFlows(
  sessionId: string,
  query: PageQuery = {},
  signal?: AbortSignal,
): Promise<FlowPage> {
  return request(
    withQuery(`${BASE}/sessions/${encodeURIComponent(sessionId)}/flows`, pageParams(query)),
    { signal, guard: isFlowPage },
  );
}

export function listAlerts(
  sessionId: string,
  query: AlertQuery = {},
  signal?: AbortSignal,
): Promise<AlertPage> {
  const params = new URLSearchParams();
  for (const severity of query.severity ?? []) params.append("severity", severity);
  if (query.rule) params.set("rule", query.rule);
  pageParams(query, params);
  return request(withQuery(`${BASE}/sessions/${encodeURIComponent(sessionId)}/alerts`, params), {
    signal,
    guard: isAlertPage,
  });
}

/** Removes a finished session with its flows and alerts. A running session cannot be deleted. */
export function deleteSession(sessionId: string, signal?: AbortSignal): Promise<void> {
  return requestNoContent(`${BASE}/sessions/${encodeURIComponent(sessionId)}`, { signal });
}

/** Looks the alert's external address up with the configured providers and returns the alert. */
export function enrichAlert(alertId: string, signal?: AbortSignal): Promise<NetworkAlert> {
  return request(`${BASE}/alerts/${encodeURIComponent(alertId)}/enrich`, {
    method: "POST",
    signal,
    timeoutMs: ENRICH_TIMEOUT_MS,
    guard: isNetworkAlert,
  });
}
