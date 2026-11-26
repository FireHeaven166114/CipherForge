import type { NetworkStatus } from "../types/network";
import { jsonResponse, stubFetch } from "./http";
import {
  SESSION_ID,
  makeAlert,
  makeAlertPage,
  makeCompletedEnrichment,
  makeFlowPage,
  makeInterfaces,
  makeNetworkStatus,
  makeRules,
  makeSessionDetail,
  makeSessionPage,
} from "./networkFixtures";

const BASE = "/api/v1/network";

/** One request the page made, with the parts of its address a handler usually needs. */
export interface NetworkCall {
  method: string;
  url: URL;
  init: RequestInit | undefined;
  /** The session id (or, for an enrichment, the alert id) named in the address. */
  id: string | null;
}

/** A body is sent as JSON, a Response as it is, and `null` answers 204 No Content. */
export type NetworkAnswer = Response | object | null;
export type NetworkHandler = (call: NetworkCall) => NetworkAnswer | Promise<NetworkAnswer>;

export type NetworkRoute =
  | "status"
  | "interfaces"
  | "rules"
  | "start"
  | "stop"
  | "pcap"
  | "sessions"
  | "session"
  | "remove"
  | "flows"
  | "alerts"
  | "enrich";

export type NetworkHandlers = Partial<Record<NetworkRoute, NetworkHandler>>;

/** The API's error envelope, as the page's error mapping reads it. */
export function apiError(
  status: number,
  code: string,
  message = `The API said ${code}.`,
  headers?: HeadersInit,
): Response {
  return jsonResponse({ error: { code, message, correlation_id: "corr-0001" } }, { status, headers });
}

/** A status answer for a capture on the given interface, as the API gives it while one runs. */
export function runningStatus(overrides: Partial<NetworkStatus> = {}): NetworkStatus {
  return makeNetworkStatus({ state: "running", interface: "eth0", session_id: SESSION_ID, ...overrides });
}

const DEFAULTS: Record<NetworkRoute, NetworkHandler> = {
  status: () => makeNetworkStatus(),
  interfaces: () => makeInterfaces(),
  rules: () => makeRules(),
  start: () => runningStatus(),
  stop: () => makeNetworkStatus({ state: "stopped", interface: "eth0", session_id: SESSION_ID }),
  pcap: () => jsonResponse(makeSessionDetail({ status: "running", ended_at: null }), { status: 202 }),
  sessions: () => makeSessionPage(),
  session: ({ id }) => makeSessionDetail({ id: id ?? SESSION_ID }),
  remove: () => null,
  flows: () => makeFlowPage(),
  alerts: () => makeAlertPage(),
  enrich: () => makeAlert({ enrichment: makeCompletedEnrichment() }),
};

function routeOf(method: string, path: string): { route: NetworkRoute; id: string | null } | null {
  const parts = path.slice(BASE.length).split("/").filter(Boolean).map(decodeURIComponent);
  const [first, second, third] = parts;
  if (method === "GET" && parts.length === 1) {
    if (first === "status" || first === "interfaces" || first === "rules" || first === "sessions") {
      return { route: first, id: null };
    }
  }
  if (method === "POST" && first === "capture" && parts.length === 2) {
    return second === "start" || second === "stop" ? { route: second, id: null } : null;
  }
  if (method === "POST" && first === "pcap" && parts.length === 1) return { route: "pcap", id: null };
  if (first === "sessions" && second !== undefined) {
    if (parts.length === 2 && method === "GET") return { route: "session", id: second };
    if (parts.length === 2 && method === "DELETE") return { route: "remove", id: second };
    if (parts.length === 3 && method === "GET" && (third === "flows" || third === "alerts")) {
      return { route: third, id: second };
    }
  }
  if (method === "POST" && first === "alerts" && third === "enrich" && parts.length === 3) {
    return { route: "enrich", id: second ?? null };
  }
  return null;
}

function respond(answer: NetworkAnswer): Response {
  if (answer instanceof Response) return answer;
  if (answer === null) return new Response(null, { status: 204 });
  return jsonResponse(answer);
}

/**
 * Stands in for the network API. Every route answers with a plain fixture unless the test gives
 * it a handler; a request to an address the page should not use is answered with a 500, so the
 * mistake shows up as an error rather than as silence.
 */
export function networkApi(handlers: NetworkHandlers = {}) {
  return stubFetch(async (input, init) => {
    const url = new URL(input, "http://localhost");
    const method = init?.method ?? "GET";
    const found = routeOf(method, url.pathname);
    if (found === null) {
      return apiError(500, "unexpected_request", `${method} ${url.pathname} is not an API route.`);
    }
    const handler = handlers[found.route] ?? DEFAULTS[found.route];
    return respond(await handler({ method, url, init, id: found.id }));
  });
}

/** The addresses fetched so far (path and query), oldest first, optionally only for one method. */
export function requested(mock: ReturnType<typeof networkApi>, method?: string): string[] {
  return mock.mock.calls
    .filter(([, init]) => method === undefined || (init?.method ?? "GET") === method)
    .map(([input]) => String(input));
}
