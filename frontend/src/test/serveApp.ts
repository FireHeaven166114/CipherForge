import type { Me } from "../types/api";
import type { Overview, Stats } from "../types/intel";
import {
  makeIndicator,
  makeInvestigation,
  makeOverview,
  makePage,
  makeStats,
} from "./fixtures";
import { jsonResponse, stubFetch } from "./http";

export const DEV_ME: Me = {
  subject: "dev-user",
  name: null,
  roles: ["SecurityAnalyst"],
  auth_mode: "dev",
};

interface ServeOptions {
  stats?: Stats;
  overview?: Overview;
  /** `null` answers 401, as the API does when nobody is signed in. */
  me?: Me | null;
}

function failure(status: number, code: string, message: string): Response {
  return jsonResponse({ error: { code, message, correlation_id: "test-correlation-id" } }, { status });
}

/** Stubs fetch with a small, healthy API: enough for the whole console to render. */
export function serveEverything({
  stats = makeStats(),
  overview = makeOverview(),
  me = DEV_ME,
}: ServeOptions = {}) {
  return stubFetch((url) => {
    const { pathname } = new URL(url, "http://localhost");
    if (pathname === "/api/v1/me") {
      return me === null ? failure(401, "unauthorized", "Authentication is required.") : jsonResponse(me);
    }
    if (pathname === "/api/v1/intel/stats") return jsonResponse(stats);
    if (pathname === "/api/v1/intel/overview") return jsonResponse(overview);
    if (pathname === "/api/v1/intel/indicators") return jsonResponse(makePage([makeIndicator()]));
    if (pathname.startsWith("/api/v1/intel/indicators/")) return jsonResponse(makeInvestigation());
    if (pathname === "/health") {
      return jsonResponse({ status: "ok", service: "cipherforge-api", version: "0.4.0" });
    }
    if (pathname === "/ready") return jsonResponse({ status: "ready", checks: { database: "ok" } });
    return failure(404, "not_found", "No such route.");
  });
}
