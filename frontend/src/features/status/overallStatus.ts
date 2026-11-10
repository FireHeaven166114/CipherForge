import type { ApiError } from "../../services/apiClient";
import type { HealthResponse, ReadinessResponse } from "../../types/api";

export type CheckResult<T> =
  | { state: "idle" }
  | { state: "ok"; data: T }
  | { state: "error"; error: ApiError };

export type OverallStatus = "checking" | "operational" | "degraded" | "down";

/**
 * Liveness answers "is the API process up?" and readiness answers "can it reach
 * its dependencies?". An unreachable API is "down"; a reachable API with a
 * failing dependency (or an unreadable readiness answer) is "degraded".
 */
export function deriveOverall(
  health: CheckResult<HealthResponse>,
  readiness: CheckResult<ReadinessResponse>,
): OverallStatus {
  if (health.state === "idle" || readiness.state === "idle") return "checking";
  if (health.state === "error") return "down";
  if (readiness.state === "error") return "degraded";
  return readiness.data.status === "ready" ? "operational" : "degraded";
}
