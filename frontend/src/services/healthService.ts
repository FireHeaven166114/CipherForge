import type { HealthResponse, ReadinessResponse } from "../types/api";
import { request } from "./apiClient";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isHealthResponse(value: unknown): value is HealthResponse {
  return (
    isRecord(value) &&
    value.status === "ok" &&
    typeof value.service === "string" &&
    typeof value.version === "string"
  );
}

function isReadinessResponse(value: unknown): value is ReadinessResponse {
  return (
    isRecord(value) &&
    (value.status === "ready" || value.status === "not_ready") &&
    isRecord(value.checks) &&
    Object.values(value.checks).every((check) => check === "ok" || check === "unavailable")
  );
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request("/health", { signal, guard: isHealthResponse });
}

/** The API answers 503 with a valid body when a dependency is down; that is data, not a failure. */
export function fetchReadiness(signal?: AbortSignal): Promise<ReadinessResponse> {
  return request("/ready", { signal, acceptStatuses: [503], guard: isReadinessResponse });
}
