import { describe, expect, it } from "vitest";

import { ApiError } from "../../services/apiClient";
import type { HealthResponse, ReadinessResponse } from "../../types/api";
import { type CheckResult, deriveOverall } from "./overallStatus";

const up: CheckResult<HealthResponse> = {
  state: "ok",
  data: { status: "ok", service: "cipherforge-api", version: "0.1.0" },
};
const ready: CheckResult<ReadinessResponse> = {
  state: "ok",
  data: { status: "ready", checks: { database: "ok" } },
};
const notReady: CheckResult<ReadinessResponse> = {
  state: "ok",
  data: { status: "not_ready", checks: { database: "unavailable" } },
};
const failed = {
  state: "error",
  error: new ApiError({ message: "nope", status: 0, code: "network_error" }),
} as const;

describe("deriveOverall", () => {
  it.each([
    ["still loading", { state: "idle" }, { state: "idle" }, "checking"],
    ["everything healthy", up, ready, "operational"],
    ["database down", up, notReady, "degraded"],
    ["readiness check failed", up, failed, "degraded"],
    ["API unreachable", failed, failed, "down"],
    ["liveness failed but readiness answered", failed, ready, "down"],
  ] as const)("%s -> %s", (_name, health, readiness, expected) => {
    expect(deriveOverall(health, readiness)).toBe(expected);
  });
});
