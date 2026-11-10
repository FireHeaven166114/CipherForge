import { useCallback, useEffect, useState } from "react";

import { type CheckResult, type OverallStatus, deriveOverall } from "../features/status/overallStatus";
import { ApiError } from "../services/apiClient";
import { fetchHealth, fetchReadiness } from "../services/healthService";
import type { HealthResponse, ReadinessResponse } from "../types/api";

const DEFAULT_POLL_INTERVAL_MS = 30_000;

interface Snapshot {
  generation: number;
  health: CheckResult<HealthResponse>;
  readiness: CheckResult<ReadinessResponse>;
  checkedAt: Date;
}

export interface ServiceStatus {
  health: CheckResult<HealthResponse>;
  readiness: CheckResult<ReadinessResponse>;
  overall: OverallStatus;
  checkedAt: Date | null;
  isRefreshing: boolean;
  refresh: () => void;
}

async function settle<T>(promise: Promise<T>): Promise<CheckResult<T>> {
  try {
    return { state: "ok", data: await promise };
  } catch (error) {
    if (error instanceof ApiError) return { state: "error", error };
    throw error;
  }
}

/** Checks API liveness and readiness on mount, on demand, and on a timer. */
export function useServiceStatus(pollIntervalMs: number = DEFAULT_POLL_INTERVAL_MS): ServiceStatus {
  const [generation, setGeneration] = useState(0);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;

    Promise.all([settle(fetchHealth(signal)), settle(fetchReadiness(signal))])
      .then(([health, readiness]) => {
        if (!signal.aborted) setSnapshot({ generation, health, readiness, checkedAt: new Date() });
      })
      .catch((error: unknown) => {
        // A superseded or unmounted check is cancelled on purpose; anything else is a bug.
        if (!signal.aborted) throw error;
      });

    return () => controller.abort();
  }, [generation]);

  useEffect(() => {
    const timer = setInterval(() => setGeneration((value) => value + 1), pollIntervalMs);
    return () => clearInterval(timer);
  }, [pollIntervalMs]);

  const refresh = useCallback(() => setGeneration((value) => value + 1), []);

  const health: CheckResult<HealthResponse> = snapshot?.health ?? { state: "idle" };
  const readiness: CheckResult<ReadinessResponse> = snapshot?.readiness ?? { state: "idle" };

  return {
    health,
    readiness,
    overall: deriveOverall(health, readiness),
    checkedAt: snapshot?.checkedAt ?? null,
    isRefreshing: snapshot === null || snapshot.generation !== generation,
    refresh,
  };
}
