import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";

import { type CheckResult, deriveOverall } from "../../features/status/overallStatus";
import { ServiceStatusContext, type ServiceStatus } from "../../hooks/useServiceStatus";
import { ApiError } from "../../services/apiClient";
import { fetchHealth, fetchReadiness } from "../../services/healthService";
import type { HealthResponse, ReadinessResponse } from "../../types/api";

const POLL_INTERVAL_MS = 30_000;

interface Snapshot {
  generation: number;
  health: CheckResult<HealthResponse>;
  readiness: CheckResult<ReadinessResponse>;
  checkedAt: Date;
}

async function settle<T>(promise: Promise<T>): Promise<CheckResult<T>> {
  try {
    return { state: "ok", data: await promise };
  } catch (error) {
    if (error instanceof ApiError) return { state: "error", error };
    throw error;
  }
}

/**
 * Checks the API's liveness and readiness for the whole app: when it loads, on demand, and every
 * 30 seconds. One check serves everything that shows the result, so the top bar and the status
 * page agree and a page load costs one pair of requests.
 */
export function ServiceStatusProvider({ children }: { children: ReactNode }) {
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
    const timer = setInterval(() => setGeneration((value) => value + 1), POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, []);

  const refresh = useCallback(() => setGeneration((value) => value + 1), []);

  const status = useMemo<ServiceStatus>(() => {
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
  }, [snapshot, generation, refresh]);

  return <ServiceStatusContext.Provider value={status}>{children}</ServiceStatusContext.Provider>;
}
