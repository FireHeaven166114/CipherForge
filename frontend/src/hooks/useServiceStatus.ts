import { createContext, useContext } from "react";

import type { CheckResult, OverallStatus } from "../features/status/overallStatus";
import type { HealthResponse, ReadinessResponse } from "../types/api";

export interface ServiceStatus {
  health: CheckResult<HealthResponse>;
  readiness: CheckResult<ReadinessResponse>;
  overall: OverallStatus;
  checkedAt: Date | null;
  isRefreshing: boolean;
  refresh: () => void;
}

export const ServiceStatusContext = createContext<ServiceStatus | null>(null);

/**
 * The API's liveness and readiness. Every caller reads the same check, so the top bar and the
 * status page cannot disagree and a refresh from either one is seen by both.
 */
export function useServiceStatus(): ServiceStatus {
  const status = useContext(ServiceStatusContext);
  if (status === null) throw new Error("useServiceStatus must be used inside a ServiceStatusProvider.");
  return status;
}
