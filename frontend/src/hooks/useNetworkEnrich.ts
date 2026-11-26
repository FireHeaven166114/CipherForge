import type { ApiError } from "../services/apiClient";
import { enrichAlert } from "../services/networkService";
import type { NetworkAlert } from "../types/network";
import { useNetworkAction } from "./useNetworkAction";

function lookUpAddress(alertId: string): Promise<NetworkAlert> {
  return enrichAlert(alertId);
}

export interface EnrichControls {
  /** True while the providers are being asked about the alert's address. */
  busy: boolean;
  /** Why the last lookup failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /** Resolves to the alert with its new enrichment, or to null when the lookup failed (see `error`). */
  lookUp: (alertId: string) => Promise<NetworkAlert | null>;
  reset: () => void;
}

/** Looks up the public address of one alert. Each alert row has its own, so rows never block each other. */
export function useNetworkEnrich(): EnrichControls {
  const { busy, error, run, reset } = useNetworkAction(lookUpAddress);
  return { busy, error, lookUp: run, reset };
}
