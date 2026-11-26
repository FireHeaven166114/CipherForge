import { useCallback, useState } from "react";

import { IDLE_POLL_MS, sessionPollInterval, statusPollInterval } from "../features/network/polling";
import { getNetworkStatus, getSession } from "../services/networkService";
import type { NetworkStatus, SessionDetail } from "../types/network";
import { type LiveResource, useLiveResource } from "./useLiveResource";

/**
 * The capture status, kept fresh: every couple of seconds while a capture or an analysis is under
 * way, and at a relaxed pace otherwise. The pace follows from each answer.
 */
export function useNetworkStatus(): LiveResource<NetworkStatus> {
  const [intervalMs, setIntervalMs] = useState(IDLE_POLL_MS);

  const load = useCallback(async (signal: AbortSignal) => {
    const status = await getNetworkStatus(signal);
    if (!signal.aborted) setIntervalMs(statusPollInterval(status));
    return status;
  }, []);

  return useLiveResource(load, intervalMs);
}

export interface NetworkSession {
  resource: LiveResource<SessionDetail>;
  /** How often the lists of this session should ask again, to match how fast it changes. */
  intervalMs: number;
}

/** One session in full, kept fresh at the pace the session itself sets. */
export function useNetworkSession(sessionId: string): NetworkSession {
  const [intervalMs, setIntervalMs] = useState(IDLE_POLL_MS);

  const load = useCallback(
    async (signal: AbortSignal) => {
      const detail = await getSession(sessionId, signal);
      if (!signal.aborted) setIntervalMs(sessionPollInterval(detail));
      return detail;
    },
    [sessionId],
  );

  return { resource: useLiveResource(load, intervalMs), intervalMs };
}
