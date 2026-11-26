import { useCallback, useEffect, useRef, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";

export interface NetworkAction<A extends unknown[], R> {
  /** True from the moment the action starts until the API has answered. */
  busy: boolean;
  /** The arguments of the action under way, or null when none is. */
  pending: A | null;
  /** Why the last run failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /**
   * Runs the action. Resolves to what it returned, or to null when it failed (see `error`), when
   * another run is still going, or when the screen went away meanwhile, so a caller never acts
   * on a screen that is no longer there.
   */
  run: (...args: A) => Promise<R | null>;
  /** Forgets the last failure. */
  reset: () => void;
}

/**
 * Runs one request-making action at a time and tracks its outcome. Like a deletion in the intel
 * pages, a confirmed action is not cancelled when the page goes away: the request is left to
 * finish and only the screen is let go. `action` must be stable (a module-level function).
 */
export function useNetworkAction<A extends unknown[], R>(
  action: (...args: A) => Promise<R>,
): NetworkAction<A, R> {
  const [pending, setPending] = useState<A | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const mounted = useRef(true);
  const running = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(
    async (...args: A) => {
      if (running.current) return null;
      running.current = true;
      setPending(args);
      setError(null);
      try {
        const result = await action(...args);
        return mounted.current ? result : null;
      } catch (caught) {
        if (mounted.current) setError(toApiError(caught));
        return null;
      } finally {
        running.current = false;
        if (mounted.current) setPending(null);
      }
    },
    [action],
  );

  const reset = useCallback(() => setError(null), []);

  return { busy: pending !== null, pending, error, run, reset };
}
