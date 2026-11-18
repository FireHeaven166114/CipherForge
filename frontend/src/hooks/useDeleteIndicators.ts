import { useCallback, useEffect, useRef, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";
import { deleteSelected } from "../services/intelService";
import type { DeleteResult } from "../types/intel";

export interface DeleteControls {
  /** True from the moment a deletion starts until the API has answered. */
  busy: boolean;
  /** Why the last deletion failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /**
   * Deletes the indicators. Resolves to what the API removed, or to null when it failed (see
   * `error`), when another deletion is still running, or when the screen went away while the API
   * was working, so a caller never acts on a screen that is no longer there.
   */
  run: (indicatorIds: readonly string[]) => Promise<DeleteResult | null>;
  /** Forgets the last failure. */
  reset: () => void;
}

/**
 * Runs deletions one at a time. Unlike a lookup, a deletion is not cancelled when the page goes
 * away: the analyst confirmed it, so the request is left to finish and only the screen is let go.
 */
export function useDeleteIndicators(): DeleteControls {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const mounted = useRef(true);
  const running = useRef(false);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (indicatorIds: readonly string[]) => {
    if (running.current) return null;
    running.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await deleteSelected(indicatorIds);
      return mounted.current ? result : null;
    } catch (caught) {
      if (mounted.current) setError(toApiError(caught));
      return null;
    } finally {
      running.current = false;
      if (mounted.current) setBusy(false);
    }
  }, []);

  const reset = useCallback(() => setError(null), []);

  return { busy, error, run, reset };
}
