import { useCallback, useEffect, useRef, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";

export interface FileActionControls {
  /** True from the moment a call starts until the API has answered. */
  busy: boolean;
  /** Why the last call failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /**
   * Runs one API call. Resolves to what it returned (`undefined` for a call that returns nothing),
   * or to null when it failed (see `error`), when another call is still running, or when the
   * screen went away while the API was working, so a caller never acts on a screen that is gone.
   * The answer is handed back and never kept here: a share link's token must live only as long as
   * the screen that shows it.
   */
  run: <T>(task: () => Promise<T>) => Promise<T | null>;
  /** Forgets the last failure. */
  reset: () => void;
}

/**
 * Runs one confirmed change (create a link, revoke it, delete a file) at a time. Like a deletion
 * elsewhere in the console, the request is not cancelled when the screen goes away: the person
 * asked for it, so it is left to finish and only the screen is let go.
 */
export function useFileAction(): FileActionControls {
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

  const run = useCallback(async <T>(task: () => Promise<T>): Promise<T | null> => {
    if (running.current) return null;
    running.current = true;
    setBusy(true);
    setError(null);
    try {
      const result = await task();
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
