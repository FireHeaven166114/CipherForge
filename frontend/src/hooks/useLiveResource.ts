import { useCallback, useEffect, useRef, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";

export type LiveState<T> =
  | { status: "loading" }
  | { status: "error"; error: ApiError }
  | {
      status: "ready";
      data: T;
      /** When `data` arrived, in epoch milliseconds. */
      updatedAt: number;
      /** True while a newer answer is on its way; `data` stays on screen meanwhile. */
      refreshing: boolean;
      /** Why the latest refresh failed. The older `data` is still shown. */
      refreshError: ApiError | null;
    };

export interface LiveResource<T> {
  state: LiveState<T>;
  /** Asks again now. The current data stays visible until the new answer arrives. */
  refresh: () => void;
}

type Loader<T> = (signal: AbortSignal) => Promise<T>;

interface Outcome<T> {
  load: Loader<T>;
  /** The request that produced this outcome. */
  generation: number;
  data: T | null;
  updatedAt: number | null;
  error: ApiError | null;
}

const DEFAULT_INTERVAL_MS = 60_000;

/**
 * Like `useApiResource`, but for a dashboard that stays open: it re-asks on a timer (and when the
 * tab comes back into view) and keeps showing the last good answer while it does, instead of
 * flashing back to "loading". `load` must be stable, as for `useApiResource`.
 *
 * Every state update happens inside a promise callback, never in an effect body.
 */
export function useLiveResource<T>(
  load: Loader<T>,
  intervalMs: number = DEFAULT_INTERVAL_MS,
): LiveResource<T> {
  const [generation, setGeneration] = useState(0);
  const [outcome, setOutcome] = useState<Outcome<T> | null>(null);
  const lastUpdate = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;

    load(signal).then(
      (data) => {
        if (signal.aborted) return;
        const now = Date.now();
        lastUpdate.current = now;
        setOutcome({ load, generation, data, updatedAt: now, error: null });
      },
      (error: unknown) => {
        if (signal.aborted) return;
        const apiError = toApiError(error);
        setOutcome((previous) => {
          const kept = previous !== null && previous.load === load ? previous : null;
          return {
            load,
            generation,
            data: kept?.data ?? null,
            updatedAt: kept?.updatedAt ?? null,
            error: apiError,
          };
        });
      },
    );

    return () => controller.abort();
  }, [load, generation]);

  useEffect(() => {
    if (intervalMs <= 0) return;
    const bump = () => setGeneration((value) => value + 1);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") bump();
    }, intervalMs);
    const onVisible = () => {
      if (document.visibilityState === "visible" && Date.now() - lastUpdate.current >= intervalMs) {
        bump();
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [intervalMs]);

  const refresh = useCallback(() => setGeneration((value) => value + 1), []);

  let state: LiveState<T> = { status: "loading" };
  if (outcome !== null && outcome.load === load) {
    if (outcome.data !== null && outcome.updatedAt !== null) {
      state = {
        status: "ready",
        data: outcome.data,
        updatedAt: outcome.updatedAt,
        refreshing: outcome.generation !== generation,
        refreshError: outcome.error,
      };
    } else if (outcome.error !== null && outcome.generation === generation) {
      state = { status: "error", error: outcome.error };
    }
  }

  return { state, refresh };
}
