import { useCallback, useEffect, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";

export type ResourceState<T> =
  | { status: "loading" }
  | { status: "success"; data: T }
  | { status: "error"; error: ApiError };

export interface ApiResource<T> {
  state: ResourceState<T>;
  /** Asks again, showing the loading state until the new answer arrives. */
  reload: () => void;
}

type Loader<T> = (signal: AbortSignal) => Promise<T>;

interface Settled<T> {
  load: Loader<T>;
  attempt: number;
  outcome: Exclude<ResourceState<T>, { status: "loading" }>;
}

/**
 * Loads one resource and tracks its state. `load` must be stable (a module-level function or a
 * `useCallback`); a new `load` starts a new request and cancels the one in flight.
 *
 * "Loading" is derived rather than stored: it is whatever has not settled for the current `load`
 * and attempt. That keeps every state update inside a promise callback, never in the effect body.
 */
export function useApiResource<T>(load: Loader<T>): ApiResource<T> {
  const [attempt, setAttempt] = useState(0);
  const [settled, setSettled] = useState<Settled<T> | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;

    load(signal).then(
      (data) => {
        if (!signal.aborted) setSettled({ load, attempt, outcome: { status: "success", data } });
      },
      (error: unknown) => {
        if (!signal.aborted) {
          setSettled({ load, attempt, outcome: { status: "error", error: toApiError(error) } });
        }
      },
    );

    return () => controller.abort();
  }, [load, attempt]);

  const reload = useCallback(() => setAttempt((value) => value + 1), []);

  const state: ResourceState<T> =
    settled !== null && settled.load === load && settled.attempt === attempt
      ? settled.outcome
      : { status: "loading" };

  return { state, reload };
}
