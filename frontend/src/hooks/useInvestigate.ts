import { useCallback, useEffect, useRef, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";
import { investigateIndicator } from "../services/intelService";
import type { Investigation } from "../types/intel";

export type InvestigateState =
  | { status: "idle" }
  | { status: "loading"; indicator: string }
  | { status: "success"; investigation: Investigation }
  | { status: "error"; error: ApiError };

export interface InvestigateControls {
  state: InvestigateState;
  run: (indicator: string, refresh: boolean) => void;
  /** Forgets the last result and cancels a request in flight. */
  reset: () => void;
}

interface Request {
  id: number;
  indicator: string;
  refresh: boolean;
}

interface Settled {
  requestId: number;
  outcome: Extract<InvestigateState, { status: "success" | "error" }>;
}

/** A lookup to start as soon as the hook mounts, such as one chosen from the command palette. */
export interface InitialRequest {
  indicator: string;
  refresh: boolean;
}

/**
 * Runs investigations one at a time; starting a new one cancels the one in flight. Pass
 * `initial` to begin a lookup on mount. It is read once: later changes to it are ignored.
 */
export function useInvestigate(initial?: InitialRequest): InvestigateControls {
  const [request, setRequest] = useState<Request | null>(() =>
    initial === undefined ? null : { id: 1, indicator: initial.indicator, refresh: initial.refresh },
  );
  const [settled, setSettled] = useState<Settled | null>(null);
  // Ids never repeat, even after reset(), so an old result can never be mistaken for a new one.
  const lastId = useRef(initial === undefined ? 0 : 1);

  useEffect(() => {
    if (request === null) return;
    const controller = new AbortController();
    const { signal } = controller;

    investigateIndicator({ indicator: request.indicator, refresh: request.refresh }, signal).then(
      (investigation) => {
        if (!signal.aborted) {
          setSettled({ requestId: request.id, outcome: { status: "success", investigation } });
        }
      },
      (error: unknown) => {
        if (!signal.aborted) {
          setSettled({
            requestId: request.id,
            outcome: { status: "error", error: toApiError(error) },
          });
        }
      },
    );

    return () => controller.abort();
  }, [request]);

  const run = useCallback((indicator: string, refresh: boolean) => {
    lastId.current += 1;
    setRequest({ id: lastId.current, indicator, refresh });
  }, []);

  const reset = useCallback(() => setRequest(null), []);

  let state: InvestigateState;
  if (request === null) state = { status: "idle" };
  else if (settled !== null && settled.requestId === request.id) state = settled.outcome;
  else state = { status: "loading", indicator: request.indicator };

  return { state, run, reset };
}
