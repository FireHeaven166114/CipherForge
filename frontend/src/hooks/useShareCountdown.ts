import { useCallback, useSyncExternalStore } from "react";

const TICK_MS = 250;

/** Whole seconds from now until `deadline` (epoch milliseconds), never below zero. */
function secondsLeft(deadline: number | null): number {
  if (deadline === null) return 0;
  return Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
}

/**
 * Counts down to `deadline` and answers how many whole seconds are left, 0 once it has passed
 * (and for no deadline). The clock is an external store, so the page re-renders as time passes
 * without the hook ever setting state, and it stops ticking once the deadline is reached.
 */
export function useShareCountdown(deadline: number | null): number {
  const subscribe = useCallback(
    (notify: () => void) => {
      if (deadline === null) return () => undefined;
      const timer = window.setInterval(() => {
        notify();
        if (Date.now() >= deadline) window.clearInterval(timer);
      }, TICK_MS);
      return () => window.clearInterval(timer);
    },
    [deadline],
  );
  const read = useCallback(() => secondsLeft(deadline), [deadline]);
  return useSyncExternalStore(subscribe, read, read);
}
