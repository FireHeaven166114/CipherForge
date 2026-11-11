import { useMemo, useSyncExternalStore } from "react";

const MINUTE_MS = 60_000;

const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;

// One timer serves every component that shows a relative time, however many there are.
function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  if (timer === undefined) {
    timer = setInterval(() => {
      for (const notify of listeners) notify();
    }, MINUTE_MS);
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0 && timer !== undefined) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

function currentMinute(): number {
  return Math.floor(Date.now() / MINUTE_MS);
}

/**
 * The current time, to the minute, kept up to date. Relative times such as "3 hours ago" never
 * need more precision, and a snapshot that changes only once a minute avoids needless renders.
 */
export function useNow(): Date {
  const minute = useSyncExternalStore(subscribe, currentMinute, currentMinute);
  return useMemo(() => new Date(minute * MINUTE_MS), [minute]);
}
