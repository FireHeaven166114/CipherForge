import { useEffect, useRef } from "react";

/**
 * Asks for fresh data whenever `trigger` changes. The first render does not count: the data is
 * being loaded then anyway.
 */
export function useNetworkRefreshOn(trigger: unknown, refresh: () => void): void {
  const seen = useRef(trigger);

  useEffect(() => {
    if (Object.is(seen.current, trigger)) return;
    seen.current = trigger;
    refresh();
  }, [trigger, refresh]);
}
