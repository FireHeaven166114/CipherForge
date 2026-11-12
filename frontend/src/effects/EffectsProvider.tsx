import { type ReactNode, useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";

import { EffectsContext, type EffectsState } from "./useEffects";

export const EFFECTS_STORAGE_KEY = "cipherforge.effects";
const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function readPreference(): boolean {
  try {
    return window.localStorage.getItem(EFFECTS_STORAGE_KEY) !== "off";
  } catch {
    return true;
  }
}

function writePreference(enabled: boolean): void {
  try {
    window.localStorage.setItem(EFFECTS_STORAGE_KEY, enabled ? "on" : "off");
  } catch {
    // Storage can be blocked (private mode, policy). The choice then lasts for this visit only.
  }
}

function subscribeReducedMotion(listener: () => void): () => void {
  if (typeof window.matchMedia !== "function") return () => undefined;
  const query = window.matchMedia(REDUCED_MOTION_QUERY);
  query.addEventListener("change", listener);
  return () => query.removeEventListener("change", listener);
}

function prefersReducedMotion(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia(REDUCED_MOTION_QUERY).matches;
}

/**
 * Owns the "visual effects" switch. The choice is remembered in this browser, the operating
 * system's reduced-motion setting always wins, and the result is mirrored onto <html> as
 * `data-effects` so the stylesheet can stop every animation in one place.
 */
export function EffectsProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = useState(readPreference);
  const forcedOff = useSyncExternalStore(subscribeReducedMotion, prefersReducedMotion, () => false);
  const enabled = preference && !forcedOff;

  useEffect(() => {
    document.documentElement.dataset.effects = enabled ? "on" : "off";
  }, [enabled]);

  const setEnabled = useCallback((next: boolean) => {
    setPreference(next);
    writePreference(next);
  }, []);
  const toggle = useCallback(() => setEnabled(!preference), [preference, setEnabled]);

  const value = useMemo<EffectsState>(
    () => ({ enabled, forcedOff, setEnabled, toggle }),
    [enabled, forcedOff, setEnabled, toggle],
  );

  return <EffectsContext.Provider value={value}>{children}</EffectsContext.Provider>;
}
