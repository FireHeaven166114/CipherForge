import { createContext, useContext } from "react";

export interface EffectsState {
  /** Whether decorative motion (animated numbers, scanning beams, orbiting rings) is on. */
  enabled: boolean;
  /** The operating system asks for reduced motion, so effects stay off and cannot be turned on. */
  forcedOff: boolean;
  setEnabled: (enabled: boolean) => void;
  toggle: () => void;
}

/**
 * Without a provider, effects are off. Unit tests then see final values at once instead of
 * animation frames, and nothing moves unless the app explicitly opted in.
 */
const OFF: EffectsState = {
  enabled: false,
  forcedOff: false,
  setEnabled: () => undefined,
  toggle: () => undefined,
};

export const EffectsContext = createContext<EffectsState>(OFF);

export function useEffects(): EffectsState {
  return useContext(EffectsContext);
}
