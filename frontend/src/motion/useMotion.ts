import { useEffects } from "../effects/useEffects";
import { canAnimate } from "./anime";

/**
 * Whether anything in the console may move right now: the visual-effects switch is on (it is
 * forced off by the system's reduced-motion setting) and the browser can run the animation engine.
 * Every motion hook asks this one question, so "off" means off everywhere.
 */
export function useMotion(): boolean {
  const { enabled } = useEffects();
  return enabled && canAnimate();
}
