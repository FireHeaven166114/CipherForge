import { type RefObject, useLayoutEffect } from "react";

import { startPanelGlow } from "../../motion/panelGlow";
import { startReveal } from "../../motion/reveal";
import { useMotion } from "../../motion/useMotion";

/**
 * Starts the motion that belongs to the page content, and stops it again when visual effects go
 * off: panels and tiles that arrive with `data-reveal` get their staggered entrance, and glass
 * panels, buttons and links catch the pointer. Renders nothing.
 */
export default function MotionDirector({ main }: { main: RefObject<HTMLElement | null> }) {
  const motion = useMotion();

  useLayoutEffect(() => {
    const root = main.current;
    if (!motion || root === null) return;
    const stops = [startPanelGlow(), startReveal(root)];
    return () => {
      for (const stop of stops) stop();
    };
  }, [motion, main]);

  return null;
}
