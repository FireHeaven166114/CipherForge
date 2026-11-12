import { useLayoutEffect, useRef } from "react";

import { formatCount } from "../../features/intel/format";
import { animate } from "../../motion/anime";
import { useMotion } from "../../motion/useMotion";

interface AnimatedNumberProps {
  value: number;
  /** Turns a number into the text that is drawn. The default groups thousands: 12,480. */
  format?: (value: number) => string;
  /** The exact figure, for assistive technology and the tooltip, when `format` shortens it. */
  spoken?: (value: number) => string;
  durationMs?: number;
  className?: string;
}

const defaultFormat = formatCount;

/**
 * A number that counts up to its value when visual effects are on, driven by anime.js. The digits
 * are written straight into one text node, so a count does not re-render React sixty times a
 * second, and assistive technology always gets the final value at once, so the animation never
 * turns into a stream of announcements.
 */
export default function AnimatedNumber({
  value,
  format = defaultFormat,
  spoken = format,
  durationMs = 900,
  className,
}: AnimatedNumberProps) {
  const motion = useMotion();
  const digits = useRef<HTMLSpanElement>(null);
  /** The figure on screen right now, so a changed value counts on from there instead of from zero. */
  const shown = useRef(0);
  /** The latest formatter, so a new one is picked up without restarting a count in progress. */
  const formatter = useRef(format);

  useLayoutEffect(() => {
    formatter.current = format;
  }, [format]);

  useLayoutEffect(() => {
    const element = digits.current;
    if (!motion || element === null) return;
    const text = document.createTextNode(formatter.current(shown.current));
    element.replaceChildren(text);
    const counter = { value: shown.current };
    const count = animate(counter, {
      value,
      duration: durationMs,
      ease: "outExpo",
      onUpdate: () => {
        shown.current = counter.value;
        text.data = formatter.current(counter.value);
      },
      onComplete: () => {
        shown.current = value;
        text.data = formatter.current(value);
      },
    });
    return () => {
      count.cancel();
    };
  }, [motion, value, durationMs]);

  const final = format(value);
  const exact = spoken(value);
  const shortened = exact !== final;
  if (!motion && !shortened) return <span className={className}>{final}</span>;
  return (
    <span className={className} title={shortened ? exact : undefined}>
      {motion ? (
        // React never renders children into this one: the count writes into it directly.
        <span key="counting" aria-hidden="true" ref={digits} />
      ) : (
        <span key="still" aria-hidden="true">
          {final}
        </span>
      )}
      <span className="sr-only">{exact}</span>
    </span>
  );
}
