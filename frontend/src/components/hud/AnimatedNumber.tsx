import { useEffect, useRef, useState } from "react";

import { useEffects } from "../../effects/useEffects";
import { formatCount } from "../../features/intel/format";

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
 * A number that counts up to its value when visual effects are on. Assistive technology always
 * gets the final value at once, so the animation never turns into a stream of announcements.
 */
export default function AnimatedNumber({
  value,
  format = defaultFormat,
  spoken = format,
  durationMs = 900,
  className,
}: AnimatedNumberProps) {
  const { enabled } = useEffects();
  const [shown, setShown] = useState(0);
  const shownRef = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    const from = shownRef.current;
    const start = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / durationMs);
      const next = from + (value - from) * (1 - (1 - progress) ** 3);
      shownRef.current = next;
      setShown(next);
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [enabled, value, durationMs]);

  const final = format(value);
  const exact = spoken(value);
  const shortened = exact !== final;
  if (!enabled && !shortened) return <span className={className}>{final}</span>;
  return (
    <span className={className} title={shortened ? exact : undefined}>
      <span aria-hidden="true">{enabled ? format(shown) : final}</span>
      <span className="sr-only">{exact}</span>
    </span>
  );
}
