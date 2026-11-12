/** A bar that never becomes invisible: a small non-zero share still gets a visible sliver. */
const MIN_VISIBLE_PERCENT = 2;

interface BarMeterProps {
  /** 0 to 100. */
  percent: number;
  /** A Tailwind `fill-*` class, written out in full at the call site. */
  fillClass: string;
}

/**
 * A decorative bar drawn as SVG, so it needs no charting library and no inline style (the CSP
 * forbids them). It is hidden from assistive technology: callers always print the value as text.
 */
export default function BarMeter({ percent, fillClass }: BarMeterProps) {
  const clamped = Number.isFinite(percent) ? Math.min(100, Math.max(0, percent)) : 0;
  const width = clamped === 0 ? 0 : Math.max(clamped, MIN_VISIBLE_PERCENT);
  return (
    <svg
      viewBox="0 0 100 8"
      preserveAspectRatio="none"
      aria-hidden="true"
      focusable="false"
      className="h-2 w-full rounded-full"
    >
      <rect width="100" height="8" className="fill-ink-700/60" />
      <rect width={width} height="8" className={fillClass} />
    </svg>
  );
}
