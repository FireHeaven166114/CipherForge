import { formatCompactCount, formatCount } from "../features/intel/format";

/**
 * A whole number that does not outgrow its box. A million or more is shortened, and the exact figure
 * stays in the tooltip and in the text that screen readers get.
 */
export default function Count({ value, className }: { value: number; className?: string }) {
  const full = formatCount(value);
  const short = formatCompactCount(value);
  if (short === full) return <span className={className}>{full}</span>;
  return (
    <span className={className} title={full}>
      <span aria-hidden="true">{short}</span>
      <span className="sr-only">{full}</span>
    </span>
  );
}
