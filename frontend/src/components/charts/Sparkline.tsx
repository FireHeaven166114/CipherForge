import { areaPath, smoothPath, type Point } from "./geometry";

interface SparklineProps {
  values: readonly number[];
  width?: number;
  height?: number;
  /** Tailwind classes, written out in full by the caller so the build can find them. */
  line?: string;
  area?: string;
}

const INSET = 2;

/** A tiny trend line for a metric tile. Decorative: the tile states the number in words. */
export default function Sparkline({
  values,
  width = 96,
  height = 28,
  line = "stroke-cipher",
  area = "fill-cipher/15",
}: SparklineProps) {
  if (values.length < 2) return <svg width={width} height={height} aria-hidden="true" focusable="false" />;

  const top = Math.max(1, ...values);
  const points: Point[] = values.map((value, index) => ({
    x: INSET + (index / (values.length - 1)) * (width - 2 * INSET),
    y: height - INSET - (Math.max(0, value) / top) * (height - 2 * INSET),
  }));
  const last = points[points.length - 1];

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      aria-hidden="true"
      focusable="false"
      className="shrink-0 overflow-visible"
    >
      <path d={areaPath(points, height - INSET)} className={`${area} animate-fade`} />
      <path
        d={smoothPath(points)}
        fill="none"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        pathLength={1}
        strokeDasharray={1}
        className={`${line} animate-draw`}
      />
      {last ? <circle cx={last.x} cy={last.y} r={2.2} className="fill-ink-50" /> : null}
    </svg>
  );
}
