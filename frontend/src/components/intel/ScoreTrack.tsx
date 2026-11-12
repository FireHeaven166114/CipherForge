import { BAND_STRIPS, type WaterfallStep } from "../../features/intel/waterfall";

/** A segment that is too short to see would look like no points at all, so it gets a sliver. */
const MIN_SEGMENT = 1.2;

const KIND_FILL = { add: "fill-cipher", trim: "fill-ember" } as const;

// Written out in full so Tailwind can find every class. Later segments start a little later.
const DELAYS = [
  "[animation-delay:0ms]",
  "[animation-delay:110ms]",
  "[animation-delay:220ms]",
  "[animation-delay:330ms]",
  "[animation-delay:440ms]",
  "[animation-delay:550ms]",
] as const;

interface ScoreTrackProps {
  /** The part of the score this row adds or takes away. */
  step: WaterfallStep;
  /** Where a score of 100 sits on the track (see `buildWaterfall`). */
  limit: number;
  /** Overrides the colour of the segment, for the row that shows the final score. */
  fillClass?: string;
  /** The row's position, so the segments appear one after another. */
  index?: number;
}

/**
 * A strip of the 0 to 100 scale, tinted by risk band, with one segment on it. It is a picture of
 * the number beside it and is hidden from assistive technology, which reads the number itself.
 */
export default function ScoreTrack({ step, limit, fillClass, index = 0 }: ScoreTrackProps) {
  const width = step.to > step.from ? Math.max(step.to - step.from, MIN_SEGMENT) : 0;
  const delay = DELAYS[Math.min(index, DELAYS.length - 1)];
  return (
    <svg
      viewBox="0 0 100 10"
      preserveAspectRatio="none"
      aria-hidden="true"
      focusable="false"
      className="h-3 w-full min-w-28"
    >
      {BAND_STRIPS.map((strip) => (
        <rect
          key={strip.from}
          x={(strip.from * limit) / 100}
          width={((strip.to - strip.from) * limit) / 100}
          height="10"
          className={strip.fill}
        />
      ))}
      {limit < 100 ? (
        <line x1={limit} x2={limit} y1="0" y2="10" strokeWidth="1" vectorEffect="non-scaling-stroke" className="stroke-ink-300" />
      ) : null}
      {width > 0 ? (
        <rect
          x={Math.min(step.from, 100 - width)}
          width={width}
          height="10"
          className={`${fillClass ?? KIND_FILL[step.kind]} origin-left animate-grow-x [transform-box:fill-box] ${delay}`}
        />
      ) : null}
    </svg>
  );
}
