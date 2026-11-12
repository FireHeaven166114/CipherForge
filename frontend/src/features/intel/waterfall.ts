/** One factor, drawn as a segment of the running total that builds up to the score. */
export interface WaterfallStep {
  /** Where the segment starts and ends, as a share (0 to 100) of the track. `from` <= `to`. */
  from: number;
  to: number;
  /** "trim" lowers the running total, as the single-source cap does. */
  kind: "add" | "trim";
}

export interface Waterfall {
  steps: WaterfallStep[];
  /** The running total after the last factor, as a share of the track. */
  end: number;
  /** Where a score of 100 sits on the track. Below 100 only when the factors briefly add up to more. */
  limit: number;
}

/** The risk bands of intel-risk-v1 as shares of a 0 to 100 score, with the fill that tints each. */
export const BAND_STRIPS = [
  { from: 0, to: 20, fill: "fill-info/15" },
  { from: 20, to: 40, fill: "fill-low/15" },
  { from: 40, to: 60, fill: "fill-med/15" },
  { from: 60, to: 80, fill: "fill-high/15" },
  { from: 80, to: 100, fill: "fill-crit/15" },
] as const;

const FULL_SCORE = 100;

/**
 * Lays the points of each factor end to end. The track always shows 0 to 100; when the factors
 * add up to more than that before a cap trims them, the whole track is squeezed so nothing is
 * cut off. This is a picture of the factor table, which stays the exact record.
 */
export function buildWaterfall(points: readonly number[]): Waterfall {
  const totals: number[] = [0];
  for (const value of points) {
    const previous = totals[totals.length - 1] ?? 0;
    totals.push(Math.max(0, previous + (Number.isFinite(value) ? value : 0)));
  }
  const peak = Math.max(FULL_SCORE, ...totals);
  const share = (value: number) => (value / peak) * 100;

  return {
    steps: points.map((_point, index) => {
      const before = share(totals[index] ?? 0);
      const after = share(totals[index + 1] ?? 0);
      return {
        from: Math.min(before, after),
        to: Math.max(before, after),
        kind: after < before ? "trim" : "add",
      };
    }),
    end: share(totals[totals.length - 1] ?? 0),
    limit: share(FULL_SCORE),
  };
}
