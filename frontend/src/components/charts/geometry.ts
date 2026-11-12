/** Pure geometry for the hand-built SVG charts. No React here, so every function is easy to test. */

export interface Point {
  x: number;
  y: number;
}

export function roundTo(value: number, digits = 2): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

/** Rounds for SVG path output so paths stay short and stable. */
function fmt(value: number): string {
  return String(roundTo(value));
}

/**
 * The smallest 1, 2, 5 or 10 times a power of ten that is at least `value`.
 * Used to pick tidy axis steps.
 */
export function niceCeil(value: number): number {
  if (!(value > 0) || !Number.isFinite(value)) return 1;
  const base = 10 ** Math.floor(Math.log10(value));
  const fraction = value / base;
  const nice = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  return nice * base;
}

export interface Axis {
  /** The top of the axis: a whole multiple of `step` that is at least the largest value. */
  top: number;
  step: number;
  ticks: number[];
}

/** A value axis from zero with at most about five tidy ticks. Values are counts, so steps are whole. */
export function valueAxis(maxValue: number): Axis {
  const max = Math.max(1, Number.isFinite(maxValue) ? maxValue : 1);
  const step = Math.max(1, niceCeil(max / 4));
  const top = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let tick = 0; tick <= top + step / 1000; tick += step) ticks.push(tick);
  return { top, step, ticks };
}

function at(values: readonly number[], index: number): number {
  return values[index] ?? 0;
}

/**
 * A smooth curve through the points that never overshoots between them (monotone cubic
 * interpolation), so a quiet day never dips below zero on the chart. The x values must increase.
 */
export function smoothPath(points: readonly Point[]): string {
  const count = points.length;
  const first = points[0];
  if (first === undefined) return "";
  if (count === 1) return `M${fmt(first.x)},${fmt(first.y)}`;

  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  const dx: number[] = [];
  const slope: number[] = [];
  for (let i = 0; i < count - 1; i++) {
    const width = at(xs, i + 1) - at(xs, i);
    dx.push(width);
    slope.push(width === 0 ? 0 : (at(ys, i + 1) - at(ys, i)) / width);
  }

  const tangent: number[] = [at(slope, 0)];
  for (let i = 1; i < count - 1; i++) {
    const before = at(slope, i - 1);
    const after = at(slope, i);
    if (before * after <= 0) {
      tangent.push(0);
    } else {
      const w1 = 2 * at(dx, i) + at(dx, i - 1);
      const w2 = at(dx, i) + 2 * at(dx, i - 1);
      tangent.push((w1 + w2) / (w1 / before + w2 / after));
    }
  }
  tangent.push(at(slope, count - 2));

  let path = `M${fmt(first.x)},${fmt(first.y)}`;
  for (let i = 0; i < count - 1; i++) {
    const width = at(dx, i);
    const c1x = at(xs, i) + width / 3;
    const c1y = at(ys, i) + (at(tangent, i) * width) / 3;
    const c2x = at(xs, i + 1) - width / 3;
    const c2y = at(ys, i + 1) - (at(tangent, i + 1) * width) / 3;
    path += `C${fmt(c1x)},${fmt(c1y)} ${fmt(c2x)},${fmt(c2y)} ${fmt(at(xs, i + 1))},${fmt(at(ys, i + 1))}`;
  }
  return path;
}

/** The smooth line closed down to `baseline`, for filling the area under it. */
export function areaPath(points: readonly Point[], baseline: number): string {
  const first = points[0];
  const last = points[points.length - 1];
  if (first === undefined || last === undefined) return "";
  return `${smoothPath(points)}L${fmt(last.x)},${fmt(baseline)}L${fmt(first.x)},${fmt(baseline)}Z`;
}

/** A point on a circle; angles run clockwise from twelve o'clock, in degrees. */
export function polar(cx: number, cy: number, radius: number, degrees: number): Point {
  const radians = ((degrees - 90) * Math.PI) / 180;
  return { x: cx + radius * Math.cos(radians), y: cy + radius * Math.sin(radians) };
}

/** Short radial tick marks around a circle, as one path: the dial of the cipher wheel. */
export function ticksPath(
  cx: number,
  cy: number,
  innerRadius: number,
  outerRadius: number,
  count: number,
): string {
  let path = "";
  for (let i = 0; i < count; i++) {
    const angle = (360 / count) * i;
    const from = polar(cx, cy, innerRadius, angle);
    const to = polar(cx, cy, outerRadius, angle);
    path += `M${fmt(from.x)},${fmt(from.y)}L${fmt(to.x)},${fmt(to.y)}`;
  }
  return path;
}

/** A closed polygon through the points, as an SVG `points` attribute. */
export function polygonPoints(points: readonly Point[]): string {
  return points.map((point) => `${fmt(point.x)},${fmt(point.y)}`).join(" ");
}

export interface Slice<T> {
  item: T;
  /** Share of the whole, 0 to 1. */
  share: number;
  /** For `strokeDasharray` on a circle drawn with `pathLength={100}`. */
  dash: string;
  /** For `strokeDashoffset` on the same circle. */
  offset: number;
}

/**
 * Splits a ring into arcs, one per value, for a donut drawn with `pathLength={100}` and rotated
 * to start at twelve o'clock. `gap` is the visible gap between slices in percent of the ring.
 * Values of zero get no slice.
 */
export function ringSlices<T>(
  items: readonly T[],
  valueOf: (item: T) => number,
  gap = 0.8,
): Slice<T>[] {
  const total = items.reduce((sum, item) => sum + Math.max(0, valueOf(item)), 0);
  if (total <= 0) return [];
  const slices: Slice<T>[] = [];
  let consumed = 0;
  for (const item of items) {
    const value = Math.max(0, valueOf(item));
    if (value === 0) continue;
    const share = value / total;
    const length = Math.max(0.01, share * 100 - gap);
    slices.push({
      item,
      share,
      dash: `${roundTo(length, 3)} ${roundTo(100 - length, 3)}`,
      offset: -roundTo(consumed + gap / 2, 3),
    });
    consumed += share * 100;
  }
  return slices;
}

/** Which of `levels` tint steps a heatmap cell gets: 0 for empty, then growing with the square root. */
export function heatLevel(value: number, max: number, levels: number): number {
  if (value <= 0 || max <= 0) return 0;
  const scaled = Math.sqrt(Math.min(1, value / max));
  return Math.min(levels, Math.max(1, Math.ceil(scaled * levels)));
}

export interface MapFrame {
  west: number;
  east: number;
  north: number;
  south: number;
  width: number;
  height: number;
}

/** Where a longitude and latitude land on an equirectangular map of the given size. */
export function project(longitude: number, latitude: number, frame: MapFrame): Point {
  return {
    x: ((longitude - frame.west) / (frame.east - frame.west)) * frame.width,
    y: ((frame.north - latitude) / (frame.north - frame.south)) * frame.height,
  };
}
