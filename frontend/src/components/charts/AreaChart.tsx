import { useMemo, useState, type KeyboardEvent, type PointerEvent } from "react";

import { formatCompactCount } from "../../features/intel/format";
import { areaPath, roundTo, smoothPath, valueAxis, type Point } from "./geometry";
import { useChartWidth } from "./useChartWidth";

export interface AreaSeries {
  id: string;
  label: string;
  values: readonly number[];
  /** Tailwind classes, written out in full by the caller so the build can find them. */
  line: string;
  area: string;
  dot: string;
  swatch: string;
}

interface AreaChartProps {
  /** One entry per position on the x axis, such as a day. */
  categories: readonly string[];
  /** The short text under the axis. */
  axisLabel: (category: string) => string;
  /** The full text in the tooltip, the announcement and the data table. */
  titleOf: (category: string) => string;
  series: readonly AreaSeries[];
  /** Names the chart for assistive technology. */
  label: string;
  /** The heading of the first column of the data table. */
  categoryName?: string;
  /** Shown inside the chart when every value is zero. */
  emptyText?: string;
  height?: number;
}

const PAD = { top: 14, right: 18, bottom: 26, left: 36 };
const TIP_MIN_WIDTH = 164;
const TIP_ROW = 16;
// Roughly how wide one character is: a 10px monospace axis label, 11px text and 11px monospace in the tooltip.
const AXIS_CHAR = 6.1;
const TIP_CHAR = 5.8;
const TIP_TITLE_CHAR = 6.2;
const TIP_NUMBER_CHAR = 6.7;
// From here on an axis label is shortened ("12.5K"), so the axis never needs more than a few characters.
const AXIS_COMPACT_FROM = 10_000;

function clamp(value: number, low: number, high: number): number {
  return Math.min(high, Math.max(low, value));
}

/**
 * Smooth area chart drawn in real pixels. Hover or touch shows a crosshair and a tooltip; with
 * the keyboard, focus the chart and use the arrow keys. A data table and a live announcement carry
 * the same numbers for assistive technology.
 */
export default function AreaChart({
  categories,
  axisLabel,
  titleOf,
  series,
  label,
  categoryName = "Day",
  emptyText = "Nothing recorded in this period.",
  height = 230,
}: AreaChartProps) {
  const [frameRef, width] = useChartWidth<HTMLDivElement>();
  const [active, setActive] = useState<number | null>(null);
  const count = categories.length;

  const plot = useMemo(() => {
    const maxValue = Math.max(0, ...series.flatMap((item) => item.values));
    const axis = valueAxis(maxValue);
    const ticks = axis.ticks.map((value) => ({ value, text: formatCompactCount(value, AXIS_COMPACT_FROM) }));
    // The margin on the left grows with the longest label on the axis, so no label is cut off.
    const left = Math.max(PAD.left, Math.ceil(Math.max(...ticks.map((tick) => tick.text.length)) * AXIS_CHAR) + 12);
    const plotWidth = Math.max(40, width - left - PAD.right);
    const plotHeight = height - PAD.top - PAD.bottom;
    const xAt = (index: number) => left + (count <= 1 ? plotWidth / 2 : (index / (count - 1)) * plotWidth);
    const yAt = (value: number) => PAD.top + plotHeight - (Math.max(0, value) / axis.top) * plotHeight;
    const baseline = PAD.top + plotHeight;
    const drawn = series.map((item) => {
      const points: Point[] = categories.map((_, index) => ({ x: xAt(index), y: yAt(item.values[index] ?? 0) }));
      return { item, points, line: smoothPath(points), fill: areaPath(points, baseline) };
    });
    return { left, plotWidth, plotHeight, maxValue, ticks, xAt, yAt, baseline, drawn };
  }, [categories, series, width, height, count]);

  const labelEvery = Math.max(1, Math.ceil(count / Math.max(2, Math.floor(plot.plotWidth / 64))));

  const nearest = (event: PointerEvent<SVGSVGElement>): number => {
    const rect = event.currentTarget.getBoundingClientRect();
    const scale = rect.width > 0 ? width / rect.width : 1;
    const x = (event.clientX - rect.left) * scale;
    return clamp(Math.round(((x - plot.left) / plot.plotWidth) * (count - 1)), 0, count - 1);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const last = count - 1;
    const current = active ?? last;
    const target =
      event.key === "ArrowLeft"
        ? Math.max(0, current - 1)
        : event.key === "ArrowRight"
          ? Math.min(last, current + 1)
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? last
              : null;
    if (target !== null) {
      event.preventDefault();
      setActive(target);
    } else if (event.key === "Escape" && active !== null) {
      event.preventDefault();
      setActive(null);
    }
  };

  if (count === 0) {
    return <p className="py-8 text-center text-sm text-ink-300">{emptyText}</p>;
  }

  const activeCategory = active === null ? undefined : categories[active];
  const readout =
    active === null || activeCategory === undefined
      ? ""
      : `${titleOf(activeCategory)}: ${series.map((item) => `${item.label} ${item.values[active] ?? 0}`).join(", ")}`;

  // The tooltip is as wide as its widest line, so a long name or a big number never runs into its neighbour.
  const tipTitle = activeCategory === undefined ? "" : titleOf(activeCategory);
  const tipRows =
    active === null ? [] : series.map((item) => ({ item, value: formatCompactCount(item.values[active] ?? 0) }));
  const tipWidth = Math.max(
    TIP_MIN_WIDTH,
    20 + tipTitle.length * TIP_TITLE_CHAR,
    ...tipRows.map(({ item, value }) => 43 + item.label.length * TIP_CHAR + value.length * TIP_NUMBER_CHAR),
  );
  const tipX =
    active === null
      ? 0
      : plot.xAt(active) + 12 + tipWidth > width - 4
        ? Math.max(4, plot.xAt(active) - 12 - tipWidth)
        : plot.xAt(active) + 12;
  const tipHeight = 26 + series.length * TIP_ROW;

  return (
    <div>
      <div
        ref={frameRef}
        role="group"
        tabIndex={0}
        aria-label={label}
        aria-roledescription="interactive chart"
        onKeyDown={onKeyDown}
        onFocus={() => setActive((current) => current ?? count - 1)}
        onBlur={() => setActive(null)}
        className="relative w-full select-none rounded-sm"
      >
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          aria-hidden="true"
          focusable="false"
          onPointerMove={(event) => setActive(nearest(event))}
          onPointerDown={(event) => setActive(nearest(event))}
          onPointerLeave={() => setActive(null)}
          className="block cursor-crosshair touch-pan-y"
        >
          {plot.ticks.map(({ value, text }) => (
            <g key={value}>
              <line
                x1={plot.left}
                x2={width - PAD.right}
                y1={roundTo(plot.yAt(value))}
                y2={roundTo(plot.yAt(value))}
                className={value === 0 ? "stroke-ink-500" : "stroke-ink-700"}
                strokeDasharray={value === 0 ? undefined : "2 4"}
              />
              <text
                x={plot.left - 8}
                y={roundTo(plot.yAt(value) + 3.5)}
                textAnchor="end"
                className="fill-ink-300 font-mono text-[10px]"
              >
                {text}
              </text>
            </g>
          ))}

          {categories.map((category, index) =>
            index % labelEvery === (count - 1) % labelEvery ? (
              <text
                key={category}
                x={roundTo(plot.xAt(index))}
                y={height - 7}
                textAnchor={index === 0 ? "start" : index === count - 1 ? "end" : "middle"}
                className="fill-ink-300 font-mono text-[10px]"
              >
                {axisLabel(category)}
              </text>
            ) : null,
          )}

          {plot.drawn.map(({ item, fill }) => (
            <path key={`${item.id}-area`} d={fill} className={`${item.area} animate-fade`} />
          ))}
          {plot.drawn.map(({ item, line }) => (
            <path
              key={`${item.id}-line`}
              d={line}
              fill="none"
              strokeWidth={2}
              strokeLinecap="round"
              strokeLinejoin="round"
              pathLength={1}
              strokeDasharray={1}
              className={`${item.line} animate-draw`}
            />
          ))}

          {plot.maxValue === 0 ? (
            <text
              x={plot.left + plot.plotWidth / 2}
              y={PAD.top + plot.plotHeight / 2 - 8}
              textAnchor="middle"
              className="fill-ink-300 text-[12px]"
            >
              {emptyText}
            </text>
          ) : null}

          {active !== null ? (
            <g>
              <line
                x1={roundTo(plot.xAt(active))}
                x2={roundTo(plot.xAt(active))}
                y1={PAD.top}
                y2={plot.baseline}
                className="stroke-cipher/60"
                strokeDasharray="3 3"
              />
              {plot.drawn.map(({ item, points }) => {
                const point = points[active];
                return point ? (
                  <circle
                    key={item.id}
                    cx={roundTo(point.x)}
                    cy={roundTo(point.y)}
                    r={4}
                    strokeWidth={2}
                    className={`${item.dot} stroke-void`}
                  />
                ) : null;
              })}
              <g transform={`translate(${roundTo(tipX)} ${PAD.top + 4})`}>
                <rect
                  width={tipWidth}
                  height={tipHeight}
                  rx={3}
                  className="fill-ink-950/95 stroke-cipher/50"
                />
                <text x={10} y={17} className="fill-ink-50 text-[11px] font-semibold">
                  {tipTitle}
                </text>
                {tipRows.map(({ item, value }, row) => (
                  <g key={item.id} transform={`translate(10 ${28 + row * TIP_ROW})`}>
                    <circle cx={3} cy={-3.5} r={3} className={item.dot} />
                    <text x={13} className="fill-ink-200 text-[11px]">
                      {item.label}
                    </text>
                    <text x={tipWidth - 20} textAnchor="end" className="fill-ink-50 font-mono text-[11px]">
                      {value}
                    </text>
                  </g>
                ))}
              </g>
            </g>
          ) : null}
        </svg>

        {/* The wrapper does the hiding: a table ignores a width of 1px and would widen the page. */}
        <div className="sr-only">
          <table>
            <caption>{label}</caption>
            <thead>
              <tr>
                <th scope="col">{categoryName}</th>
                {series.map((item) => (
                  <th key={item.id} scope="col">
                    {item.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {categories.map((category, index) => (
                <tr key={category}>
                  <th scope="row">{titleOf(category)}</th>
                  {series.map((item) => (
                    <td key={item.id}>{item.values[index] ?? 0}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="sr-only" role="status" aria-live="polite">
          {readout}
        </p>
      </div>

      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink-300">
        {series.map((item) => (
          <li key={item.id} className="flex items-center gap-2">
            <span aria-hidden="true" className={`size-2.5 rounded-full ${item.swatch}`} />
            {item.label}
          </li>
        ))}
        <li aria-hidden="true" className="ml-auto hidden text-ink-300 @lg:block">
          Hover or use ← → to inspect
        </li>
      </ul>
    </div>
  );
}
