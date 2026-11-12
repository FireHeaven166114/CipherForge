import { useState, type ReactNode } from "react";
import { Link } from "react-router";

import { formatCompactCount, formatCount, plural } from "../../features/intel/format";
import { ringSlices } from "./geometry";

export interface DonutSlice {
  key: string;
  label: string;
  value: number;
  /** Tailwind classes, written out in full by the caller so the build can find them. */
  stroke: string;
  swatch: string;
  /** A shape that tells the slices apart without colour. */
  symbol: string;
  /** Where the legend entry leads. Omit it for a slice with nowhere to go. */
  to?: string;
}

interface DonutProps {
  slices: readonly DonutSlice[];
  /** What is counted, in the singular: "indicator". */
  noun: string;
  /** Names the chart for assistive technology. */
  label: string;
  /** Shown in the middle of the ring when no slice is highlighted: "indicators". */
  centerCaption: string;
  emptyText: string;
}

const ENTRY =
  "grid grid-cols-[1.25rem_minmax(0,1fr)_auto_3rem] items-center gap-x-2 rounded-[3px] px-2 py-1 text-left text-sm";

// The ::after spreads the link over its whole row (the <li> is the positioning parent), and the focus
// ring is drawn on it for the same reason: the label alone is clipped by the cell around it.
const ROW_LINK =
  "after:absolute after:inset-0 after:rounded-[3px] focus-visible:outline-none focus-visible:after:outline-2 focus-visible:after:outline-cipher";

function percent(value: number, total: number): string {
  const share = (value / total) * 100;
  return share > 0 && share < 1 ? "<1%" : `${Math.round(share)}%`;
}

/** A ring split by share. Hovering or focusing a legend entry highlights its slice. */
export default function Donut({ slices, noun, label, centerCaption, emptyText }: DonutProps) {
  const [active, setActive] = useState<string | null>(null);
  const total = slices.reduce((sum, slice) => sum + Math.max(0, slice.value), 0);
  if (total === 0) return <p className="py-8 text-center text-sm text-ink-300">{emptyText}</p>;

  const arcs = ringSlices(slices, (slice) => slice.value);
  const highlighted = slices.find((slice) => slice.key === active);

  return (
    <div className="flex flex-col items-center gap-4 @lg:flex-row @lg:items-center">
      <svg
        viewBox="0 0 100 100"
        aria-hidden="true"
        focusable="false"
        className="size-40 shrink-0 @lg:size-44"
        onPointerLeave={() => setActive(null)}
      >
        <circle cx="50" cy="50" r="40" fill="none" strokeWidth="11" className="stroke-ink-800" />
        <g transform="rotate(-90 50 50)">
          {arcs.map(({ item, dash, offset }) => (
            <circle
              key={item.key}
              cx="50"
              cy="50"
              r="40"
              fill="none"
              pathLength={100}
              strokeDasharray={dash}
              strokeDashoffset={offset}
              strokeWidth={active === item.key ? 14 : 11}
              onPointerEnter={() => setActive(item.key)}
              className={`${item.stroke} animate-fade transition-[stroke-width] duration-150 ${
                active !== null && active !== item.key ? "opacity-40" : ""
              }`}
            />
          ))}
        </g>
        <text
          x="50"
          y="51"
          textAnchor="middle"
          className="fill-ink-50 font-mono text-[15px] font-bold"
        >
          {formatCompactCount(highlighted ? highlighted.value : total)}
        </text>
        <text x="50" y="62" textAnchor="middle" className="fill-ink-300 text-[6.5px] uppercase tracking-widest">
          {highlighted ? highlighted.label : centerCaption}
        </text>
      </svg>

      <ul aria-label={label} className="w-full min-w-0 space-y-0.5">
        {slices.map((slice) => {
          const entryLabel = `${slice.label}: ${plural(slice.value, noun)}, ${percent(slice.value, total)}`;
          const mark = (
            <span aria-hidden="true" className="mr-1.5 font-mono text-xs text-ink-300">
              {slice.symbol}
            </span>
          );
          const cells: ReactNode = (
            <>
              <span aria-hidden="true" className="flex items-center gap-1 text-ink-100">
                <span className={`size-2 rounded-full ${slice.swatch}`} />
              </span>
              <span className="min-w-0 truncate text-ink-100">
                {slice.to !== undefined ? (
                  // Only the band's name is the link, so the words it shows are the start of its
                  // accessible name (WCAG 2.5.3). The overlay still makes the whole row the target.
                  <Link to={slice.to} aria-label={entryLabel} className={ROW_LINK}>
                    {mark}
                    {slice.label}
                  </Link>
                ) : (
                  <>
                    {mark}
                    {slice.label}
                  </>
                )}
              </span>
              <span aria-hidden="true" className="font-mono text-xs tabular-nums text-ink-50">
                {formatCount(slice.value)}
              </span>
              <span aria-hidden="true" className="text-right font-mono text-xs tabular-nums text-ink-300">
                {percent(slice.value, total)}
              </span>
            </>
          );
          const handlers = {
            onPointerEnter: () => setActive(slice.key),
            onPointerLeave: () => setActive(null),
            onFocus: () => setActive(slice.key),
            onBlur: () => setActive(null),
          };
          return (
            <li key={slice.key} className="relative">
              {slice.to !== undefined ? (
                <div
                  className={`${ENTRY} transition hover:bg-cipher/10 has-[a:focus-visible]:bg-cipher/10`}
                  {...handlers}
                >
                  {cells}
                </div>
              ) : (
                <div className={ENTRY} role="group" aria-label={entryLabel} {...handlers}>
                  {cells}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
