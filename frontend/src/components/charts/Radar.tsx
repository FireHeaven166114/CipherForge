import { Fragment } from "react";
import { Link } from "react-router";

import { formatCompactCount, plural } from "../../features/intel/format";
import { polar, polygonPoints, roundTo, valueAxis } from "./geometry";

export interface RadarAxis {
  key: string;
  label: string;
  value: number;
  /** Where the axis label leads. Omit it for an axis with nowhere to go. */
  to?: string;
}

interface RadarProps {
  axes: readonly RadarAxis[];
  /** What is counted, in the singular: "indicator". */
  noun: string;
  /** Names the chart for assistive technology. */
  label: string;
}

const WIDTH = 260;
const HEIGHT = 236;
const CX = 130;
const CY = 118;
const RADIUS = 78;
const HIT_HEIGHT = 26;
// The counts beside the chart have a few characters of room, so from here on they are shortened.
const COMPACT_FROM = 10_000;

function anchorFor(angle: number): "start" | "middle" | "end" {
  const sine = Math.sin((angle * Math.PI) / 180);
  return Math.abs(sine) < 0.2 ? "middle" : sine > 0 ? "start" : "end";
}

/** A box around a label (and the count under it) that is at least 24 pixels each way and stays in the chart. */
function hitBox(x: number, y: number, anchor: "start" | "middle" | "end", characters: number) {
  const width = Math.max(32, characters * 6.5 + 8);
  const left = anchor === "start" ? x - 4 : anchor === "end" ? x + 4 - width : x - width / 2;
  return {
    x: roundTo(Math.min(Math.max(left, 0), WIDTH - width)),
    y: roundTo(y - 11),
    width: roundTo(width),
    height: HIT_HEIGHT,
  };
}

/** A radar of how many indicators each type has. The rings are whole-number steps from the centre. */
export default function Radar({ axes, noun, label }: RadarProps) {
  if (axes.length < 3) return null;
  const axis = valueAxis(Math.max(0, ...axes.map((item) => item.value)));
  const angleOf = (index: number) => (360 / axes.length) * index;
  const radiusOf = (value: number) => (Math.max(0, value) / axis.top) * RADIUS;
  const rings = axis.ticks.filter((tick) => tick > 0);
  const shape = axes.map((item, index) => polar(CX, CY, radiusOf(item.value), angleOf(index)));

  return (
    <svg
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      role="group"
      aria-label={label}
      className="mx-auto block h-auto w-full max-w-[22rem]"
    >
      {rings.map((tick) => (
        <polygon
          key={tick}
          points={polygonPoints(axes.map((_, index) => polar(CX, CY, radiusOf(tick), angleOf(index))))}
          fill="none"
          className="stroke-ink-700"
          strokeDasharray={tick === axis.top ? undefined : "2 3"}
        />
      ))}
      {axes.map((item, index) => {
        const end = polar(CX, CY, RADIUS, angleOf(index));
        return (
          <line
            key={item.key}
            x1={CX}
            y1={CY}
            x2={roundTo(end.x)}
            y2={roundTo(end.y)}
            className="stroke-ink-700"
          />
        );
      })}
      {rings.map((tick) => (
        <text
          key={tick}
          x={CX + 4}
          y={roundTo(CY - radiusOf(tick) - 2)}
          aria-hidden="true"
          className="fill-ink-300 font-mono text-[8px]"
        >
          {formatCompactCount(tick, COMPACT_FROM)}
        </text>
      ))}

      <polygon
        points={polygonPoints(shape)}
        strokeWidth="1.6"
        strokeLinejoin="round"
        className="animate-fade fill-cipher/20 stroke-cipher"
      />
      {axes.map((item, index) => {
        const point = shape[index];
        return point ? (
          <circle key={item.key} cx={roundTo(point.x)} cy={roundTo(point.y)} r="3" className="fill-cipher" />
        ) : null;
      })}

      {axes.map((item, index) => {
        const spot = polar(CX, CY, RADIUS + 16, angleOf(index));
        const anchor = anchorFor(angleOf(index));
        const x = roundTo(spot.x);
        const y = roundTo(spot.y + 3);
        const name = `${item.label}: ${plural(item.value, noun)}`;
        const labelText = (
          <text x={x} y={y} textAnchor={anchor} className="fill-ink-100 text-[10px] font-semibold">
            {item.label}
          </text>
        );
        const valueText = (
          <text
            x={x}
            y={y + 11}
            textAnchor={anchor}
            aria-hidden="true"
            className="pointer-events-none fill-ink-300 font-mono text-[9px]"
          >
            {formatCompactCount(item.value, COMPACT_FROM)}
          </text>
        );
        if (item.to === undefined) {
          return (
            <g key={item.key} role="img" aria-label={name}>
              {labelText}
              {valueText}
            </g>
          );
        }
        // Only the label sits inside the link, so the words it shows are the start of its accessible name
        // (WCAG 2.5.3). The transparent box keeps the link as easy to press as the label and count together.
        const box = hitBox(x, y, anchor, item.label.length);
        return (
          <Fragment key={item.key}>
            <Link to={item.to} aria-label={name} className="hover:[&_text]:fill-cipher">
              <rect {...box} rx="3" className="fill-transparent" />
              {labelText}
            </Link>
            {valueText}
          </Fragment>
        );
      })}
    </svg>
  );
}
