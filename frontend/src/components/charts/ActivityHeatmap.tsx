import { hourLabel, longDay, weekdayAndDate } from "../../features/overview/dates";
import type { ActivityRow } from "../../types/intel";
import { heatLevel } from "./geometry";

interface ActivityHeatmapProps {
  rows: readonly ActivityRow[];
}

const CELL = 20;
const LABEL_WIDTH = 66;
const HEADER = 16;
const FOOT = 4;
const LEVELS = 5;
// Opacity of the cell at each heat level; level 0 is a faint cell so the grid stays readable.
const OPACITY = [0.07, 0.28, 0.45, 0.65, 0.85, 1] as const;

function busiest(hours: readonly number[]): { hour: number; lookups: number } | null {
  let best: { hour: number; lookups: number } | null = null;
  for (const [hour, lookups] of hours.entries()) {
    if (lookups > 0 && (best === null || lookups > best.lookups)) best = { hour, lookups };
  }
  return best;
}

/** Lookups by day and by hour of the UTC day. Brighter cells are busier hours. */
export default function ActivityHeatmap({ rows }: ActivityHeatmapProps) {
  const width = LABEL_WIDTH + 24 * CELL;
  const height = HEADER + rows.length * CELL + FOOT;
  const peak = Math.max(0, ...rows.flatMap((row) => row.hours));

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        aria-hidden="true"
        focusable="false"
        className="block h-auto w-full"
      >
        {Array.from({ length: 8 }, (_, step) => step * 3).map((hour) => (
          <text
            key={hour}
            x={LABEL_WIDTH + hour * CELL}
            y={9}
            className="fill-ink-300 font-mono text-[8px]"
          >
            {String(hour).padStart(2, "0")}
          </text>
        ))}
        {rows.map((row, rowIndex) => (
          <g key={row.day}>
            <text
              x={0}
              y={HEADER + rowIndex * CELL + 12}
              className="fill-ink-300 font-mono text-[9px]"
            >
              {weekdayAndDate(row.day)}
            </text>
            {row.hours.map((lookups, hour) => (
              <rect
                key={hour}
                x={LABEL_WIDTH + hour * CELL}
                y={HEADER + rowIndex * CELL}
                width={CELL - 3}
                height={CELL - 3}
                rx={2}
                fillOpacity={OPACITY[heatLevel(lookups, peak, LEVELS)]}
                strokeWidth={1}
                className="fill-cipher hover:stroke-ink-50"
              >
                <title>{`${longDay(row.day)}, ${hourLabel(hour)} UTC: ${lookups} ${lookups === 1 ? "lookup" : "lookups"}`}</title>
              </rect>
            ))}
          </g>
        ))}
      </svg>
      <div className="mt-2 flex items-center justify-between text-[0.68rem] text-ink-300" aria-hidden="true">
        <span>Hours are UTC</span>
        <span className="flex items-center gap-1.5">
          fewer
          {OPACITY.map((opacity) => (
            <span key={opacity} className="size-2.5 rounded-[2px] bg-cipher" style={{ opacity }} />
          ))}
          more
        </span>
      </div>

      {/* The wrapper does the hiding: a table ignores a width of 1px and would widen the page. */}
      <div className="sr-only">
        <table>
          <caption>Lookups per day, with the busiest hour (UTC)</caption>
          <thead>
            <tr>
              <th scope="col">Day</th>
              <th scope="col">Lookups</th>
              <th scope="col">Busiest hour</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const top = busiest(row.hours);
              return (
                <tr key={row.day}>
                  <th scope="row">{longDay(row.day)}</th>
                  <td>{row.hours.reduce((sum, lookups) => sum + lookups, 0)}</td>
                  <td>{top === null ? "None" : `${hourLabel(top.hour)} UTC (${top.lookups})`}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
