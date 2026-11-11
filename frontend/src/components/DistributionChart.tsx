import BarMeter from "./BarMeter";

export interface DistributionRow {
  id: string;
  label: string;
  count: number;
  /** A shape shown before the label, so categories differ by more than colour. */
  marker?: string;
  /** A Tailwind `fill-*` class, written out in full where the row is defined. */
  fillClass: string;
}

interface DistributionChartProps {
  rows: readonly DistributionRow[];
  /** What each bar is a share of. */
  total: number;
}

/** A bar for each category with its count and share printed beside it. */
export default function DistributionChart({ rows, total }: DistributionChartProps) {
  return (
    <ul role="list" className="space-y-2.5">
      {rows.map((row) => {
        const share = total > 0 ? (row.count / total) * 100 : 0;
        return (
          <li key={row.id} className="grid grid-cols-[8rem_minmax(0,1fr)_6rem] items-center gap-3">
            <span className="flex items-center gap-1.5 text-slate-200">
              {row.marker ? <span aria-hidden="true">{row.marker}</span> : null}
              {row.label}
            </span>
            <BarMeter percent={share} fillClass={row.fillClass} />
            <span className="text-right tabular-nums text-slate-200">
              {row.count} <span className="text-slate-400">({Math.round(share)}%)</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}
