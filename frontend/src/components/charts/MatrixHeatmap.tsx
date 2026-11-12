import { Link } from "react-router";

import { CLASSIFICATION_META } from "../../features/intel/classification";
import { indicatorsHref } from "../../features/intel/filters";
import { plural } from "../../features/intel/format";
import { INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { MatrixRow, RiskBand } from "../../types/intel";
import { heatLevel } from "./geometry";

// Calm to hot, left to right. "Not assessed" has no verdict, so it sits apart at the end.
const COLUMNS: readonly RiskBand[] = ["informational", "low", "medium", "high", "critical", "not_assessed"];

// Written out in full so Tailwind finds every class. Five tint steps per column. The strongest step is held
// at 40% because that is as bright as yellow, the lightest hue, can get while the count on it still
// reads at 4.5:1 or better. Nothing is gained from a hotter tint if the number on it cannot be read.
const HEAT: Record<RiskBand, readonly string[]> = {
  informational: ["bg-info/10", "bg-info/18", "bg-info/26", "bg-info/33", "bg-info/40"],
  low: ["bg-low/10", "bg-low/18", "bg-low/26", "bg-low/33", "bg-low/40"],
  medium: ["bg-med/10", "bg-med/18", "bg-med/26", "bg-med/33", "bg-med/40"],
  high: ["bg-high/10", "bg-high/18", "bg-high/26", "bg-high/33", "bg-high/40"],
  critical: ["bg-crit/10", "bg-crit/18", "bg-crit/26", "bg-crit/33", "bg-crit/40"],
  not_assessed: ["bg-ink-600/20", "bg-ink-600/30", "bg-ink-600/45", "bg-ink-500/55", "bg-ink-500/70"],
};
const LEVELS = 5;

function bandLabel(band: RiskBand): string {
  return band === "not_assessed" ? "Not assessed" : CLASSIFICATION_META[band].label;
}

function bandSymbol(band: RiskBand): string {
  return band === "not_assessed" ? "–" : CLASSIFICATION_META[band].symbol;
}

function bandText(band: RiskBand): string {
  return band === "not_assessed" ? "text-ink-300" : CLASSIFICATION_META[band].text;
}

interface MatrixHeatmapProps {
  rows: readonly MatrixRow[];
}

/**
 * Indicator type by risk band. Every non-zero count is a link to the indicators list filtered the
 * same way, so the matrix is a way into the data and not only a picture of it.
 */
export default function MatrixHeatmap({ rows }: MatrixHeatmapProps) {
  const peak = Math.max(0, ...rows.flatMap((row) => COLUMNS.map((band) => row.counts[band] ?? 0)));

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[34rem] border-separate border-spacing-1 text-sm">
        <caption className="sr-only">Indicators by type and risk band</caption>
        <thead>
          <tr>
            <th scope="col" className="w-20 px-1 pb-1 text-left text-[0.62rem] font-semibold uppercase tracking-[0.12em] text-ink-300">
              Type
            </th>
            {COLUMNS.map((band) => (
              <th
                key={band}
                scope="col"
                className={`whitespace-nowrap px-1 pb-1 text-center text-[0.62rem] font-semibold uppercase tracking-[0.08em] ${bandText(band)}`}
              >
                <span aria-hidden="true" className="mr-1">
                  {bandSymbol(band)}
                </span>
                {bandLabel(band)}
              </th>
            ))}
            <th scope="col" className="w-12 px-1 pb-1 text-right text-[0.62rem] font-semibold uppercase tracking-[0.12em] text-ink-300">
              Total
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const typeLabel = INDICATOR_TYPE_LABELS[row.indicator_type];
            const total = COLUMNS.reduce((sum, band) => sum + (row.counts[band] ?? 0), 0);
            return (
              <tr key={row.indicator_type}>
                <th scope="row" className="px-1 text-left font-medium text-ink-100">
                  <Link
                    to={indicatorsHref({ type: row.indicator_type })}
                    className="rounded-chip hover:text-cipher"
                  >
                    {typeLabel}
                  </Link>
                </th>
                {COLUMNS.map((band) => {
                  const count = row.counts[band] ?? 0;
                  if (count === 0) {
                    return (
                      <td key={band} className="rounded-chip bg-ink-900/60 py-2 text-center font-mono text-xs text-ink-300">
                        0
                      </td>
                    );
                  }
                  const tint = HEAT[band][heatLevel(count, peak, LEVELS) - 1] ?? "";
                  const cell = "block py-2 text-center font-mono text-sm font-semibold tabular-nums text-ink-50";
                  return (
                    <td key={band} className={`rounded-chip p-0 ${tint}`}>
                      <Link
                        to={indicatorsHref({ type: row.indicator_type, classification: band })}
                        aria-label={`${typeLabel}, ${bandLabel(band)}: ${plural(count, "indicator")}`}
                        className={`${cell} rounded-chip transition hover:bg-ink-950/25 hover:inset-ring-1 hover:inset-ring-cipher`}
                      >
                        {count}
                      </Link>
                    </td>
                  );
                })}
                <td className="px-1 text-right font-mono text-xs tabular-nums text-ink-200">{total}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
