import { Link } from "react-router";

import { formatCompactCount, formatCount } from "../../features/intel/format";
import type { Trend } from "../../features/overview/trend";
import { LABEL } from "../styles";
import Sparkline from "../charts/Sparkline";
import AnimatedNumber from "../hud/AnimatedNumber";
import { ArrowIcon } from "../hud/Icons";
import StatusLed from "../hud/StatusLed";

export type KpiTone = "cipher" | "high" | "crit" | "muted";

// Written out in full so Tailwind can find every class.
const TONES: Record<KpiTone, { value: string; edge: string; line: string; area: string }> = {
  cipher: { value: "text-ink-50", edge: "bg-cipher", line: "stroke-cipher", area: "fill-cipher/15" },
  high: { value: "text-high", edge: "bg-high", line: "stroke-high", area: "fill-high/15" },
  crit: { value: "text-crit", edge: "bg-crit", line: "stroke-crit", area: "fill-crit/15" },
  muted: { value: "text-ink-100", edge: "bg-ink-400", line: "stroke-ink-300", area: "fill-ink-300/15" },
};

interface KpiTileProps {
  /** A short tag printed in the corner, such as "KPI-01". Decorative. */
  code: string;
  label: string;
  value: number;
  tone?: KpiTone;
  /** How the number compares with the period before it. */
  trend?: Trend;
  /** A line of explanation under the number. */
  note?: string;
  /** Daily values for a small trend line. Decorative: the trend text states the change. */
  spark?: readonly number[];
  /** Where the tile leads. Every tile is a drill-down into the list behind the number. */
  to: string;
  /** Draws attention to a count that deserves it, such as critical indicators. */
  pulsing?: boolean;
}

/** One headline number. The whole tile is a link to the indicators it counts. */
export default function KpiTile({
  code,
  label,
  value,
  tone = "cipher",
  trend,
  note,
  spark,
  to,
  pulsing = false,
}: KpiTileProps) {
  const style = TONES[tone];
  return (
    <li data-reveal className="min-w-0">
      <Link
        to={to}
        className="hud-panel group relative flex h-full flex-col rounded-ui p-4 pl-5 transition hover:border-cipher/60 hover:shadow-glow"
      >
        <span aria-hidden="true" className={`absolute inset-y-4 left-0 w-[3px] rounded-r-full ${style.edge}`} />
        <span className="flex items-center justify-between gap-2">
          <span className={`${LABEL} flex items-center gap-2`}>
            {pulsing ? <StatusLed tone="bad" pulsing /> : null}
            {label}
          </span>
          <span aria-hidden="true" className="font-mono text-[0.62rem] text-ink-300">
            {code}
          </span>
        </span>
        {/* The trend line moves below the number when a big number leaves it no room beside it. */}
        <span className="mt-2 flex flex-wrap items-end justify-between gap-x-3 gap-y-1">
          <AnimatedNumber
            value={value}
            format={formatCompactCount}
            spoken={formatCount}
            className={`font-mono text-4xl font-semibold tabular-nums ${style.value}`}
          />
          {spark !== undefined ? <Sparkline values={spark} line={style.line} area={style.area} /> : null}
        </span>
        <span className="mt-2 block space-y-0.5 text-xs text-ink-300">
          {note !== undefined ? <span className="block">{note}</span> : null}
          {trend !== undefined ? (
            <span className="flex items-center gap-1.5">
              {trend.direction !== "flat" ? (
                <ArrowIcon direction={trend.direction} className="size-3 shrink-0 text-cipher" />
              ) : null}
              {trend.text}
            </span>
          ) : null}
        </span>
      </Link>
    </li>
  );
}
