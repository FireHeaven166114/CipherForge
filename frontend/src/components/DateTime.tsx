import { formatRelative, formatUtc, parseTimestamp } from "../features/intel/format";
import { useNow } from "../hooks/useNow";

interface DateTimeProps {
  value: string | null | undefined;
  /** Shown when there is no readable value. */
  fallback?: string;
  /** Puts the relative time on its own line, which suits narrow table cells. */
  stacked?: boolean;
}

/** An exact UTC time for correlating with other systems, plus how long ago that was. */
export default function DateTime({ value, fallback = "Never", stacked = false }: DateTimeProps) {
  const now = useNow();
  const date = parseTimestamp(value);
  if (date === null) return <span className="text-slate-400">{fallback}</span>;

  const relative = formatRelative(date, now);
  return (
    <time dateTime={date.toISOString()}>
      {formatUtc(date)}{" "}
      <span className={stacked ? "block text-xs text-slate-400" : "text-slate-400"}>
        {stacked ? relative : `(${relative})`}
      </span>
    </time>
  );
}
