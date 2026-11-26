import { formatRelative } from "../features/intel/format";
import { formatIst, parseTimestamp } from "../features/time/ist";
import { useNow } from "../hooks/useNow";

interface DateTimeProps {
  value: string | null | undefined;
  /** Shown when there is no readable value. */
  fallback?: string;
  /** Puts the relative time on its own line, which suits narrow table cells. */
  stacked?: boolean;
}

/** An exact IST time (`DD-MM-YYYY hh:mm:ss A IST`), plus how long ago that was. */
export default function DateTime({ value, fallback = "Never", stacked = false }: DateTimeProps) {
  const now = useNow();
  const date = parseTimestamp(value);
  if (date === null) return <span className="text-ink-300">{fallback}</span>;

  const relative = formatRelative(date, now);
  return (
    <time dateTime={date.toISOString()}>
      {formatIst(date)}{" "}
      <span className={stacked ? "block text-xs text-ink-300" : "text-ink-300"}>
        {stacked ? relative : `(${relative})`}
      </span>
    </time>
  );
}
