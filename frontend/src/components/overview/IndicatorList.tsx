import { Link } from "react-router";

import { CLASSIFICATION_META, isIndicatorAssessed } from "../../features/intel/classification";
import { formatRelative, formatUtc, parseTimestamp } from "../../features/intel/format";
import { INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import { useNow } from "../../hooks/useNow";
import type { Indicator } from "../../types/intel";
import ClassificationBadge from "../intel/ClassificationBadge";

interface IndicatorListProps {
  indicators: readonly Indicator[];
  /** Names the list for assistive technology. */
  label: string;
  emptyText: string;
}

function CheckedAgo({ value }: { value: string | null }) {
  const now = useNow();
  const date = parseTimestamp(value);
  if (date === null) return <span>Never checked</span>;
  return (
    <time dateTime={date.toISOString()} title={formatUtc(date)}>
      {formatRelative(date, now)}
    </time>
  );
}

/** A short ranked list of indicators. Every row opens the stored record. */
export default function IndicatorList({ indicators, label, emptyText }: IndicatorListProps) {
  if (indicators.length === 0) {
    return <p className="py-6 text-center text-sm text-ink-300">{emptyText}</p>;
  }
  return (
    <ol aria-label={label} className="space-y-0.5">
      {indicators.map((indicator, index) => {
        const assessed = isIndicatorAssessed(indicator);
        const edge = assessed ? CLASSIFICATION_META[indicator.classification].swatch : "bg-ink-500";
        return (
          <li key={indicator.indicator_id}>
            <Link
              to={`/indicators/${encodeURIComponent(indicator.indicator_id)}`}
              className="group relative flex items-center gap-3 rounded-[3px] py-2 pl-4 pr-2 transition hover:bg-cipher/10 focus-visible:bg-cipher/10"
            >
              <span aria-hidden="true" className={`absolute inset-y-1.5 left-0 w-0.5 rounded-full ${edge}`} />
              <span aria-hidden="true" className="font-mono text-[0.68rem] text-ink-300">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-sm text-ink-50" title={indicator.indicator_value}>
                  {indicator.indicator_value}
                </span>
                <span className="block text-xs text-ink-300">
                  {INDICATOR_TYPE_LABELS[indicator.indicator_type]} · <CheckedAgo value={indicator.last_checked_at} />
                </span>
              </span>
              <span className="flex shrink-0 flex-col items-end gap-1">
                <ClassificationBadge classification={indicator.classification} assessed={assessed} />
                <span className="font-mono text-xs text-ink-200">
                  {assessed ? `Score ${indicator.risk_score}` : "No score"}
                </span>
              </span>
            </Link>
          </li>
        );
      })}
    </ol>
  );
}
