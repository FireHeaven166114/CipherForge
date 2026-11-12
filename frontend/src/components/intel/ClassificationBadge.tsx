import { CLASSIFICATION_META } from "../../features/intel/classification";
import type { Classification } from "../../types/intel";

interface ClassificationBadgeProps {
  classification: Classification;
  /**
   * False when no provider answered. A score of zero then says nothing about the indicator, so
   * showing "Informational" would read as a clean result; the badge says "Not assessed" instead.
   */
  assessed?: boolean;
}

/** Severity is shown as a shape and a word as well as a colour. */
export default function ClassificationBadge({
  classification,
  assessed = true,
}: ClassificationBadgeProps) {
  if (!assessed) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-chip border border-dashed border-ink-400 px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-ink-200">
        <span aria-hidden="true">?</span>
        Not assessed
      </span>
    );
  }
  const { label, symbol, badge } = CLASSIFICATION_META[classification];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-chip border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${badge}`}
    >
      <span aria-hidden="true">{symbol}</span>
      {label}
    </span>
  );
}
