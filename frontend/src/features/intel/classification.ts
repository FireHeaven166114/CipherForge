import type { Classification, Indicator, Score } from "../../types/intel";

export interface ClassificationMeta {
  label: string;
  /** A distinct shape per level, so severity is never conveyed by colour alone. */
  symbol: string;
  /** Tailwind classes are written out in full so the build can find them. */
  badge: string;
  bar: string;
}

export const CLASSIFICATION_META: Record<Classification, ClassificationMeta> = {
  critical: {
    label: "Critical",
    symbol: "◆",
    badge: "border-red-600 bg-red-950 text-red-200",
    bar: "fill-red-500",
  },
  high: {
    label: "High",
    symbol: "▲",
    badge: "border-orange-600 bg-orange-950 text-orange-200",
    bar: "fill-orange-500",
  },
  medium: {
    label: "Medium",
    symbol: "■",
    badge: "border-amber-600 bg-amber-950 text-amber-200",
    bar: "fill-amber-500",
  },
  low: {
    label: "Low",
    symbol: "●",
    badge: "border-sky-700 bg-sky-950 text-sky-200",
    bar: "fill-sky-500",
  },
  informational: {
    label: "Informational",
    symbol: "○",
    badge: "border-slate-600 bg-slate-800 text-slate-200",
    bar: "fill-slate-400",
  },
};

/** Most severe first, which is how analysts scan a list. */
export const CLASSIFICATIONS_BY_SEVERITY: readonly Classification[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

/**
 * A score of 0 only means "clean" when at least one provider answered. With no answers,
 * "Informational" would read as a clean bill of health, so callers show "Not assessed".
 */
export function isScoreAssessed(score: Pick<Score, "answered_sources">): boolean {
  return score.answered_sources > 0;
}

/**
 * Lists carry no answer count, but confidence is built from the answers (every fresh or stale
 * answer adds to it), so a confidence of 0 is exactly the "no provider answered" case.
 */
export function isIndicatorAssessed(indicator: Pick<Indicator, "confidence">): boolean {
  return indicator.confidence > 0;
}
