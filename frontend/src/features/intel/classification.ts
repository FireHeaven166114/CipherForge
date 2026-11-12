import type { Classification, Indicator, Score } from "../../types/intel";

export interface ClassificationMeta {
  label: string;
  /** A distinct shape per level, so severity is never conveyed by colour alone. */
  symbol: string;
  /** Tailwind classes are written out in full so the build can find them. */
  badge: string;
  /** SVG fill, for bars and cells. */
  bar: string;
  /** SVG stroke, for rings and lines. */
  stroke: string;
  /** Text colour, for numbers and labels. */
  text: string;
  /** A solid swatch, for legends. */
  swatch: string;
}

export const CLASSIFICATION_META: Record<Classification, ClassificationMeta> = {
  critical: {
    label: "Critical",
    symbol: "◆",
    badge: "border-crit/70 cf-plate text-crit",
    bar: "fill-crit",
    stroke: "stroke-crit",
    text: "text-crit",
    swatch: "bg-crit",
  },
  high: {
    label: "High",
    symbol: "▲",
    badge: "border-high/70 cf-plate text-high",
    bar: "fill-high",
    stroke: "stroke-high",
    text: "text-high",
    swatch: "bg-high",
  },
  medium: {
    label: "Medium",
    symbol: "■",
    badge: "border-med/70 cf-plate text-med",
    bar: "fill-med",
    stroke: "stroke-med",
    text: "text-med",
    swatch: "bg-med",
  },
  low: {
    label: "Low",
    symbol: "●",
    badge: "border-low/70 cf-plate text-low",
    bar: "fill-low",
    stroke: "stroke-low",
    text: "text-low",
    swatch: "bg-low",
  },
  informational: {
    label: "Informational",
    symbol: "○",
    badge: "border-info/60 cf-plate text-info",
    bar: "fill-info",
    stroke: "stroke-info",
    text: "text-info",
    swatch: "bg-info",
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
 * The band a risk score (0 to 100) falls in. These are the API's own bands (intel-risk-v1), used
 * to colour a bar by the highest score behind it when only the number is at hand.
 */
export function classificationForScore(score: number): Classification {
  if (score <= 20) return "informational";
  if (score <= 40) return "low";
  if (score <= 60) return "medium";
  if (score <= 80) return "high";
  return "critical";
}

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
