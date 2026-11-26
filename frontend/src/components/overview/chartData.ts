import { CLASSIFICATIONS_BY_SEVERITY, CLASSIFICATION_META } from "../../features/intel/classification";
import { indicatorsHref } from "../../features/intel/filters";
import { INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import { countryLabel } from "../../features/overview/countries";
import { INDICATOR_TYPES, type FacetEntry, type Overview } from "../../types/intel";
import type { AreaSeries } from "../charts/AreaChart";
import type { DonutSlice } from "../charts/Donut";
import type { MapMarker } from "../charts/DotMap";
import type { HBarItem } from "../charts/HBarList";
import type { RadarAxis } from "../charts/Radar";

/** The risk bands, most severe first, then "not assessed". Each opens the list of what it counts. */
export function riskSlices(overview: Overview): DonutSlice[] {
  const slices: DonutSlice[] = CLASSIFICATIONS_BY_SEVERITY.map((classification) => {
    const meta = CLASSIFICATION_META[classification];
    return {
      key: classification,
      label: meta.label,
      value: overview.by_classification[classification] ?? 0,
      stroke: meta.stroke,
      swatch: meta.swatch,
      symbol: meta.symbol,
      to: indicatorsHref({ classification, sort: "risk" }),
    };
  });
  slices.push({
    key: "not_assessed",
    label: "Not assessed",
    value: overview.by_classification["not_assessed"] ?? 0,
    stroke: "stroke-ink-400",
    swatch: "bg-ink-400",
    symbol: "?",
    to: indicatorsHref({ classification: "not_assessed" }),
  });
  return slices;
}

/** One axis per indicator type, each leading to the list of that type. */
export function typeAxes(overview: Overview): RadarAxis[] {
  return INDICATOR_TYPES.map((type) => ({
    key: type,
    label: INDICATOR_TYPE_LABELS[type],
    value: overview.by_type[type] ?? 0,
    to: indicatorsHref({ type }),
  }));
}

/** Lookups and high-risk lookups per IST day, for the trend chart. */
export function threatSeries(overview: Overview): { categories: string[]; series: AreaSeries[] } {
  return {
    categories: overview.series.map((point) => point.day),
    series: [
      {
        id: "lookups",
        label: "Lookups",
        values: overview.series.map((point) => point.lookups),
        line: "stroke-cipher",
        area: "fill-cipher/15",
        dot: "fill-cipher",
        swatch: "bg-cipher",
      },
      {
        id: "high-risk",
        label: "High-risk lookups",
        values: overview.series.map((point) => point.high_risk_lookups),
        line: "stroke-crit",
        area: "fill-crit/15",
        dot: "fill-crit",
        swatch: "bg-crit",
      },
    ],
  };
}

export function facetItems(
  entries: readonly FacetEntry[],
  labelOf: (key: string) => string = (key) => key,
): HBarItem[] {
  return entries.map((entry) => ({
    key: entry.key,
    label: labelOf(entry.key),
    count: entry.count,
    maxRisk: entry.max_risk,
  }));
}

export function mapMarkers(entries: readonly FacetEntry[]): MapMarker[] {
  return entries.map((entry) => ({
    code: entry.key,
    name: countryLabel(entry.key),
    count: entry.count,
    maxRisk: entry.max_risk,
  }));
}
