import {
  CLASSIFICATIONS,
  INDICATOR_TYPES,
  type IndicatorQuery,
  type IndicatorSort,
  type IndicatorType,
} from "../../types/intel";

export const PAGE_SIZE = 25;
/** The API refuses offsets above this. */
const MAX_OFFSET = 10_000;
export const MAX_PAGE = Math.floor(MAX_OFFSET / PAGE_SIZE) + 1;
/** The API refuses longer searches. */
export const MAX_SEARCH_LENGTH = 256;

export interface IndicatorFilters {
  q: string;
  type: IndicatorType | "";
  classification: RiskFilter | "";
  sort: IndicatorSort;
  /** 1-based. */
  page: number;
}

/**
 * What the classification filter can hold: one band, High and Critical together, or "not
 * assessed". These are the groups the overview counts, so each of its numbers opens exactly the
 * indicators it counts.
 */
export const RISK_FILTERS = [...CLASSIFICATIONS, "high_risk", "not_assessed"] as const;
export type RiskFilter = (typeof RISK_FILTERS)[number];

export const DEFAULT_FILTERS: IndicatorFilters = {
  q: "",
  type: "",
  classification: "",
  sort: "recent",
  page: 1,
};

function pick<T extends string>(allowed: readonly T[], value: string | null): T | null {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : null;
}

/** Reads filters from the address bar. Anything unknown or out of range falls back to the default. */
export function readFilters(params: URLSearchParams): IndicatorFilters {
  const page = Number(params.get("page"));
  return {
    q: (params.get("q") ?? "").trim().slice(0, MAX_SEARCH_LENGTH),
    type: pick(INDICATOR_TYPES, params.get("type")) ?? "",
    classification: pick(RISK_FILTERS, params.get("classification")) ?? "",
    sort: pick(["recent", "risk"] as const, params.get("sort")) ?? DEFAULT_FILTERS.sort,
    page: Number.isInteger(page) && page >= 1 ? Math.min(page, MAX_PAGE) : 1,
  };
}

/** Writes only what differs from the defaults, so the address bar stays short and clean. */
export function writeFilters(filters: IndicatorFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.type) params.set("type", filters.type);
  if (filters.classification) params.set("classification", filters.classification);
  if (filters.sort !== DEFAULT_FILTERS.sort) params.set("sort", filters.sort);
  if (filters.page > 1) params.set("page", String(filters.page));
  return params;
}

/** A link to the indicators list with the given filters applied, for drilling down from a chart. */
export function indicatorsHref(filters: Partial<IndicatorFilters> = {}): string {
  const query = writeFilters({ ...DEFAULT_FILTERS, ...filters }).toString();
  return query === "" ? "/indicators" : `/indicators?${query}`;
}

/**
 * The API's view of a risk filter. A band means assessed indicators in that band: an indicator no
 * provider answered for also scores 0, but it is "not assessed", never "informational".
 */
function riskQuery(filter: RiskFilter | ""): Pick<IndicatorQuery, "classification" | "assessed"> {
  switch (filter) {
    case "":
      return {};
    case "not_assessed":
      return { assessed: false };
    case "high_risk":
      return { classification: ["high", "critical"], assessed: true };
    default:
      return { classification: [filter], assessed: true };
  }
}

export function toQuery(filters: IndicatorFilters): IndicatorQuery {
  return {
    type: filters.type || undefined,
    ...riskQuery(filters.classification),
    q: filters.q || undefined,
    sort: filters.sort,
    limit: PAGE_SIZE,
    offset: (filters.page - 1) * PAGE_SIZE,
  };
}

export function hasActiveFilters(filters: IndicatorFilters): boolean {
  return Boolean(filters.q || filters.type || filters.classification);
}
