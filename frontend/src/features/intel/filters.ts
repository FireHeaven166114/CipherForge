import {
  CLASSIFICATIONS,
  INDICATOR_TYPES,
  type Classification,
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
  classification: Classification | "";
  sort: IndicatorSort;
  /** 1-based. */
  page: number;
}

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
    classification: pick(CLASSIFICATIONS, params.get("classification")) ?? "",
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

export function toQuery(filters: IndicatorFilters): IndicatorQuery {
  return {
    type: filters.type || undefined,
    classification: filters.classification || undefined,
    q: filters.q || undefined,
    sort: filters.sort,
    limit: PAGE_SIZE,
    offset: (filters.page - 1) * PAGE_SIZE,
  };
}

export function hasActiveFilters(filters: IndicatorFilters): boolean {
  return Boolean(filters.q || filters.type || filters.classification);
}
