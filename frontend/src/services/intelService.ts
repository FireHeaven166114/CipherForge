import type { IndicatorPage, IndicatorQuery, Investigation, Stats } from "../types/intel";
import { request } from "./apiClient";
import { isIndicatorPage, isInvestigation, isStats } from "./intelGuards";

const BASE = "/api/v1/intel";

// Providers are queried in parallel and each may take up to the server's provider timeout.
// This matches the proxy's read timeout, so the browser never gives up before nginx does.
const INVESTIGATE_TIMEOUT_MS = 30_000;

export interface InvestigateInput {
  indicator: string;
  /** Ask the providers again even if a stored answer is still fresh (the server rate-limits it). */
  refresh?: boolean;
}

export function investigateIndicator(
  input: InvestigateInput,
  signal?: AbortSignal,
): Promise<Investigation> {
  return request(`${BASE}/investigate`, {
    method: "POST",
    body: { indicator: input.indicator, refresh: input.refresh ?? false },
    signal,
    timeoutMs: INVESTIGATE_TIMEOUT_MS,
    guard: isInvestigation,
  });
}

/** The stored view of an indicator. Read-only: this never calls a provider. */
export function getIndicator(indicatorId: string, signal?: AbortSignal): Promise<Investigation> {
  return request(`${BASE}/indicators/${encodeURIComponent(indicatorId)}`, {
    signal,
    guard: isInvestigation,
  });
}

export function listIndicators(
  query: IndicatorQuery = {},
  signal?: AbortSignal,
): Promise<IndicatorPage> {
  const params = new URLSearchParams();
  if (query.type) params.set("type", query.type);
  if (query.classification) params.set("classification", query.classification);
  if (query.q) params.set("q", query.q);
  if (query.sort) params.set("sort", query.sort);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset !== undefined) params.set("offset", String(query.offset));
  const search = params.toString();
  return request(`${BASE}/indicators${search ? `?${search}` : ""}`, {
    signal,
    guard: isIndicatorPage,
  });
}

export function getStats(signal?: AbortSignal): Promise<Stats> {
  return request(`${BASE}/stats`, { signal, guard: isStats });
}
