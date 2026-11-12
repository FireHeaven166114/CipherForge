/** Shapes returned by the threat-intelligence API. Keep in sync with backend/app/schemas/intel.py. */

/** Wire values are lowercase; see features/intel/classification.ts for the display labels. */
export const CLASSIFICATIONS = ["informational", "low", "medium", "high", "critical"] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];

export const INDICATOR_TYPES = ["ipv4", "ipv6", "domain", "url", "sha256"] as const;
export type IndicatorType = (typeof INDICATOR_TYPES)[number];

export const PROVIDER_STATUSES = [
  "ok",
  "no_data",
  "not_configured",
  "unsupported",
  "rate_limited",
  "error",
  "not_queried",
] as const;
export type ProviderStatus = (typeof PROVIDER_STATUSES)[number];

/** "active": at least one provider answered freshly. "stale": no fresh provider evidence. */
export type IndicatorStatus = "active" | "stale";
export type Freshness = "fresh" | "stale";
export type IndicatorSort = "recent" | "risk";

export interface Indicator {
  indicator_id: string;
  indicator_type: IndicatorType;
  indicator_value: string;
  risk_score: number;
  classification: Classification;
  confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  source_count: number;
  tags: string[];
  status: IndicatorStatus;
  created_at: string;
  scored_at: string | null;
  last_checked_at: string | null;
}

/** One provider's independent answer. `summary`, `tags` and `message` are community-supplied text. */
export interface ProviderView {
  provider: string;
  display_name: string;
  status: ProviderStatus;
  freshness: Freshness | null;
  /** Strength of this provider's evidence (0 to 1). Not a probability of malice. */
  signal: number | null;
  fetched_at: string | null;
  evidence_at: string | null;
  first_evidence_at: string | null;
  cache_expires_at: string | null;
  from_cache: boolean;
  summary: Record<string, unknown>;
  tags: string[];
  message: string | null;
}

export interface ScoreFactor {
  code: string;
  label: string;
  points: number;
  detail: string;
}

export interface Score {
  methodology: string;
  score: number;
  classification: Classification;
  confidence: number;
  /** 0 means no provider answered: the score is then "not assessed", not "clean". */
  answered_sources: number;
  contributing_sources: number;
  supporting_sources: number;
  factors: ScoreFactor[];
  uncertainty: string[];
  recommended_actions: string[];
  scored_at: string | null;
}

export interface InternalEvidence {
  available: boolean;
  message: string;
}

export interface Investigation {
  indicator: Indicator;
  providers: ProviderView[];
  score: Score;
  internal_evidence: InternalEvidence;
}

export interface IndicatorPage {
  items: Indicator[];
  total: number;
  limit: number;
  offset: number;
}

export interface ProviderInfo {
  name: string;
  display_name: string;
  /** Whether the server has an API key for this provider. The key itself is never returned. */
  configured: boolean;
  supported_types: IndicatorType[];
  /** True only for the development demo server, whose providers return made-up answers. */
  simulated: boolean;
}

export interface Stats {
  total_indicators: number;
  by_classification: Record<string, number>;
  by_type: Record<string, number>;
  lookups_last_24h: number;
  providers: ProviderInfo[];
}

/** The five risk bands plus "not assessed" (no provider answered, so there is no verdict). */
export const RISK_BANDS = [...CLASSIFICATIONS, "not_assessed"] as const;
export type RiskBand = (typeof RISK_BANDS)[number];

/** A short reference to an indicator, used to list examples behind a count. */
export interface SampleIndicator {
  indicator_id: string;
  indicator_type: IndicatorType;
  indicator_value: string;
  risk_score: number;
  classification: Classification;
}

/** One value of a grouped field (a country, a malware family, ...) with how often it occurs. */
export interface FacetEntry {
  key: string;
  count: number;
  max_risk: number;
  /** The highest-risk indicators carrying this value. */
  samples: SampleIndicator[];
}

export interface OverviewKpis {
  total_indicators: number;
  new_indicators_24h: number;
  new_indicators_prev_24h: number;
  lookups_24h: number;
  lookups_prev_24h: number;
  /** High plus critical indicators. */
  high_risk_indicators: number;
  critical_indicators: number;
  not_assessed_indicators: number;
}

export interface DayPoint {
  /** A UTC calendar day, `YYYY-MM-DD`. */
  day: string;
  lookups: number;
  high_risk_lookups: number;
  new_indicators: number;
}

export interface ActivityRow {
  day: string;
  /** Lookup counts for the 24 UTC hours of the day. */
  hours: number[];
}

export interface MatrixRow {
  indicator_type: IndicatorType;
  counts: Record<string, number>;
}

/** How much data the aggregates were built from, so truncation is never silent. */
export interface OverviewScope {
  series_days: number;
  activity_days: number;
  lookups_scanned: number;
  lookups_truncated: boolean;
  answers_scanned: number;
  answers_truncated: boolean;
}

export interface Overview {
  generated_at: string;
  kpis: OverviewKpis;
  by_classification: Record<string, number>;
  by_type: Record<string, number>;
  matrix: MatrixRow[];
  series: DayPoint[];
  activity: ActivityRow[];
  countries: FacetEntry[];
  malware_families: FacetEntry[];
  attack_techniques: FacetEntry[];
  tags: FacetEntry[];
  top_risk: Indicator[];
  recent: Indicator[];
  providers: ProviderInfo[];
  scope: OverviewScope;
}

export interface IndicatorQuery {
  type?: IndicatorType;
  /** Score bands. Several match any of them. */
  classification?: readonly Classification[];
  /** true: a provider answered for it. false: none did, so its score says nothing. */
  assessed?: boolean;
  q?: string;
  sort?: IndicatorSort;
  limit?: number;
  offset?: number;
}
