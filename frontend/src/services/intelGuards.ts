import {
  CLASSIFICATIONS,
  INDICATOR_TYPES,
  PROVIDER_REASONS,
  PROVIDER_STATUSES,
  PROVIDER_VERDICTS,
  type ActivityRow,
  type DayPoint,
  type DeleteResult,
  type FacetEntry,
  type Indicator,
  type IndicatorPage,
  type Investigation,
  type MatrixRow,
  type Overview,
  type OverviewKpis,
  type OverviewScope,
  type ProviderInfo,
  type ProviderView,
  type SampleIndicator,
  type Score,
  type ScoreFactor,
  type Stats,
} from "../types/intel";
import {
  isArrayOf,
  isCount,
  isCountRecord,
  isFiniteNumber,
  isNullableString,
  isOneOf,
  isRecord,
  isString,
  isStringArray,
} from "./guardPrimitives";

// Runtime checks for API responses; the building blocks are shared with the other *Guards files.

const isClassification = isOneOf(CLASSIFICATIONS);
const isIndicatorType = isOneOf(INDICATOR_TYPES);
const isProviderStatus = isOneOf(PROVIDER_STATUSES);
const isProviderVerdict = isOneOf(PROVIDER_VERDICTS);
const isProviderReason = isOneOf(PROVIDER_REASONS);
const isIndicatorStatus = isOneOf(["active", "stale"] as const);
const isFreshness = isOneOf(["fresh", "stale"] as const);

export function isIndicator(value: unknown): value is Indicator {
  return (
    isRecord(value) &&
    isString(value.indicator_id) &&
    isIndicatorType(value.indicator_type) &&
    isString(value.indicator_value) &&
    isCount(value.risk_score) &&
    isClassification(value.classification) &&
    isCount(value.confidence) &&
    isNullableString(value.first_seen) &&
    isNullableString(value.last_seen) &&
    isCount(value.source_count) &&
    isStringArray(value.tags) &&
    isIndicatorStatus(value.status) &&
    isString(value.created_at) &&
    isNullableString(value.scored_at) &&
    isNullableString(value.last_checked_at)
  );
}

function isProviderView(value: unknown): value is ProviderView {
  return (
    isRecord(value) &&
    isString(value.provider) &&
    isString(value.display_name) &&
    isProviderStatus(value.status) &&
    (value.freshness === null || isFreshness(value.freshness)) &&
    (value.signal === null || isFiniteNumber(value.signal)) &&
    isNullableString(value.fetched_at) &&
    isNullableString(value.evidence_at) &&
    isNullableString(value.first_evidence_at) &&
    isNullableString(value.cache_expires_at) &&
    typeof value.from_cache === "boolean" &&
    isRecord(value.summary) &&
    isStringArray(value.tags) &&
    isNullableString(value.message) &&
    (value.verdict === null || isProviderVerdict(value.verdict)) &&
    (value.reason === null || isProviderReason(value.reason))
  );
}

function isScoreFactor(value: unknown): value is ScoreFactor {
  return (
    isRecord(value) &&
    isString(value.code) &&
    isString(value.label) &&
    isFiniteNumber(value.points) &&
    isString(value.detail)
  );
}

function isScore(value: unknown): value is Score {
  return (
    isRecord(value) &&
    isString(value.methodology) &&
    isCount(value.score) &&
    isClassification(value.classification) &&
    isCount(value.confidence) &&
    isCount(value.answered_sources) &&
    isCount(value.contributing_sources) &&
    isCount(value.supporting_sources) &&
    isArrayOf(isScoreFactor)(value.factors) &&
    isStringArray(value.uncertainty) &&
    isStringArray(value.recommended_actions) &&
    isNullableString(value.scored_at)
  );
}

export function isInvestigation(value: unknown): value is Investigation {
  return (
    isRecord(value) &&
    isIndicator(value.indicator) &&
    isArrayOf(isProviderView)(value.providers) &&
    isScore(value.score) &&
    isRecord(value.internal_evidence) &&
    typeof value.internal_evidence.available === "boolean" &&
    isString(value.internal_evidence.message)
  );
}

export function isIndicatorPage(value: unknown): value is IndicatorPage {
  return (
    isRecord(value) &&
    isArrayOf(isIndicator)(value.items) &&
    isCount(value.total) &&
    isCount(value.limit) &&
    isCount(value.offset)
  );
}

export function isDeleteResult(value: unknown): value is DeleteResult {
  return (
    isRecord(value) &&
    isStringArray(value.deleted) &&
    isStringArray(value.not_found) &&
    isCount(value.observations_removed)
  );
}

function isProviderInfo(value: unknown): value is ProviderInfo {
  return (
    isRecord(value) &&
    isString(value.name) &&
    isString(value.display_name) &&
    typeof value.configured === "boolean" &&
    isArrayOf(isIndicatorType)(value.supported_types) &&
    typeof value.simulated === "boolean"
  );
}

export function isStats(value: unknown): value is Stats {
  return (
    isRecord(value) &&
    isCount(value.total_indicators) &&
    isCountRecord(value.by_classification) &&
    isCountRecord(value.by_type) &&
    isCount(value.lookups_last_24h) &&
    isArrayOf(isProviderInfo)(value.providers)
  );
}

function isSampleIndicator(value: unknown): value is SampleIndicator {
  return (
    isRecord(value) &&
    isString(value.indicator_id) &&
    isIndicatorType(value.indicator_type) &&
    isString(value.indicator_value) &&
    isCount(value.risk_score) &&
    isClassification(value.classification)
  );
}

function isFacetEntry(value: unknown): value is FacetEntry {
  return (
    isRecord(value) &&
    isString(value.key) &&
    isCount(value.count) &&
    isCount(value.max_risk) &&
    isArrayOf(isSampleIndicator)(value.samples)
  );
}

function isOverviewKpis(value: unknown): value is OverviewKpis {
  return (
    isRecord(value) &&
    isCount(value.total_indicators) &&
    isCount(value.new_indicators_24h) &&
    isCount(value.new_indicators_prev_24h) &&
    isCount(value.lookups_24h) &&
    isCount(value.lookups_prev_24h) &&
    isCount(value.high_risk_indicators) &&
    isCount(value.critical_indicators) &&
    isCount(value.not_assessed_indicators)
  );
}

function isDay(value: unknown): value is string {
  return isString(value) && /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function isDayPoint(value: unknown): value is DayPoint {
  return (
    isRecord(value) &&
    isDay(value.day) &&
    isCount(value.lookups) &&
    isCount(value.high_risk_lookups) &&
    isCount(value.new_indicators)
  );
}

function isActivityRow(value: unknown): value is ActivityRow {
  return (
    isRecord(value) &&
    isDay(value.day) &&
    Array.isArray(value.hours) &&
    value.hours.length === 24 &&
    value.hours.every(isCount)
  );
}

function isMatrixRow(value: unknown): value is MatrixRow {
  return isRecord(value) && isIndicatorType(value.indicator_type) && isCountRecord(value.counts);
}

function isOverviewScope(value: unknown): value is OverviewScope {
  return (
    isRecord(value) &&
    isCount(value.series_days) &&
    isCount(value.activity_days) &&
    isCount(value.lookups_scanned) &&
    typeof value.lookups_truncated === "boolean" &&
    isCount(value.answers_scanned) &&
    typeof value.answers_truncated === "boolean"
  );
}

export function isOverview(value: unknown): value is Overview {
  return (
    isRecord(value) &&
    isString(value.generated_at) &&
    isOverviewKpis(value.kpis) &&
    isCountRecord(value.by_classification) &&
    isCountRecord(value.by_type) &&
    isArrayOf(isMatrixRow)(value.matrix) &&
    isArrayOf(isDayPoint)(value.series) &&
    isArrayOf(isActivityRow)(value.activity) &&
    isArrayOf(isFacetEntry)(value.countries) &&
    isArrayOf(isFacetEntry)(value.malware_families) &&
    isArrayOf(isFacetEntry)(value.attack_techniques) &&
    isArrayOf(isFacetEntry)(value.tags) &&
    isArrayOf(isIndicator)(value.top_risk) &&
    isArrayOf(isIndicator)(value.recent) &&
    isArrayOf(isProviderInfo)(value.providers) &&
    isOverviewScope(value.scope)
  );
}
