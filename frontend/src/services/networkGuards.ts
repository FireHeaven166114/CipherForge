import {
  CAPTURE_STATES,
  ENRICHMENT_STATES,
  SESSION_STATUSES,
  SEVERITIES,
  SOURCE_KINDS,
  type AlertPage,
  type Backend,
  type CaptureSession,
  type DetectionRule,
  type Enrichment,
  type EnrichmentSummary,
  type ExternalIp,
  type Flow,
  type FlowPage,
  type InterfaceList,
  type NetworkAlert,
  type NetworkInterface,
  type NetworkStatus,
  type ProtocolStat,
  type SessionDetail,
  type SessionPage,
  type TalkerStat,
} from "../types/network";
import {
  isArrayOf,
  isCount,
  isCountRecord,
  isFiniteNumber,
  isNullableCount,
  isNullableString,
  isOneOf,
  isRecord,
  isString,
  isStringArray,
} from "./guardPrimitives";

const isCaptureState = isOneOf(CAPTURE_STATES);
const isSessionStatus = isOneOf(SESSION_STATUSES);
const isSourceKind = isOneOf(SOURCE_KINDS);
const isSeverity = isOneOf(SEVERITIES);
const isEnrichmentState = isOneOf(ENRICHMENT_STATES);

function isBackend(value: unknown): value is Backend {
  return isRecord(value) && isString(value.name) && typeof value.available === "boolean";
}

export function isNetworkStatus(value: unknown): value is NetworkStatus {
  return (
    isRecord(value) &&
    isCaptureState(value.state) &&
    isBackend(value.backend) &&
    isNullableString(value.interface) &&
    isNullableString(value.session_id) &&
    isNullableString(value.error_code) &&
    isNullableString(value.message) &&
    typeof value.busy === "boolean" &&
    isRecord(value.analysis) &&
    typeof value.analysis.running === "boolean" &&
    isNullableString(value.analysis.session_id) &&
    isCount(value.analysis.max_upload_mb) &&
    typeof value.enrichment_enabled === "boolean"
  );
}

function isNetworkInterface(value: unknown): value is NetworkInterface {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isString(value.name) &&
    isString(value.description) &&
    isStringArray(value.addresses)
  );
}

export function isInterfaceList(value: unknown): value is InterfaceList {
  return (
    isRecord(value) && isBackend(value.backend) && isArrayOf(isNetworkInterface)(value.interfaces)
  );
}

function isDetectionRule(value: unknown): value is DetectionRule {
  return (
    isRecord(value) &&
    isString(value.rule_id) &&
    isString(value.name) &&
    isString(value.title) &&
    isString(value.description) &&
    isString(value.unit) &&
    isFiniteNumber(value.threshold) &&
    isNullableCount(value.window_seconds) &&
    isNullableString(value.detail) &&
    typeof value.active === "boolean" &&
    isArrayOf(isSeverity)(value.severities)
  );
}

export const isRuleList = isArrayOf(isDetectionRule);

function isEnrichmentProvider(value: unknown): value is Enrichment["providers"][number] {
  return (
    isRecord(value) &&
    isString(value.provider) &&
    isString(value.display_name) &&
    isString(value.status) &&
    isNullableString(value.verdict)
  );
}

export function isEnrichment(value: unknown): value is Enrichment {
  return (
    isRecord(value) &&
    isEnrichmentState(value.status) &&
    isNullableString(value.address) &&
    isNullableCount(value.risk_score) &&
    isNullableString(value.classification) &&
    (value.assessed === null || typeof value.assessed === "boolean") &&
    isNullableString(value.indicator_id) &&
    isNullableString(value.completed_at) &&
    isNullableString(value.error_code) &&
    isNullableString(value.message) &&
    isArrayOf(isEnrichmentProvider)(value.providers)
  );
}

function isProtocolStat(value: unknown): value is ProtocolStat {
  return (
    isRecord(value) && isString(value.protocol) && isCount(value.packets) && isCount(value.bytes)
  );
}

function isTalkerStat(value: unknown): value is TalkerStat {
  return (
    isRecord(value) && isString(value.address) && isCount(value.packets) && isCount(value.bytes)
  );
}

function isExternalIp(value: unknown): value is ExternalIp {
  return (
    isRecord(value) &&
    isString(value.address) &&
    isNullableString(value.first_seen) &&
    isNullableString(value.last_seen) &&
    isNullableCount(value.packets) &&
    isNullableCount(value.bytes) &&
    typeof value.sent_to === "boolean" &&
    typeof value.alerted === "boolean" &&
    isStringArray(value.peers) &&
    isArrayOf(isCount)(value.ports) &&
    isStringArray(value.protocols) &&
    isEnrichment(value.enrichment)
  );
}

function isEnrichmentSummary(value: unknown): value is EnrichmentSummary {
  return (
    isRecord(value) &&
    typeof value.enabled === "boolean" &&
    isCount(value.total) &&
    isCount(value.completed) &&
    isCount(value.pending) &&
    isCount(value.failed) &&
    isCount(value.unavailable) &&
    isCount(value.skipped)
  );
}

export function isCaptureSession(value: unknown): value is CaptureSession {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isSourceKind(value.source_kind) &&
    isSessionStatus(value.status) &&
    isNullableString(value.interface) &&
    isNullableString(value.source_label) &&
    isString(value.started_at) &&
    isNullableString(value.ended_at) &&
    isFiniteNumber(value.duration_seconds) &&
    isCount(value.packets_total) &&
    isCount(value.bytes_total) &&
    isCount(value.flows_total) &&
    isCount(value.active_flows) &&
    isCount(value.alerts_total) &&
    isCount(value.packets_dropped) &&
    isNullableString(value.error_code) &&
    isNullableString(value.message)
  );
}

export function isSessionDetail(value: unknown): value is SessionDetail {
  return (
    isCaptureSession(value) &&
    isRecord(value) &&
    isNullableString(value.first_packet_at) &&
    isNullableString(value.last_packet_at) &&
    isArrayOf(isProtocolStat)(value.protocols) &&
    isArrayOf(isTalkerStat)(value.top_sources) &&
    isArrayOf(isTalkerStat)(value.top_destinations) &&
    isCount(value.non_ip_packets) &&
    isCount(value.malformed_packets) &&
    isCount(value.flows_evicted) &&
    isCount(value.flows_stored) &&
    isCount(value.flows_not_stored) &&
    isCountRecord(value.alerts_by_rule) &&
    isCount(value.alerts_suppressed) &&
    isCount(value.alerts_lost) &&
    typeof value.talkers_truncated === "boolean" &&
    isArrayOf(isExternalIp)(value.external_ips) &&
    isEnrichmentSummary(value.enrichment)
  );
}

function pageGuard<T>(
  isItem: (value: unknown) => value is T,
): (value: unknown) => value is { items: T[]; total: number; limit: number; offset: number } {
  return (value): value is { items: T[]; total: number; limit: number; offset: number } =>
    isRecord(value) &&
    isArrayOf(isItem)(value.items) &&
    isCount(value.total) &&
    isCount(value.limit) &&
    isCount(value.offset);
}

export const isSessionPage: (value: unknown) => value is SessionPage = pageGuard(isCaptureSession);

function isFlow(value: unknown): value is Flow {
  return (
    isRecord(value) &&
    isCount(value.id) &&
    isString(value.protocol) &&
    isString(value.src_ip) &&
    isNullableCount(value.src_port) &&
    isString(value.dst_ip) &&
    isNullableCount(value.dst_port) &&
    isString(value.first_seen) &&
    isString(value.last_seen) &&
    isFiniteNumber(value.duration_seconds) &&
    isCount(value.packets_out) &&
    isCount(value.packets_in) &&
    isCount(value.bytes_out) &&
    isCount(value.bytes_in) &&
    isNullableCount(value.tcp_flags) &&
    isStringArray(value.tcp_flag_names) &&
    isString(value.close_reason)
  );
}

export const isFlowPage: (value: unknown) => value is FlowPage = pageGuard(isFlow);

export function isNetworkAlert(value: unknown): value is NetworkAlert {
  return (
    isRecord(value) &&
    isString(value.id) &&
    isString(value.session_id) &&
    isString(value.rule_id) &&
    isString(value.rule_name) &&
    isString(value.title) &&
    isSeverity(value.severity) &&
    isString(value.explanation) &&
    isFiniteNumber(value.observed_value) &&
    isFiniteNumber(value.threshold) &&
    isString(value.unit) &&
    isNullableCount(value.window_seconds) &&
    isNullableString(value.src_ip) &&
    isNullableString(value.dst_ip) &&
    isNullableCount(value.dst_port) &&
    isNullableString(value.protocol) &&
    isString(value.first_observed) &&
    isString(value.last_observed) &&
    isString(value.created_at) &&
    isRecord(value.evidence) &&
    isEnrichment(value.enrichment)
  );
}

export const isAlertPage: (value: unknown) => value is AlertPage = pageGuard(isNetworkAlert);
