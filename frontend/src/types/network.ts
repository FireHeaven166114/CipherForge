/** Shapes returned by the network-monitoring API. Keep in sync with backend/app/schemas/network.py. */

export const CAPTURE_STATES = [
  "not_configured",
  "ready",
  "starting",
  "running",
  "stopping",
  "stopped",
  "failed",
  "permission_denied",
] as const;
export type CaptureState = (typeof CAPTURE_STATES)[number];

export const SESSION_STATUSES = [
  "starting",
  "running",
  "stopping",
  "stopped",
  "completed",
  "failed",
  "permission_denied",
] as const;
export type SessionStatus = (typeof SESSION_STATUSES)[number];

export const SOURCE_KINDS = ["live", "pcap"] as const;
export type SourceKind = (typeof SOURCE_KINDS)[number];

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const ENRICHMENT_STATES = [
  "pending",
  "completed",
  "failed",
  "unavailable",
  "disabled",
  "skipped_budget",
  "not_applicable",
  "not_looked_up",
] as const;
export type EnrichmentState = (typeof ENRICHMENT_STATES)[number];

export interface Backend {
  /** "npcap", "winpcap", "libpcap", "native" or "none". */
  name: string;
  available: boolean;
}

export interface AnalysisStatus {
  running: boolean;
  /** Set only for the caller's own analysis. */
  session_id: string | null;
  max_upload_mb: number;
}

export interface NetworkStatus {
  state: CaptureState;
  backend: Backend;
  interface: string | null;
  session_id: string | null;
  error_code: string | null;
  message: string | null;
  /** Someone else's live capture holds the single capture slot. */
  busy: boolean;
  analysis: AnalysisStatus;
  enrichment_enabled: boolean;
}

export interface NetworkInterface {
  id: string;
  name: string;
  description: string;
  addresses: string[];
}

export interface InterfaceList {
  backend: Backend;
  interfaces: NetworkInterface[];
}

export interface DetectionRule {
  rule_id: string;
  name: string;
  title: string;
  description: string;
  /** What `threshold` counts: ports, connections, SYN packets, MB, risk score. */
  unit: string;
  threshold: number;
  window_seconds: number | null;
  detail: string | null;
  /** False when the rule cannot fire in the current configuration. */
  active: boolean;
  /** The severity at 1x, 3x and 10x the threshold. */
  severities: Severity[];
}

export interface EnrichmentProvider {
  provider: string;
  display_name: string;
  status: string;
  verdict: string | null;
}

export interface Enrichment {
  status: EnrichmentState;
  address: string | null;
  /** Present only when at least one provider answered. "No data" never means "safe". */
  risk_score: number | null;
  classification: string | null;
  assessed: boolean | null;
  indicator_id: string | null;
  completed_at: string | null;
  error_code: string | null;
  message: string | null;
  providers: EnrichmentProvider[];
}

export interface ProtocolStat {
  protocol: string;
  packets: number;
  bytes: number;
}

export interface TalkerStat {
  address: string;
  packets: number;
  bytes: number;
}

export interface ExternalIp {
  address: string;
  first_seen: string | null;
  last_seen: string | null;
  packets: number | null;
  bytes: number | null;
  /** Whether anything on the monitored side sent traffic to it. */
  sent_to: boolean;
  alerted: boolean;
  peers: string[];
  ports: number[];
  protocols: string[];
  enrichment: Enrichment;
}

export interface EnrichmentSummary {
  enabled: boolean;
  total: number;
  completed: number;
  pending: number;
  failed: number;
  unavailable: number;
  skipped: number;
}

export interface CaptureSession {
  id: string;
  source_kind: SourceKind;
  status: SessionStatus;
  interface: string | null;
  /** For a capture file: the name it was uploaded under. Display only. */
  source_label: string | null;
  started_at: string;
  ended_at: string | null;
  duration_seconds: number;
  packets_total: number;
  bytes_total: number;
  flows_total: number;
  active_flows: number;
  alerts_total: number;
  packets_dropped: number;
  error_code: string | null;
  message: string | null;
}

export interface SessionDetail extends CaptureSession {
  first_packet_at: string | null;
  last_packet_at: string | null;
  protocols: ProtocolStat[];
  top_sources: TalkerStat[];
  top_destinations: TalkerStat[];
  non_ip_packets: number;
  malformed_packets: number;
  flows_evicted: number;
  flows_stored: number;
  /** Finished flows beyond the per-session storage limit. They are counted, not stored. */
  flows_not_stored: number;
  alerts_by_rule: Record<string, number>;
  alerts_suppressed: number;
  alerts_lost: number;
  talkers_truncated: boolean;
  external_ips: ExternalIp[];
  enrichment: EnrichmentSummary;
}

export interface Flow {
  id: number;
  protocol: string;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  first_seen: string;
  last_seen: string;
  duration_seconds: number;
  packets_out: number;
  packets_in: number;
  bytes_out: number;
  bytes_in: number;
  tcp_flags: number | null;
  tcp_flag_names: string[];
  close_reason: string;
}

export interface NetworkAlert {
  id: string;
  session_id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  severity: Severity;
  explanation: string;
  observed_value: number;
  threshold: number;
  unit: string;
  window_seconds: number | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  first_observed: string;
  last_observed: string;
  created_at: string;
  evidence: Record<string, unknown>;
  enrichment: Enrichment;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export type SessionPage = Page<CaptureSession>;
export type FlowPage = Page<Flow>;
export type AlertPage = Page<NetworkAlert>;

export interface PageQuery {
  limit?: number;
  offset?: number;
}

export interface AlertQuery extends PageQuery {
  severity?: readonly Severity[];
  rule?: string;
}
