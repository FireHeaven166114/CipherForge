import type {
  AlertPage,
  Backend,
  CaptureSession,
  DetectionRule,
  Enrichment,
  ExternalIp,
  Flow,
  FlowPage,
  InterfaceList,
  NetworkAlert,
  NetworkInterface,
  NetworkStatus,
  SessionDetail,
  SessionPage,
} from "../types/network";

// Test data only. Addresses come from the ranges reserved for documentation (RFC 5737), and every
// timestamp is UTC, as the API sends them (the pages show them in IST).

export const SESSION_ID = "7c1e5b2a-4f3d-4e8a-9b6c-2d1f0a9e8b7c";
export const OTHER_SESSION_ID = "0d4c3b2a-9e8f-4a7b-8c6d-5e4f3a2b1c0d";
export const ALERT_ID = "3b9d6f0e-1a2c-4d5e-8f70-6a5b4c3d2e1f";
export const SCANNER_IP = "203.0.113.45";
export const HOST_IP = "192.0.2.10";

export const STARTED_AT = "2026-05-20T08:30:00Z";
export const ENDED_AT = "2026-05-20T08:31:30Z";

export function makeBackend(overrides: Partial<Backend> = {}): Backend {
  return { name: "npcap", available: true, ...overrides };
}

export function makeNetworkStatus(overrides: Partial<NetworkStatus> = {}): NetworkStatus {
  return {
    state: "ready",
    backend: makeBackend(),
    interface: null,
    session_id: null,
    error_code: null,
    message: null,
    busy: false,
    analysis: { running: false, session_id: null, max_upload_mb: 50 },
    enrichment_enabled: true,
    ...overrides,
  };
}

export function makeInterface(overrides: Partial<NetworkInterface> = {}): NetworkInterface {
  return {
    id: "eth0",
    name: "eth0",
    description: "Ethernet adapter",
    addresses: [HOST_IP],
    ...overrides,
  };
}

export function makeInterfaces(
  interfaces: NetworkInterface[] = [
    makeInterface(),
    makeInterface({ id: "lo", name: "lo", description: "Loopback", addresses: ["127.0.0.1"] }),
  ],
  backend: Backend = makeBackend(),
): InterfaceList {
  return { backend, interfaces };
}

export function makeRules(): DetectionRule[] {
  const rule = (overrides: Partial<DetectionRule> & Pick<DetectionRule, "rule_id" | "name">): DetectionRule => ({
    title: overrides.name,
    description: `Description of ${overrides.name}.`,
    unit: "events",
    threshold: 10,
    window_seconds: 60,
    detail: null,
    active: true,
    severities: ["medium", "high", "critical"],
    ...overrides,
  });
  return [
    rule({ rule_id: "NET-001", name: "port_scan", title: "Port scan", unit: "ports", threshold: 20 }),
    rule({
      rule_id: "NET-002",
      name: "connection_rate",
      title: "High connection rate",
      unit: "connections",
      threshold: 100,
      severities: ["low", "medium", "high"],
    }),
    rule({
      rule_id: "NET-003",
      name: "syn_rate",
      title: "Abnormal SYN rate",
      unit: "SYN packets",
      threshold: 200,
      window_seconds: 10,
    }),
    rule({
      rule_id: "NET-004",
      name: "high_volume",
      title: "High traffic volume",
      unit: "MB",
      threshold: 50,
      severities: ["low", "medium", "high"],
    }),
    rule({
      rule_id: "NET-005",
      name: "known_malicious_ip",
      title: "Communication with a known malicious address",
      unit: "risk score",
      threshold: 61,
      window_seconds: null,
      detail: "Needs external enrichment: only addresses that were looked up can raise it.",
      severities: ["high", "high", "critical"],
    }),
    rule({
      rule_id: "NET-006",
      name: "suspicious_port",
      title: "Repeated connections to suspicious ports",
      unit: "attempts",
      threshold: 25,
      detail: "Ports: 23, 135, 139, 445, 1433, 3389, 4444, 5900, 6667, 31337",
      severities: ["medium", "high", "high"],
    }),
    rule({
      rule_id: "NET-007",
      name: "unexpected_protocol",
      title: "Unexpected protocol",
      unit: "packets",
      threshold: 1,
      window_seconds: null,
      detail: "Expected: icmp, icmpv6, igmp, tcp, udp",
      severities: ["low", "low", "low"],
    }),
  ];
}

export function makeEnrichment(overrides: Partial<Enrichment> = {}): Enrichment {
  return {
    status: "not_looked_up",
    address: null,
    risk_score: null,
    classification: null,
    assessed: null,
    indicator_id: null,
    completed_at: null,
    error_code: null,
    message: null,
    providers: [],
    ...overrides,
  };
}

export function makeCompletedEnrichment(overrides: Partial<Enrichment> = {}): Enrichment {
  return makeEnrichment({
    status: "completed",
    address: SCANNER_IP,
    risk_score: 72,
    classification: "high",
    assessed: true,
    indicator_id: "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9",
    completed_at: "2026-05-20T08:32:00Z",
    providers: [
      { provider: "abuseipdb", display_name: "AbuseIPDB", status: "ok", verdict: "malicious" },
      { provider: "otx", display_name: "AlienVault OTX", status: "no_data", verdict: null },
    ],
    ...overrides,
  });
}

export function makeExternalIp(overrides: Partial<ExternalIp> = {}): ExternalIp {
  return {
    address: SCANNER_IP,
    first_seen: "2026-05-20T08:30:05Z",
    last_seen: "2026-05-20T08:30:50Z",
    packets: 40,
    bytes: 2400,
    sent_to: false,
    alerted: true,
    peers: [HOST_IP],
    ports: [22, 80, 443],
    protocols: ["tcp"],
    enrichment: makeEnrichment({ status: "not_looked_up", address: SCANNER_IP }),
    ...overrides,
  };
}

export function makeSession(overrides: Partial<CaptureSession> = {}): CaptureSession {
  return {
    id: SESSION_ID,
    source_kind: "pcap",
    status: "completed",
    interface: null,
    source_label: "sample.pcap",
    started_at: STARTED_AT,
    ended_at: ENDED_AT,
    duration_seconds: 90,
    packets_total: 40,
    bytes_total: 2400,
    flows_total: 40,
    active_flows: 0,
    alerts_total: 1,
    packets_dropped: 0,
    error_code: null,
    message: null,
    ...overrides,
  };
}

export function makeSessionDetail(overrides: Partial<SessionDetail> = {}): SessionDetail {
  return {
    ...makeSession(),
    first_packet_at: "2026-05-20T08:30:05Z",
    last_packet_at: "2026-05-20T08:30:50Z",
    protocols: [{ protocol: "tcp", packets: 40, bytes: 2400 }],
    top_sources: [{ address: SCANNER_IP, packets: 40, bytes: 2400 }],
    top_destinations: [{ address: HOST_IP, packets: 40, bytes: 2400 }],
    non_ip_packets: 0,
    malformed_packets: 0,
    flows_evicted: 0,
    flows_stored: 40,
    flows_not_stored: 0,
    alerts_by_rule: { "NET-001": 1 },
    alerts_suppressed: 0,
    alerts_lost: 0,
    talkers_truncated: false,
    external_ips: [makeExternalIp()],
    enrichment: {
      enabled: true,
      total: 1,
      completed: 0,
      pending: 0,
      failed: 0,
      unavailable: 0,
      skipped: 0,
    },
    ...overrides,
  };
}

export function makeSessionPage(items: CaptureSession[] = [makeSession()]): SessionPage {
  return { items, total: items.length, limit: 25, offset: 0 };
}

export function makeFlow(overrides: Partial<Flow> = {}): Flow {
  return {
    id: 1,
    protocol: "tcp",
    src_ip: SCANNER_IP,
    src_port: 40001,
    dst_ip: HOST_IP,
    dst_port: 22,
    first_seen: "2026-05-20T08:30:05Z",
    last_seen: "2026-05-20T08:30:06Z",
    duration_seconds: 1,
    packets_out: 1,
    packets_in: 0,
    bytes_out: 60,
    bytes_in: 0,
    tcp_flags: 2,
    tcp_flag_names: ["SYN"],
    close_reason: "idle",
    ...overrides,
  };
}

export function makeFlowPage(items: Flow[] = [makeFlow()], total = items.length): FlowPage {
  return { items, total, limit: 25, offset: 0 };
}

export function makeAlert(overrides: Partial<NetworkAlert> = {}): NetworkAlert {
  return {
    id: ALERT_ID,
    session_id: SESSION_ID,
    rule_id: "NET-001",
    rule_name: "port_scan",
    title: "Port scan",
    severity: "high",
    explanation: `${SCANNER_IP} tried 40 different destination ports within 60 seconds.`,
    observed_value: 40,
    threshold: 20,
    unit: "ports",
    window_seconds: 60,
    src_ip: SCANNER_IP,
    dst_ip: HOST_IP,
    dst_port: null,
    protocol: "tcp",
    first_observed: "2026-05-20T08:30:05Z",
    last_observed: "2026-05-20T08:30:45Z",
    created_at: "2026-05-20T08:30:46Z",
    evidence: { distinct_ports: 40, sample_ports: [1, 2, 3] },
    enrichment: makeEnrichment({ status: "not_looked_up", address: SCANNER_IP }),
    ...overrides,
  };
}

export function makeAlertPage(items: NetworkAlert[] = [makeAlert()], total = items.length): AlertPage {
  return { items, total, limit: 25, offset: 0 };
}
