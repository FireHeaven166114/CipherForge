import { describe, expect, it } from "vitest";

import {
  makeAlert,
  makeAlertPage,
  makeCompletedEnrichment,
  makeEnrichment,
  makeExternalIp,
  makeFlow,
  makeFlowPage,
  makeInterfaces,
  makeNetworkStatus,
  makeRules,
  makeSession,
  makeSessionDetail,
  makeSessionPage,
} from "../test/networkFixtures";
import {
  isAlertPage,
  isCaptureSession,
  isEnrichment,
  isFlowPage,
  isInterfaceList,
  isNetworkAlert,
  isNetworkStatus,
  isRuleList,
  isSessionDetail,
  isSessionPage,
} from "./networkGuards";

function without(value: object, key: string): unknown {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  delete copy[key];
  return copy;
}

function expectEveryKeyRequired(guard: (value: unknown) => boolean, valid: object) {
  for (const key of Object.keys(valid)) {
    expect(guard(without(valid, key)), `missing ${key}`).toBe(false);
  }
}

const NOT_OBJECTS = [null, undefined, "text", 42, [], true];

describe("isNetworkStatus", () => {
  it("accepts every capture state and rejects an unknown one", () => {
    for (const state of [
      "not_configured",
      "ready",
      "starting",
      "running",
      "stopping",
      "stopped",
      "failed",
      "permission_denied",
    ] as const) {
      expect(isNetworkStatus(makeNetworkStatus({ state }))).toBe(true);
    }
    expect(isNetworkStatus({ ...makeNetworkStatus(), state: "paused" })).toBe(false);
  });

  it("accepts a running status with a session and rejects bad parts", () => {
    const running = makeNetworkStatus({ state: "running", interface: "eth0", session_id: "s-1" });
    expect(isNetworkStatus(running)).toBe(true);
    expectEveryKeyRequired(isNetworkStatus, running);
    expect(isNetworkStatus({ ...running, busy: "no" })).toBe(false);
    expect(isNetworkStatus({ ...running, backend: { name: "npcap" } })).toBe(false);
    expect(isNetworkStatus({ ...running, analysis: { running: false, session_id: null } })).toBe(
      false,
    );
    expect(isNetworkStatus({ ...running, analysis: { running: false, session_id: null, max_upload_mb: -1 } })).toBe(false);
    for (const value of NOT_OBJECTS) expect(isNetworkStatus(value)).toBe(false);
  });
});

describe("isInterfaceList", () => {
  it("accepts a list, including an empty one", () => {
    expect(isInterfaceList(makeInterfaces())).toBe(true);
    expect(isInterfaceList(makeInterfaces([]))).toBe(true);
  });

  it("rejects a malformed interface", () => {
    const valid = makeInterfaces();
    expect(isInterfaceList({ ...valid, interfaces: [{ id: "eth0" }] })).toBe(false);
    expect(isInterfaceList({ ...valid, interfaces: [{ ...valid.interfaces[0], addresses: [4] }] })).toBe(false);
    expectEveryKeyRequired(isInterfaceList, valid);
  });
});

describe("isRuleList", () => {
  it("accepts the seven rules and rejects a damaged one", () => {
    const rules = makeRules();
    expect(rules).toHaveLength(7);
    expect(isRuleList(rules)).toBe(true);
    expect(isRuleList([])).toBe(true);
    expect(isRuleList([{ ...rules[0], threshold: "20" }])).toBe(false);
    expect(isRuleList([{ ...rules[0], severities: ["urgent"] }])).toBe(false);
    expect(isRuleList([{ ...rules[0], window_seconds: -1 }])).toBe(false);
    expect(isRuleList([without(rules[0] as object, "active")])).toBe(false);
    expect(isRuleList({ rules })).toBe(false);
  });
});

describe("isEnrichment", () => {
  it("accepts every state and nullable fields", () => {
    for (const status of [
      "pending",
      "completed",
      "failed",
      "unavailable",
      "disabled",
      "skipped_budget",
      "not_applicable",
      "not_looked_up",
    ] as const) {
      expect(isEnrichment(makeEnrichment({ status }))).toBe(true);
    }
    expect(isEnrichment(makeCompletedEnrichment())).toBe(true);
  });

  it("rejects an unknown state, a bad score and a malformed provider", () => {
    const valid = makeCompletedEnrichment();
    expect(isEnrichment({ ...valid, status: "done" })).toBe(false);
    expect(isEnrichment({ ...valid, risk_score: 72.5 })).toBe(false);
    expect(isEnrichment({ ...valid, assessed: "yes" })).toBe(false);
    expect(isEnrichment({ ...valid, providers: [{ provider: "otx" }] })).toBe(false);
    expectEveryKeyRequired(isEnrichment, valid);
  });
});

describe("isCaptureSession and isSessionDetail", () => {
  it("accepts live and uploaded sessions", () => {
    expect(isCaptureSession(makeSession())).toBe(true);
    expect(isCaptureSession(makeSession({ source_kind: "live", interface: "eth0", ended_at: null }))).toBe(true);
    expect(isSessionDetail(makeSessionDetail())).toBe(true);
  });

  it("rejects a bad status, source, counter or missing key", () => {
    const valid = makeSession();
    expect(isCaptureSession({ ...valid, status: "paused" })).toBe(false);
    expect(isCaptureSession({ ...valid, source_kind: "wifi" })).toBe(false);
    expect(isCaptureSession({ ...valid, packets_total: -1 })).toBe(false);
    expect(isCaptureSession({ ...valid, duration_seconds: Number.NaN })).toBe(false);
    expectEveryKeyRequired(isCaptureSession, valid);
  });

  it("requires the extra fields of a detail and validates its nested parts", () => {
    const detail = makeSessionDetail();
    expectEveryKeyRequired(isSessionDetail, detail);
    expect(isSessionDetail(makeSession())).toBe(false);
    expect(isSessionDetail({ ...detail, protocols: [{ protocol: "tcp" }] })).toBe(false);
    expect(isSessionDetail({ ...detail, top_sources: [{ address: 1, packets: 1, bytes: 1 }] })).toBe(false);
    expect(isSessionDetail({ ...detail, alerts_by_rule: { "NET-001": "1" } })).toBe(false);
    expect(isSessionDetail({ ...detail, external_ips: [{ address: "203.0.113.45" }] })).toBe(false);
    expect(isSessionDetail({ ...detail, enrichment: { enabled: true } })).toBe(false);
    expect(isSessionDetail({ ...detail, external_ips: [makeExternalIp({ packets: null, bytes: null, first_seen: null, last_seen: null })] })).toBe(true);
  });
});

describe("pages, flows and alerts", () => {
  it("accepts pages and rejects broken ones", () => {
    expect(isSessionPage(makeSessionPage())).toBe(true);
    expect(isFlowPage(makeFlowPage())).toBe(true);
    expect(isFlowPage(makeFlowPage([makeFlow({ src_port: null, dst_port: null, tcp_flags: null, protocol: "icmp" })]))).toBe(true);
    expect(isAlertPage(makeAlertPage())).toBe(true);
    expect(isAlertPage(makeAlertPage([]))).toBe(true);

    expect(isSessionPage({ ...makeSessionPage(), items: [{}] })).toBe(false);
    expect(isFlowPage({ ...makeFlowPage(), total: -1 })).toBe(false);
    expect(isFlowPage({ ...makeFlowPage(), limit: "25" })).toBe(false);
    expect(isAlertPage({ ...makeAlertPage(), items: "none" })).toBe(false);
    expectEveryKeyRequired(isFlowPage, makeFlowPage());
    for (const value of NOT_OBJECTS) expect(isAlertPage(value)).toBe(false);
  });

  it("validates a flow's fields", () => {
    const valid = makeFlow();
    expectEveryKeyRequired((value) => isFlowPage({ items: [value], total: 1, limit: 25, offset: 0 }), valid);
    expect(isFlowPage({ items: [{ ...valid, bytes_in: -5 }], total: 1, limit: 25, offset: 0 })).toBe(false);
    expect(isFlowPage({ items: [{ ...valid, tcp_flag_names: [1] }], total: 1, limit: 25, offset: 0 })).toBe(false);
  });

  it("validates an alert's fields", () => {
    const valid = makeAlert();
    expect(isNetworkAlert(valid)).toBe(true);
    expect(isNetworkAlert(makeAlert({ src_ip: null, dst_ip: null, dst_port: null, protocol: null, window_seconds: null }))).toBe(true);
    expectEveryKeyRequired(isNetworkAlert, valid);
    expect(isNetworkAlert({ ...valid, severity: "urgent" })).toBe(false);
    expect(isNetworkAlert({ ...valid, evidence: [] })).toBe(false);
    expect(isNetworkAlert({ ...valid, evidence: null })).toBe(false);
    expect(isNetworkAlert({ ...valid, enrichment: { status: "completed" } })).toBe(false);
    expect(isNetworkAlert({ ...valid, observed_value: "40" })).toBe(false);
  });
});
