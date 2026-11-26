import { describe, expect, it } from "vitest";

import { makeNetworkStatus, makeSessionDetail } from "../../test/networkFixtures";
import {
  IDLE_POLL_MS,
  LIVE_POLL_MS,
  PCAP_POLL_MS,
  sessionPollInterval,
  statusPollInterval,
} from "./polling";

describe("intervals", () => {
  it("polls an uploaded capture faster than the live rate and the idle rate slowest", () => {
    expect(PCAP_POLL_MS).toBe(1500);
    expect(LIVE_POLL_MS).toBe(2000);
    expect(IDLE_POLL_MS).toBe(15000);
  });
});

describe("statusPollInterval", () => {
  it.each(["starting", "running", "stopping"] as const)("polls fast while a capture is %s", (state) => {
    expect(statusPollInterval(makeNetworkStatus({ state }))).toBe(LIVE_POLL_MS);
  });

  it("polls fast while a capture file is being analysed, wherever it was uploaded from", () => {
    const analysing = makeNetworkStatus({ analysis: { running: true, session_id: null, max_upload_mb: 50 } });
    expect(statusPollInterval(analysing)).toBe(LIVE_POLL_MS);
  });

  it.each(["not_configured", "ready", "stopped", "failed", "permission_denied"] as const)(
    "polls slowly when %s",
    (state) => {
      expect(statusPollInterval(makeNetworkStatus({ state }))).toBe(IDLE_POLL_MS);
    },
  );
});

describe("sessionPollInterval", () => {
  it("polls slowly without a session or for a finished one", () => {
    expect(sessionPollInterval(null)).toBe(IDLE_POLL_MS);
    expect(sessionPollInterval(makeSessionDetail())).toBe(IDLE_POLL_MS);
  });

  it("polls fast while a session is still being filled", () => {
    expect(sessionPollInterval(makeSessionDetail({ status: "running" }))).toBe(LIVE_POLL_MS);
    expect(sessionPollInterval(makeSessionDetail({ status: "stopping" }))).toBe(LIVE_POLL_MS);
  });

  it("polls fast while address lookups are pending", () => {
    const detail = makeSessionDetail();
    const pending = { ...detail, enrichment: { ...detail.enrichment, pending: 2 } };
    expect(sessionPollInterval(pending)).toBe(LIVE_POLL_MS);
  });
});
