import { describe, expect, it } from "vitest";

import { CAPTURE_STATES, SESSION_STATUSES } from "../../types/network";
import {
  CAPTURE_STATE_META,
  closeReasonLabel,
  countOf,
  describeSource,
  formatEndpoint,
  formatFlags,
  humanize,
  isCaptureActive,
  isSessionActive,
  protocolLabel,
  SESSION_STATUS_META,
  yesNo,
} from "./labels";

describe("state metadata", () => {
  it("has a label for every capture state and every session status", () => {
    for (const state of CAPTURE_STATES) expect(CAPTURE_STATE_META[state].label).not.toBe("");
    for (const status of SESSION_STATUSES) expect(SESSION_STATUS_META[status].label).not.toBe("");
  });

  it("tones a problem as bad and a change under way as neutral and pulsing", () => {
    expect(CAPTURE_STATE_META.failed.tone).toBe("bad");
    expect(CAPTURE_STATE_META.permission_denied.tone).toBe("bad");
    expect(CAPTURE_STATE_META.not_configured.tone).toBe("warn");
    expect(CAPTURE_STATE_META.starting).toMatchObject({ tone: "neutral", pulsing: true });
    expect(CAPTURE_STATE_META.stopped).toMatchObject({ tone: "neutral", pulsing: false });
    expect(SESSION_STATUS_META.completed).toMatchObject({ label: "Completed", tone: "ok" });
  });
});

describe("activity", () => {
  it("counts starting, running and stopping as active", () => {
    expect(CAPTURE_STATES.filter(isCaptureActive)).toEqual(["starting", "running", "stopping"]);
    expect(SESSION_STATUSES.filter(isSessionActive)).toEqual(["starting", "running", "stopping"]);
  });
});

describe("humanize", () => {
  it.each([
    ["idle_timeout", "Idle timeout"],
    ["port-scan", "Port scan"],
    ["tcp", "Tcp"],
    ["", ""],
  ])("writes %j as %j", (key, expected) => {
    expect(humanize(key)).toBe(expected);
  });
});

describe("describeSource", () => {
  it("names the interface of a live capture and the file of an analysis", () => {
    expect(describeSource({ source_kind: "live", interface: "eth0", source_label: null })).toEqual({
      kind: "Live capture",
      name: "eth0",
    });
    expect(describeSource({ source_kind: "pcap", interface: null, source_label: "sample.pcap" })).toEqual({
      kind: "Capture file",
      name: "sample.pcap",
    });
  });

  it("does not invent a name", () => {
    expect(describeSource({ source_kind: "live", interface: null, source_label: null }).name).toBe(
      "Unknown interface",
    );
    expect(describeSource({ source_kind: "pcap", interface: null, source_label: null }).name).toBe(
      "Unnamed file",
    );
  });
});

describe("protocolLabel", () => {
  it.each([
    ["tcp", "TCP"],
    ["udp", "UDP"],
    ["icmp", "ICMP"],
    ["icmpv6", "ICMPv6"],
    ["igmp", "IGMP"],
    ["proto-47", "Protocol 47"],
    ["gre", "GRE"],
  ])("writes %s as %s", (protocol, expected) => {
    expect(protocolLabel(protocol)).toBe(expected);
  });
});

describe("formatEndpoint", () => {
  it("joins an address and a port, bracketing an IPv6 address", () => {
    expect(formatEndpoint("192.0.2.10", 22)).toBe("192.0.2.10:22");
    expect(formatEndpoint("2001:db8::1", 443)).toBe("[2001:db8::1]:443");
    expect(formatEndpoint("192.0.2.10", null)).toBe("192.0.2.10");
    expect(formatEndpoint("2001:db8::1", null)).toBe("2001:db8::1");
  });
});

describe("closeReasonLabel", () => {
  it("words the reasons the backend gives, and any other in plain language", () => {
    expect(closeReasonLabel("idle")).toBe("Idle");
    expect(closeReasonLabel("evicted")).toBe("Evicted");
    expect(closeReasonLabel("closed")).toBe("Closed");
    expect(closeReasonLabel("ended")).toBe("Session ended");
    expect(closeReasonLabel("reset_by_peer")).toBe("Reset by peer");
    expect(closeReasonLabel("constructor")).toBe("Constructor");
  });
});

describe("formatFlags", () => {
  it("lists the names, or says why there are none", () => {
    expect(formatFlags({ tcp_flags: 18, tcp_flag_names: ["SYN", "ACK"] })).toBe("SYN ACK");
    expect(formatFlags({ tcp_flags: 0, tcp_flag_names: [] })).toBe("None");
    expect(formatFlags({ tcp_flags: null, tcp_flag_names: [] })).toBe("Not TCP");
  });
});

describe("yesNo", () => {
  it("writes a flag as a word", () => {
    expect(yesNo(true)).toBe("Yes");
    expect(yesNo(false)).toBe("No");
  });
});

describe("countOf", () => {
  it("puts the noun in the plural unless the count is exactly one", () => {
    expect(countOf(0, "packet")).toBe("0 packets");
    expect(countOf(1, "packet")).toBe("1 packet");
    expect(countOf(2, "flow")).toBe("2 flows");
  });

  it("groups large counts", () => {
    expect(countOf(1_204_333, "alert")).toBe("1,204,333 alerts");
  });
});
