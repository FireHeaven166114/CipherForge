import { describe, expect, it } from "vitest";

import { makeAlert } from "../../test/networkFixtures";
import {
  describeObservation,
  describeTraffic,
  formatMeasure,
  formatWindow,
  severityMeta,
  toggleSeverity,
} from "./alerts";

describe("severityMeta", () => {
  it("gives every severity a word and its own shape", () => {
    const shapes = (["low", "medium", "high", "critical"] as const).map((severity) => {
      const meta = severityMeta(severity);
      expect(meta.label.toLowerCase()).toBe(severity);
      return meta.symbol;
    });
    expect(new Set(shapes).size).toBe(4);
  });
});

describe("toggleSeverity", () => {
  it("adds and removes a severity, always in the order low to critical", () => {
    expect(toggleSeverity([], "high")).toEqual(["high"]);
    expect(toggleSeverity(["high"], "low")).toEqual(["low", "high"]);
    expect(toggleSeverity(["critical", "low"], "medium")).toEqual(["low", "medium", "critical"]);
    expect(toggleSeverity(["low", "high"], "low")).toEqual(["high"]);
    expect(toggleSeverity(["low"], "low")).toEqual([]);
  });
});

describe("formatMeasure", () => {
  it.each([
    [40, "ports", "40 ports"],
    [12480, "connections", "12,480 connections"],
    [51.34, "MB", "51.3 MB"],
    [2048.6, "MB", "2,049 MB"],
    [72, "", "72"],
    [1, "packets", "1 packet"],
    [1, "ports", "1 port"],
    [1, "risk score", "1 risk score"],
    [0, "packets", "0 packets"],
    [1.5, "packets", "1.5 packets"],
    [1, "constructor", "1 constructor"],
  ])("writes %d %j as %j", (value, unit, expected) => {
    expect(formatMeasure(value, unit)).toBe(expected);
  });
});

describe("formatWindow", () => {
  it("counts seconds, or says there is no window", () => {
    expect(formatWindow(60)).toBe("60 seconds");
    expect(formatWindow(1)).toBe("1 second");
    expect(formatWindow(null)).toBe("No time window");
  });
});

describe("describeObservation", () => {
  it("sets the observed value against the threshold and the window", () => {
    expect(describeObservation(makeAlert())).toBe(
      "Observed 40 ports against a threshold of 20 ports, within 60 seconds.",
    );
  });

  it("leaves the window out when the rule has none", () => {
    expect(
      describeObservation(makeAlert({ observed_value: 83, threshold: 61, unit: "risk score", window_seconds: null })),
    ).toBe("Observed 83 risk score against a threshold of 61 risk score.");
  });
});

describe("describeTraffic", () => {
  it("names the source, the destination with its port, and the protocol", () => {
    expect(describeTraffic(makeAlert({ dst_port: 22 }))).toEqual({
      source: "203.0.113.45",
      destination: "192.0.2.10:22",
      protocol: "TCP",
    });
  });

  it("leaves out what the alert does not know", () => {
    expect(describeTraffic(makeAlert({ src_ip: null, dst_ip: null, dst_port: null, protocol: null }))).toEqual({
      source: null,
      destination: null,
      protocol: null,
    });
    expect(describeTraffic(makeAlert({ dst_port: null })).destination).toBe("192.0.2.10");
  });
});
