import { describe, expect, it } from "vitest";

import {
  formatPoints,
  formatRelative,
  formatStrength,
  formatUtc,
  formatWait,
  parseTimestamp,
  plural,
} from "./format";

describe("parseTimestamp", () => {
  it("reads API timestamps and treats a missing zone as UTC", () => {
    expect(parseTimestamp("2026-05-01T12:00:00Z")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T14:00:00+02:00")?.toISOString()).toBe(
      "2026-05-01T12:00:00.000Z",
    );
    expect(parseTimestamp("2026-05-01T12:00:00.123456")?.toISOString()).toBe(
      "2026-05-01T12:00:00.123Z",
    );
  });

  it("returns null for missing or unreadable values", () => {
    for (const value of [null, undefined, "", "yesterday", "2026-13-45T99:99:99Z"]) {
      expect(parseTimestamp(value)).toBeNull();
    }
  });
});

describe("formatUtc", () => {
  it("always shows UTC, whatever the browser's zone", () => {
    expect(formatUtc(new Date("2026-05-01T23:59:59Z"))).toBe("2026-05-01 23:59 UTC");
    expect(formatUtc(new Date("2026-01-02T03:04:00+05:30"))).toBe("2026-01-01 21:34 UTC");
  });
});

describe("formatRelative", () => {
  const now = new Date("2026-05-10T12:00:00Z");
  const at = (iso: string) => formatRelative(new Date(iso), now);

  it("describes the past and the future", () => {
    expect(at("2026-05-07T12:00:00Z")).toBe("3 days ago");
    expect(at("2026-05-10T07:00:00Z")).toBe("5 hours ago");
    expect(at("2026-05-10T12:45:00Z")).toBe("in 45 minutes");
    expect(at("2026-05-11T18:00:00Z")).toBe("tomorrow");
    expect(at("2024-05-10T12:00:00Z")).toBe("2 years ago");
  });

  it("calls anything under a minute just now", () => {
    expect(at("2026-05-10T12:00:00Z")).toBe("just now");
    expect(at("2026-05-10T11:59:30Z")).toBe("just now");
  });
});

describe("formatPoints", () => {
  it("marks contributions and deductions", () => {
    expect(formatPoints(45)).toBe("+45");
    expect(formatPoints(-12)).toBe("-12");
    expect(formatPoints(0)).toBe("0");
  });
});

describe("formatStrength", () => {
  it("uses two decimals and says so when there is none", () => {
    expect(formatStrength(0.5)).toBe("0.50");
    expect(formatStrength(1)).toBe("1.00");
    expect(formatStrength(null)).toBe("Not available");
  });
});

describe("formatWait", () => {
  it("rounds up to whole seconds or minutes", () => {
    expect(formatWait(0)).toBe("a moment");
    expect(formatWait(1)).toBe("1 second");
    expect(formatWait(45)).toBe("45 seconds");
    expect(formatWait(60)).toBe("1 minute");
    expect(formatWait(61)).toBe("2 minutes");
    expect(formatWait(3600)).toBe("60 minutes");
  });
});

describe("plural", () => {
  it("adds an s except for exactly one", () => {
    expect(plural(0, "provider")).toBe("0 providers");
    expect(plural(1, "provider")).toBe("1 provider");
    expect(plural(2, "provider")).toBe("2 providers");
  });
});
