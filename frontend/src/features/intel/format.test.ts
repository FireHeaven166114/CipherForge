import { describe, expect, it } from "vitest";

import {
  formatCompactCount,
  formatCount,
  formatPoints,
  formatRelative,
  formatStrength,
  formatWait,
  plural,
} from "./format";

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

describe("formatCount and formatCompactCount", () => {
  it("group thousands in full, whatever the browser's locale", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(1234)).toBe("1,234");
    expect(formatCount(987_654_321_012)).toBe("987,654,321,012");
    expect(formatCompactCount(999_999)).toBe("999,999");
  });

  it("shorten a million or more, and only then", () => {
    expect(formatCompactCount(1_000_000)).toBe("1M");
    expect(formatCompactCount(2_450_000)).toBe("2.5M");
    expect(formatCompactCount(987_654_321_012)).toBe("987.7B");
  });

  it("can start shortening earlier, for a chart label that has little room", () => {
    expect(formatCompactCount(9_999, 10_000)).toBe("9,999");
    expect(formatCompactCount(12_480, 10_000)).toBe("12.5K");
    expect(formatCompactCount(250_000, 10_000)).toBe("250K");
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
