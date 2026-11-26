import { describe, expect, it } from "vitest";

import { formatIst, formatIstTime, IST_LABEL, IST_TIME_ZONE, parseTimestamp } from "./ist";

describe("parseTimestamp", () => {
  it("reads API timestamps and treats a missing zone as UTC", () => {
    expect(parseTimestamp("2026-05-01T12:00:00Z")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T14:00:00+02:00")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T12:00:00.123456")?.toISOString()).toBe("2026-05-01T12:00:00.123Z");
    expect(parseTimestamp("2026-05-01T12:00:00")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
  });

  it("accepts a space separator, a lower-case z, an offset without a colon and no seconds", () => {
    expect(parseTimestamp("2026-05-01 12:00:00")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T12:00:00z")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T17:30:00+0530")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T09:00:00-03")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
    expect(parseTimestamp("2026-05-01T12:00Z")?.toISOString()).toBe("2026-05-01T12:00:00.000Z");
  });

  it("returns null for missing, unreadable or impossible values", () => {
    const unreadable = [
      null,
      undefined,
      "",
      "yesterday",
      "2026-05-01",
      "2026-13-45T99:99:99Z",
      "2026-02-30T00:00:00Z",
      "2026-05-01T24:00:00Z",
      "2026-05-01T12:60:00Z",
      "2026-05-01T12:00:60Z",
      "2026-05-01T12:00:00+25:00",
      "1969-12-31T23:59:59Z",
      "2201-01-01T00:00:00Z",
    ];
    for (const value of unreadable) expect(parseTimestamp(value)).toBeNull();
  });
});

describe("formatIst", () => {
  it("shows Indian Standard Time as DD-MM-YYYY hh:mm:ss A IST", () => {
    expect(IST_TIME_ZONE).toBe("Asia/Kolkata");
    expect(IST_LABEL).toBe("IST");
    expect(formatIst("2026-11-25T04:19:00Z")).toBe("25-11-2026 09:49:00 AM IST");
  });

  it("takes an instant as well as an API timestamp", () => {
    expect(formatIst(new Date("2026-11-25T04:19:00Z"))).toBe("25-11-2026 09:49:00 AM IST");
  });

  it("converts a time-zone-aware value and reads a naive one as UTC", () => {
    expect(formatIst("2026-05-01T14:00:00+02:00")).toBe("01-05-2026 05:30:00 PM IST");
    expect(formatIst("2026-11-25T04:19:00")).toBe("25-11-2026 09:49:00 AM IST");
  });

  it("uses a 12-hour clock with 12 for midnight and noon", () => {
    expect(formatIst("2026-11-24T18:30:00Z")).toBe("25-11-2026 12:00:00 AM IST");
    expect(formatIst("2026-05-01T06:30:00Z")).toBe("01-05-2026 12:00:00 PM IST");
    expect(formatIst("2026-05-01T07:30:00Z")).toBe("01-05-2026 01:00:00 PM IST");
    expect(formatIst("2026-05-01T18:29:59Z")).toBe("01-05-2026 11:59:59 PM IST");
  });

  it("moves to the next IST day while it is still the same UTC day", () => {
    expect(formatIst("2026-11-24T18:29:59Z")).toBe("24-11-2026 11:59:59 PM IST");
    expect(formatIst("2026-11-24T18:30:00Z")).toBe("25-11-2026 12:00:00 AM IST");
    expect(formatIst("2026-12-31T20:00:00Z")).toBe("01-01-2027 01:30:00 AM IST");
  });

  it("is +05:30 all year, because India has no daylight saving", () => {
    expect(formatIst("2026-01-15T00:00:00Z")).toBe("15-01-2026 05:30:00 AM IST");
    expect(formatIst("2026-07-15T00:00:00Z")).toBe("15-07-2026 05:30:00 AM IST");
  });

  it("falls back for a missing or unreadable value, and never throws", () => {
    expect(formatIst(null)).toBe("Unknown");
    expect(formatIst(undefined)).toBe("Unknown");
    expect(formatIst("")).toBe("Unknown");
    expect(formatIst("not a time")).toBe("Unknown");
    expect(formatIst(new Date(Number.NaN))).toBe("Unknown");
    expect(formatIst(null, "Never")).toBe("Never");
    expect(formatIst("not a time", "Never")).toBe("Never");
  });
});

describe("formatIstTime", () => {
  it("shows the IST time of day with seconds", () => {
    expect(formatIstTime(new Date("2026-05-01T09:05:03Z"))).toBe("02:35:03 PM IST");
    expect(formatIstTime(new Date("2026-05-01T23:59:59.999+02:00"))).toBe("03:29:59 AM IST");
    expect(formatIstTime("2026-11-25T04:19:00Z")).toBe("09:49:00 AM IST");
  });

  it("falls back for a missing or unreadable value", () => {
    expect(formatIstTime(null)).toBe("Unknown");
    expect(formatIstTime("nope", "Not checked yet")).toBe("Not checked yet");
  });
});
