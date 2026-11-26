import { describe, expect, it } from "vitest";

import { formatBytes, formatDuration, formatHours } from "./units";

describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [812, "812 B"],
    [1023, "1,023 B"],
    [1024, "1.00 KB"],
    [1536, "1.50 KB"],
    [10 * 1024, "10.0 KB"],
    [25 * 1024 * 1024, "25.0 MB"],
    [150 * 1024 * 1024, "150 MB"],
    [3 * 1024 ** 3, "3.00 GB"],
  ])("writes %d bytes as %s", (bytes, expected) => {
    expect(formatBytes(bytes)).toBe(expected);
  });

  it("stops at terabytes and does not invent a size for a value that is not one", () => {
    expect(formatBytes(5000 * 1024 ** 4)).toBe("5000 TB");
    expect(formatBytes(-1)).toBe("Unknown size");
    expect(formatBytes(Number.NaN)).toBe("Unknown size");
  });
});

describe("formatDuration", () => {
  it.each([
    [0, "0.0 s"],
    [0.44, "0.4 s"],
    [9.96, "10.0 s"],
    [42, "42 s"],
    [59.6, "1 min 00 s"],
    [185, "3 min 05 s"],
    [3600, "1 h 00 min"],
    [7500, "2 h 05 min"],
  ])("writes %d seconds as %s", (seconds, expected) => {
    expect(formatDuration(seconds)).toBe(expected);
  });

  it("answers Unknown for a value that cannot be a duration", () => {
    expect(formatDuration(-1)).toBe("Unknown");
    expect(formatDuration(Number.POSITIVE_INFINITY)).toBe("Unknown");
  });
});

describe("formatHours", () => {
  it("uses days only when the lifetime is a whole number of them", () => {
    expect(formatHours(1)).toBe("1 hour");
    expect(formatHours(24)).toBe("1 day");
    expect(formatHours(36)).toBe("36 hours");
    expect(formatHours(72)).toBe("3 days");
  });
});
