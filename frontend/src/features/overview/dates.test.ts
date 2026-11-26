import { describe, expect, it } from "vitest";

import { hourLabel, longDay, parseDay, shortDay, weekdayAndDate } from "./dates";

describe("day formatting", () => {
  it("formats an IST calendar day in three lengths", () => {
    expect(shortDay("2026-05-14")).toBe("14 May");
    expect(weekdayAndDate("2026-05-14")).toBe("Thu 14");
    expect(longDay("2026-05-14")).toBe("Thu 14 May 2026");
  });

  it("does not shift the day for time zones", () => {
    expect(longDay("2026-01-01")).toBe("Thu 1 Jan 2026");
    expect(longDay("2026-12-31")).toBe("Thu 31 Dec 2026");
  });

  it("hands back text that is not a real day unchanged", () => {
    for (const bad of ["", "tomorrow", "2026-02-30", "2026-13-01", "2026-5-4"]) {
      expect(parseDay(bad)).toBeNull();
      expect(shortDay(bad)).toBe(bad);
      expect(longDay(bad)).toBe(bad);
    }
  });

  it("pads hours", () => {
    expect(hourLabel(9)).toBe("09:00");
    expect(hourLabel(23)).toBe("23:00");
  });
});
