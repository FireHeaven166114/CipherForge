import { describe, expect, it } from "vitest";

import { describeTrend } from "./trend";

describe("describeTrend", () => {
  it("says how much a count rose compared with the previous period", () => {
    expect(describeTrend(9, 4)).toEqual({ direction: "up", text: "+5 vs 4 in the previous 24 hours" });
  });

  it("says how much a count fell", () => {
    expect(describeTrend(1, 6)).toEqual({ direction: "down", text: "-5 vs 6 in the previous 24 hours" });
  });

  it("distinguishes no change from nothing at all", () => {
    expect(describeTrend(3, 3)).toEqual({ direction: "flat", text: "No change from 3 in the previous 24 hours" });
    expect(describeTrend(0, 0)).toEqual({ direction: "flat", text: "None in the last 48 hours" });
  });

  it("compares with zero without dividing by it", () => {
    expect(describeTrend(2, 0)).toEqual({ direction: "up", text: "+2 vs 0 in the previous 24 hours" });
  });
});
