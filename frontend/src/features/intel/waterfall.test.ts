import { describe, expect, it } from "vitest";

import { buildWaterfall } from "./waterfall";

describe("buildWaterfall", () => {
  it("lays factors end to end so the last one stops at the score", () => {
    const { steps, end, limit } = buildWaterfall([45, 22, 8, 5]);

    expect(steps).toEqual([
      { from: 0, to: 45, kind: "add" },
      { from: 45, to: 67, kind: "add" },
      { from: 67, to: 75, kind: "add" },
      { from: 75, to: 80, kind: "add" },
    ]);
    expect(end).toBe(80);
    expect(limit).toBe(100);
  });

  it("draws a cap as a trim that steps the total back down", () => {
    const { steps, end } = buildWaterfall([45, 22, 8, 5, -20]);

    expect(steps[4]).toEqual({ from: 60, to: 80, kind: "trim" });
    expect(end).toBe(60);
  });

  it("squeezes the track when the factors add up to more than 100 before the cap", () => {
    const { steps, end, limit } = buildWaterfall([45, 45, 16, 10, -16]);

    expect(limit).toBeCloseTo((100 / 116) * 100);
    expect(steps[3]?.to).toBe(100);
    expect(end).toBeCloseTo(limit);
    for (const step of steps) {
      expect(step.from).toBeGreaterThanOrEqual(0);
      expect(step.to).toBeLessThanOrEqual(100);
    }
  });

  it("never draws below zero or from a value that is not a number", () => {
    const { steps, end } = buildWaterfall([-10, Number.NaN, 5]);

    expect(steps.map((step) => [step.from, step.to])).toEqual([
      [0, 0],
      [0, 0],
      [0, 5],
    ]);
    expect(end).toBe(5);
  });

  it("draws nothing for no factors", () => {
    expect(buildWaterfall([])).toEqual({ steps: [], end: 0, limit: 100 });
  });
});
