import { describe, expect, it } from "vitest";

import {
  areaPath,
  heatLevel,
  niceCeil,
  polar,
  project,
  ringSlices,
  smoothPath,
  ticksPath,
  valueAxis,
} from "./geometry";

describe("niceCeil", () => {
  it("rounds up to 1, 2, 5 or 10 times a power of ten", () => {
    expect(niceCeil(0.75)).toBe(1);
    expect(niceCeil(1)).toBe(1);
    expect(niceCeil(1.1)).toBe(2);
    expect(niceCeil(2.25)).toBe(5);
    expect(niceCeil(5.1)).toBe(10);
    expect(niceCeil(38)).toBe(50);
    expect(niceCeil(1200)).toBe(2000);
  });

  it("falls back to 1 for values that are not positive numbers", () => {
    for (const value of [0, -4, Number.NaN, Number.POSITIVE_INFINITY]) expect(niceCeil(value)).toBe(1);
  });
});

describe("valueAxis", () => {
  it("builds a tidy axis that always contains the largest value", () => {
    expect(valueAxis(9)).toEqual({ top: 10, step: 5, ticks: [0, 5, 10] });
    expect(valueAxis(3)).toEqual({ top: 3, step: 1, ticks: [0, 1, 2, 3] });
    expect(valueAxis(38)).toEqual({ top: 40, step: 10, ticks: [0, 10, 20, 30, 40] });
  });

  it("still draws an axis when everything is zero", () => {
    expect(valueAxis(0)).toEqual({ top: 1, step: 1, ticks: [0, 1] });
    expect(valueAxis(Number.NaN).top).toBe(1);
  });
});

describe("smoothPath", () => {
  it("is empty without points and a lone move with one point", () => {
    expect(smoothPath([])).toBe("");
    expect(smoothPath([{ x: 3, y: 4 }])).toBe("M3,4");
  });

  it("passes through every point", () => {
    const path = smoothPath([
      { x: 0, y: 10 },
      { x: 10, y: 0 },
      { x: 20, y: 10 },
    ]);
    expect(path.startsWith("M0,10C")).toBe(true);
    expect(path.endsWith("20,10")).toBe(true);
    expect(path).toContain(" 10,0C");
  });

  it("never overshoots a flat run (monotone), so a zero stays a zero", () => {
    const path = smoothPath([
      { x: 0, y: 100 },
      { x: 10, y: 100 },
      { x: 20, y: 40 },
      { x: 30, y: 100 },
    ]);
    const ys = [...path.matchAll(/-?\d+(?:\.\d+)?/g)].map(Number).filter((_, index) => index % 2 === 1);
    expect(Math.max(...ys)).toBeLessThanOrEqual(100);
    expect(Math.min(...ys)).toBeGreaterThanOrEqual(40);
  });
});

describe("areaPath", () => {
  it("closes the line down to the baseline", () => {
    const points = [
      { x: 0, y: 5 },
      { x: 10, y: 2 },
    ];
    const path = areaPath(points, 20);
    expect(path.endsWith("L10,20L0,20Z")).toBe(true);
    expect(areaPath([], 20)).toBe("");
  });
});

describe("polar and ticksPath", () => {
  it("measures angles clockwise from twelve o'clock", () => {
    const top = polar(50, 50, 10, 0);
    const right = polar(50, 50, 10, 90);
    expect([top.x, top.y]).toEqual([50, 40]);
    expect(right.x).toBeCloseTo(60);
    expect(right.y).toBeCloseTo(50);
  });

  it("draws one tick per step", () => {
    expect(ticksPath(0, 0, 8, 10, 12).match(/M/g)).toHaveLength(12);
  });
});

describe("ringSlices", () => {
  it("shares the ring in proportion to the values, leaving a gap between slices", () => {
    const slices = ringSlices(
      [
        { name: "a", value: 3 },
        { name: "b", value: 1 },
        { name: "c", value: 0 },
      ],
      (item) => item.value,
      0,
    );
    expect(slices.map((slice) => slice.item.name)).toEqual(["a", "b"]);
    expect(slices.map((slice) => slice.share)).toEqual([0.75, 0.25]);
    expect(slices[0]?.dash).toBe("75 25");
    expect(slices[1]?.offset).toBe(-75);
  });

  it("returns nothing when there is nothing to show", () => {
    expect(ringSlices([{ value: 0 }], (item) => item.value)).toEqual([]);
    expect(ringSlices([], () => 1)).toEqual([]);
  });
});

describe("heatLevel", () => {
  it("is 0 for empty cells and grows to the top level at the maximum", () => {
    expect(heatLevel(0, 10, 5)).toBe(0);
    expect(heatLevel(1, 100, 5)).toBe(1);
    expect(heatLevel(10, 10, 5)).toBe(5);
    expect(heatLevel(50, 10, 5)).toBe(5);
    expect(heatLevel(3, 0, 5)).toBe(0);
  });
});

describe("project", () => {
  const frame = { west: -180, east: 180, north: 90, south: -90, width: 360, height: 180 };

  it("maps longitude and latitude onto the frame", () => {
    expect(project(-180, 90, frame)).toEqual({ x: 0, y: 0 });
    expect(project(0, 0, frame)).toEqual({ x: 180, y: 90 });
    expect(project(180, -90, frame)).toEqual({ x: 360, y: 180 });
  });
});
