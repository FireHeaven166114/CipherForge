import { describe, expect, it } from "vitest";

import { makeIndicator, makeNotAssessed, makeScore } from "../../test/fixtures";
import {
  CLASSIFICATIONS_BY_SEVERITY,
  classificationForScore,
  isIndicatorAssessed,
  isScoreAssessed,
} from "./classification";

describe("classificationForScore", () => {
  it.each([
    [0, "informational"],
    [20, "informational"],
    [21, "low"],
    [40, "low"],
    [41, "medium"],
    [60, "medium"],
    [61, "high"],
    [80, "high"],
    [81, "critical"],
    [100, "critical"],
  ])("puts a score of %i in the %s band", (score, expected) => {
    expect(classificationForScore(score)).toBe(expected);
  });

  it("agrees with the severity order, most severe first", () => {
    const scores = [95, 70, 50, 30, 5];
    expect(scores.map(classificationForScore)).toEqual([...CLASSIFICATIONS_BY_SEVERITY]);
  });
});

describe("isScoreAssessed", () => {
  it("is true when at least one provider answered", () => {
    expect(isScoreAssessed(makeScore({ answered_sources: 1 }))).toBe(true);
  });

  it("is false when no provider answered, whatever the stored score says", () => {
    expect(isScoreAssessed(makeNotAssessed().score)).toBe(false);
  });
});

describe("isIndicatorAssessed", () => {
  it("treats zero confidence as nothing assessed, because confidence is 0 only without answers", () => {
    expect(isIndicatorAssessed(makeIndicator({ confidence: 0 }))).toBe(false);
    expect(isIndicatorAssessed(makeIndicator({ confidence: 15 }))).toBe(true);
  });
});
