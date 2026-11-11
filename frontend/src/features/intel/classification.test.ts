import { describe, expect, it } from "vitest";

import { makeIndicator, makeNotAssessed, makeScore } from "../../test/fixtures";
import { isIndicatorAssessed, isScoreAssessed } from "./classification";

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
