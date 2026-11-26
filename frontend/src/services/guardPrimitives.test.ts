import { describe, expect, it } from "vitest";

import {
  isArrayOf,
  isCount,
  isCountRecord,
  isFiniteNumber,
  isNullableCount,
  isNullableNumber,
  isNullableString,
  isOneOf,
  isRecord,
  isString,
  isStringArray,
} from "./guardPrimitives";

describe("guard primitives", () => {
  it("isRecord accepts plain objects only", () => {
    expect(isRecord({})).toBe(true);
    for (const value of [null, undefined, [], "text", 4, true]) expect(isRecord(value)).toBe(false);
  });

  it("isString and isNullableString", () => {
    expect(isString("")).toBe(true);
    expect(isString(null)).toBe(false);
    expect(isNullableString(null)).toBe(true);
    expect(isNullableString("x")).toBe(true);
    expect(isNullableString(undefined)).toBe(false);
    expect(isNullableString(3)).toBe(false);
  });

  it("numbers must be finite; counts must also be whole and not negative", () => {
    expect(isFiniteNumber(1.5)).toBe(true);
    for (const value of [Infinity, -Infinity, Number.NaN, "1", null]) {
      expect(isFiniteNumber(value)).toBe(false);
    }
    expect(isNullableNumber(null)).toBe(true);
    expect(isNullableNumber(Number.NaN)).toBe(false);

    expect(isCount(0)).toBe(true);
    expect(isCount(65535)).toBe(true);
    for (const value of [-1, 1.5, Number.NaN, "3", null, undefined]) {
      expect(isCount(value)).toBe(false);
    }
    expect(isNullableCount(null)).toBe(true);
    expect(isNullableCount(2)).toBe(true);
    expect(isNullableCount(-2)).toBe(false);
  });

  it("isArrayOf checks every item", () => {
    expect(isStringArray([])).toBe(true);
    expect(isStringArray(["a", "b"])).toBe(true);
    expect(isStringArray(["a", 1])).toBe(false);
    expect(isStringArray("a")).toBe(false);
    expect(isArrayOf(isCount)([1, 2, 3])).toBe(true);
  });

  it("isOneOf accepts only the listed strings", () => {
    const isColour = isOneOf(["red", "blue"] as const);
    expect(isColour("red")).toBe(true);
    expect(isColour("green")).toBe(false);
    expect(isColour(1)).toBe(false);
    expect(isColour("toString")).toBe(false);
  });

  it("isCountRecord needs an object whose values are all counts", () => {
    expect(isCountRecord({})).toBe(true);
    expect(isCountRecord({ "NET-001": 2 })).toBe(true);
    expect(isCountRecord({ "NET-001": -2 })).toBe(false);
    expect(isCountRecord({ "NET-001": "2" })).toBe(false);
    expect(isCountRecord([])).toBe(false);
    expect(isCountRecord(null)).toBe(false);
  });
});
