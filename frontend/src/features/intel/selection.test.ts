import { describe, expect, it } from "vitest";

import { pageSelection, rangeBetween } from "./selection";

const ROWS = ["a", "b", "c", "d", "e"];

describe("pageSelection", () => {
  it("says whether none, some or all of the rows on screen are ticked", () => {
    expect(pageSelection(ROWS, new Set())).toBe("none");
    expect(pageSelection(ROWS, new Set(["b"]))).toBe("some");
    expect(pageSelection(ROWS, new Set(ROWS))).toBe("all");
  });

  it("counts only the rows that are on screen", () => {
    expect(pageSelection(ROWS, new Set(["gone"]))).toBe("none");
    expect(pageSelection(["a", "b"], new Set(["a", "b", "gone"]))).toBe("all");
  });

  it("never calls an empty page fully ticked", () => {
    expect(pageSelection([], new Set())).toBe("none");
    expect(pageSelection([], new Set(["a"]))).toBe("none");
  });
});

describe("rangeBetween", () => {
  it("includes both ends, whichever way the range runs", () => {
    expect(rangeBetween(ROWS, "b", "d")).toEqual(["b", "c", "d"]);
    expect(rangeBetween(ROWS, "d", "b")).toEqual(["b", "c", "d"]);
  });

  it("is the one row when both ends are the same", () => {
    expect(rangeBetween(ROWS, "c", "c")).toEqual(["c"]);
  });

  it("falls back to the clicked row when the row it started from is no longer on screen", () => {
    expect(rangeBetween(ROWS, "gone", "c")).toEqual(["c"]);
  });

  it("changes nothing when the clicked row is not on screen", () => {
    expect(rangeBetween(ROWS, "b", "gone")).toEqual([]);
  });
});
