import { describe, expect, it } from "vitest";

import { describeDeletion } from "./deletion";

function result(deleted: number, notFound: number, answers = 0) {
  return {
    deleted: Array.from({ length: deleted }, (_, index) => `d${index}`),
    not_found: Array.from({ length: notFound }, (_, index) => `n${index}`),
    observations_removed: answers,
  };
}

describe("describeDeletion", () => {
  it("counts what was removed, in the singular or the plural", () => {
    expect(describeDeletion(result(1, 0, 1))).toBe("Deleted 1 indicator and 1 stored provider answer.");
    expect(describeDeletion(result(3, 0, 7))).toBe("Deleted 3 indicators and 7 stored provider answers.");
  });

  it("adds that some were already gone", () => {
    expect(describeDeletion(result(2, 1, 4))).toBe(
      "Deleted 2 indicators and 4 stored provider answers. 1 indicator was already gone.",
    );
    expect(describeDeletion(result(1, 3, 2))).toBe(
      "Deleted 1 indicator and 2 stored provider answers. 3 indicators were already gone.",
    );
  });

  it("says plainly when there was nothing left to delete", () => {
    expect(describeDeletion(result(0, 1))).toBe("Nothing was deleted. 1 indicator was already gone.");
    expect(describeDeletion(result(0, 2))).toBe("Nothing was deleted. 2 indicators were already gone.");
    expect(describeDeletion(result(0, 0))).toBe("Nothing was deleted.");
  });
});
