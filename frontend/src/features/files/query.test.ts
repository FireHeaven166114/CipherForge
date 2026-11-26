import { describe, expect, it } from "vitest";

import { buildQuery, fileLinkId, PAGE_SIZE, parseFileParam, parsePageParam } from "./query";

const FILE = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

describe("parseFileParam", () => {
  it("returns an id that could be a file's, and nothing else", () => {
    expect(parseFileParam(FILE)).toBe(FILE);
    expect(parseFileParam(` ${FILE} `)).toBe(FILE);
    expect(parseFileParam(null)).toBeNull();
    expect(parseFileParam("")).toBeNull();
    expect(parseFileParam("../etc/passwd")).toBeNull();
    expect(parseFileParam("a b")).toBeNull();
    expect(parseFileParam("x".repeat(65))).toBeNull();
  });
});

describe("parsePageParam", () => {
  it("reads a page number and treats everything else as the first page", () => {
    expect(parsePageParam("3")).toBe(3);
    expect(parsePageParam("1")).toBe(1);
    for (const bad of [null, "", "0", "-2", "1.5", "two", "9999999", "100001"]) {
      expect(parsePageParam(bad)).toBe(1);
    }
  });
});

describe("buildQuery", () => {
  it("leaves out whatever is the default", () => {
    expect(buildQuery(1, null)).toBe("");
    expect(buildQuery(2, null)).toBe("?page=2");
    expect(buildQuery(1, FILE)).toBe(`?file=${FILE}`);
    expect(buildQuery(3, FILE)).toBe(`?file=${FILE}&page=3`);
  });

  it("is read back by the parsers", () => {
    const params = new URLSearchParams(buildQuery(4, FILE));
    expect(parseFileParam(params.get("file"))).toBe(FILE);
    expect(parsePageParam(params.get("page"))).toBe(4);
  });
});

describe("fileLinkId", () => {
  it("is a valid, per-file DOM id", () => {
    expect(fileLinkId(FILE)).toBe(`file-link-${FILE}`);
    expect(fileLinkId(FILE)).not.toBe(fileLinkId("other"));
  });
});

describe("PAGE_SIZE", () => {
  it("is a size the API accepts (1 to 200)", () => {
    expect(PAGE_SIZE).toBeGreaterThanOrEqual(1);
    expect(PAGE_SIZE).toBeLessThanOrEqual(200);
  });
});
