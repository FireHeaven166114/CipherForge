import { describe, expect, it } from "vitest";

import {
  DEFAULT_FILTERS,
  MAX_PAGE,
  MAX_SEARCH_LENGTH,
  PAGE_SIZE,
  hasActiveFilters,
  indicatorsHref,
  readFilters,
  toQuery,
  writeFilters,
} from "./filters";

const params = (query: string) => new URLSearchParams(query);

describe("readFilters", () => {
  it("returns the defaults for an empty address", () => {
    expect(readFilters(params(""))).toEqual(DEFAULT_FILTERS);
  });

  it("reads valid values", () => {
    expect(
      readFilters(params("q=%20example.test%20&type=domain&classification=high&sort=risk&page=3")),
    ).toEqual({ q: "example.test", type: "domain", classification: "high", sort: "risk", page: 3 });
  });

  it("reads the two groups the overview counts that are not a single band", () => {
    expect(readFilters(params("classification=high_risk")).classification).toBe("high_risk");
    expect(readFilters(params("classification=not_assessed")).classification).toBe("not_assessed");
  });

  it("ignores values the API would reject", () => {
    expect(
      readFilters(params("type=mac&classification=HIGH&sort=oldest&page=0")),
    ).toEqual(DEFAULT_FILTERS);
    expect(readFilters(params("page=-2")).page).toBe(1);
    expect(readFilters(params("page=2.5")).page).toBe(1);
    expect(readFilters(params("page=abc")).page).toBe(1);
  });

  it("clamps the page and the search text to what the API accepts", () => {
    expect(readFilters(params("page=999999")).page).toBe(MAX_PAGE);
    expect((MAX_PAGE - 1) * PAGE_SIZE).toBeLessThanOrEqual(10_000);
    expect(readFilters(params(`q=${"a".repeat(1000)}`)).q).toHaveLength(MAX_SEARCH_LENGTH);
  });
});

describe("writeFilters", () => {
  it("writes only what differs from the defaults", () => {
    expect(writeFilters(DEFAULT_FILTERS).toString()).toBe("");
    expect(
      writeFilters({ q: "a b", type: "ipv4", classification: "low", sort: "risk", page: 2 }).toString(),
    ).toBe("q=a+b&type=ipv4&classification=low&sort=risk&page=2");
  });

  it("round-trips through readFilters", () => {
    const filters = { q: "x&y=z", type: "url", classification: "critical", sort: "risk", page: 7 } as const;
    expect(readFilters(writeFilters(filters))).toEqual(filters);
    for (const classification of ["high_risk", "not_assessed"] as const) {
      expect(readFilters(writeFilters({ ...DEFAULT_FILTERS, classification })).classification).toBe(
        classification,
      );
    }
  });
});

describe("indicatorsHref", () => {
  it("links to the plain list without filters", () => {
    expect(indicatorsHref()).toBe("/indicators");
  });

  it("carries only the filters given, in the form the list page reads back", () => {
    const href = indicatorsHref({ type: "ipv4", classification: "critical", sort: "risk" });
    expect(href).toBe("/indicators?type=ipv4&classification=critical&sort=risk");
    expect(readFilters(new URLSearchParams(href.split("?")[1]))).toMatchObject({
      type: "ipv4",
      classification: "critical",
      sort: "risk",
    });
  });

  it("can lead to the indicators nobody assessed", () => {
    expect(indicatorsHref({ type: "domain", classification: "not_assessed" })).toBe(
      "/indicators?type=domain&classification=not_assessed",
    );
  });

  it("encodes search text", () => {
    expect(indicatorsHref({ q: "a&b c" })).toBe("/indicators?q=a%26b+c");
  });
});

describe("toQuery", () => {
  it("turns the page into an offset and drops empty filters", () => {
    expect(toQuery({ ...DEFAULT_FILTERS, page: 3 })).toEqual({
      type: undefined,
      q: undefined,
      sort: "recent",
      limit: PAGE_SIZE,
      offset: 2 * PAGE_SIZE,
    });
    expect(toQuery({ ...DEFAULT_FILTERS, q: "x", type: "sha256" })).toMatchObject({
      q: "x",
      type: "sha256",
      offset: 0,
    });
  });

  it("asks for assessed indicators in a band, so informational never includes unanswered ones", () => {
    expect(toQuery({ ...DEFAULT_FILTERS, classification: "informational" })).toMatchObject({
      classification: ["informational"],
      assessed: true,
    });
    expect(toQuery({ ...DEFAULT_FILTERS, classification: "high_risk" })).toMatchObject({
      classification: ["high", "critical"],
      assessed: true,
    });
  });

  it("asks for the indicators no provider answered without naming a band", () => {
    const query = toQuery({ ...DEFAULT_FILTERS, classification: "not_assessed" });

    expect(query.assessed).toBe(false);
    expect(query.classification).toBeUndefined();
  });
});

describe("hasActiveFilters", () => {
  it("ignores sort and page, which narrow nothing", () => {
    expect(hasActiveFilters({ ...DEFAULT_FILTERS, sort: "risk", page: 4 })).toBe(false);
    expect(hasActiveFilters({ ...DEFAULT_FILTERS, classification: "low" })).toBe(true);
    expect(hasActiveFilters({ ...DEFAULT_FILTERS, classification: "not_assessed" })).toBe(true);
    expect(hasActiveFilters({ ...DEFAULT_FILTERS, q: "x" })).toBe(true);
  });
});
