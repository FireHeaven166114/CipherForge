import { describe, expect, it } from "vitest";

import { countryLabel, countryName, hasMapPosition, mapPosition } from "./countries";

describe("country names", () => {
  it("names a country from its ISO code", () => {
    expect(countryName("NL")).toBe("Netherlands");
    expect(countryLabel("DE")).toBe("Germany (DE)");
  });

  it("falls back to the code for anything that is not a code", () => {
    expect(countryName("netherlands")).toBe("netherlands");
    expect(countryName("")).toBe("");
    expect(countryLabel("QQ")).toBe("QQ");
  });

  it("knows which countries the map can place", () => {
    expect(hasMapPosition("NL")).toBe(true);
    expect(hasMapPosition("QQ")).toBe(false);
  });

  it("never mistakes a property of the lookup table for a country", () => {
    for (const key of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      expect(hasMapPosition(key)).toBe(false);
      expect(mapPosition(key)).toBeUndefined();
    }
    expect(mapPosition("NL")).toHaveLength(2);
  });
});
