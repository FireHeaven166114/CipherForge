import { describe, expect, it } from "vitest";

import { makeOverview } from "../../test/fixtures";
import { facetItems, mapMarkers, riskSlices, threatSeries, typeAxes } from "./chartData";

describe("riskSlices", () => {
  it("lists the bands most severe first, then not assessed, each opening the indicators it counts", () => {
    const slices = riskSlices(makeOverview());

    expect(slices.map((slice) => [slice.key, slice.value])).toEqual([
      ["critical", 1],
      ["high", 2],
      ["medium", 1],
      ["low", 3],
      ["informational", 4],
      ["not_assessed", 1],
    ]);
    expect(slices[0]?.to).toBe("/indicators?classification=critical&sort=risk");
    expect(slices[5]?.to).toBe("/indicators?classification=not_assessed");
  });

  it("counts a band the API left out as zero", () => {
    const overview = makeOverview({ by_classification: { high: 2 } });
    const values = Object.fromEntries(riskSlices(overview).map((slice) => [slice.key, slice.value]));
    expect(values).toMatchObject({ critical: 0, high: 2, not_assessed: 0 });
  });
});

describe("typeAxes", () => {
  it("has an axis per indicator type that opens the list of that type", () => {
    const axes = typeAxes(makeOverview());
    expect(axes.map((axis) => [axis.label, axis.value])).toEqual([
      ["IPv4", 6],
      ["IPv6", 1],
      ["Domain", 3],
      ["URL", 1],
      ["MD5", 0],
      ["SHA-1", 0],
      ["SHA-256", 1],
    ]);
    expect(axes[2]?.to).toBe("/indicators?type=domain");
  });
});

describe("threatSeries", () => {
  it("builds one line for lookups and one for high-risk lookups over the same days", () => {
    const overview = makeOverview();
    const { categories, series } = threatSeries(overview);

    expect(categories).toEqual(overview.series.map((point) => point.day));
    expect(series.map((line) => line.label)).toEqual(["Lookups", "High-risk lookups"]);
    for (const line of series) expect(line.values).toHaveLength(categories.length);
    expect(series[0]?.values).toEqual(overview.series.map((point) => point.lookups));
  });
});

describe("facetItems and mapMarkers", () => {
  it("turn facet entries into bar rows, naming them with the given label", () => {
    const { malware_families: families, countries } = makeOverview();
    expect(facetItems(families)[0]).toEqual({
      key: families[0]?.key,
      label: families[0]?.key,
      count: families[0]?.count,
      maxRisk: families[0]?.max_risk,
    });
    expect(facetItems(countries, (key) => `<${key}>`)[0]?.label).toBe(`<${countries[0]?.key}>`);
  });

  it("names map markers by country", () => {
    const markers = mapMarkers(makeOverview().countries);
    expect(markers[0]).toMatchObject({ code: "NL", name: "Netherlands (NL)", count: 4, maxRisk: 80 });
  });
});
