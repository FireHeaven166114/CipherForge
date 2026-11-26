import { describe, expect, it } from "vitest";

import { buildPaletteItems } from "./paletteItems";

const EFFECTS_ON = { enabled: true, locked: false };

function ids(query: string, effects = EFFECTS_ON): string[] {
  return buildPaletteItems(query, effects).map((item) => item.id);
}

describe("buildPaletteItems", () => {
  it("offers every page and the effects switch when nothing is typed", () => {
    expect(ids("")).toEqual([
      "go-overview",
      "go-investigate",
      "go-indicators",
      "go-network",
      "go-files",
      "go-status",
      "effects",
    ]);
  });

  it("offers to investigate or search for anything typed, ahead of the pages", () => {
    const items = buildPaletteItems("8.8.8.8", EFFECTS_ON);

    expect(items.slice(0, 2).map((item) => item.action)).toEqual([
      { kind: "investigate", indicator: "8.8.8.8" },
      { kind: "search", query: "8.8.8.8" },
    ]);
  });

  it("trims the text it offers to investigate", () => {
    const [first] = buildPaletteItems("  example.com  ", EFFECTS_ON);

    expect(first?.action).toEqual({ kind: "investigate", indicator: "example.com" });
  });

  it("filters pages by every word typed, including related words", () => {
    expect(ids("over")).toEqual(["investigate", "search", "go-overview"]);
    expect(ids("health")).toContain("go-status");
    expect(ids("go to status")).toContain("go-status");
    expect(ids("go to status")).not.toContain("go-overview");
    expect(ids("pcap")).toContain("go-network");
    expect(ids("encrypted share")).toContain("go-files");
    expect(ids("encrypted share")).not.toContain("go-network");
  });

  it("words the effects switch by its current state, and hides it when reduced motion is requested", () => {
    expect(buildPaletteItems("effects", EFFECTS_ON).at(-1)?.label).toBe("Turn visual effects off");
    expect(buildPaletteItems("effects", { enabled: false, locked: false }).at(-1)?.label).toBe(
      "Turn visual effects on",
    );
    expect(ids("effects", { enabled: false, locked: true })).not.toContain("effects");
  });
});
