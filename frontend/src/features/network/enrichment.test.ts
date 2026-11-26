import { describe, expect, it } from "vitest";

import { makeCompletedEnrichment, makeEnrichment } from "../../test/networkFixtures";
import { ENRICHMENT_STATES } from "../../types/network";
import {
  canLookUp,
  classificationMeta,
  describeProvider,
  ENRICHMENT_META,
  enrichmentNote,
  hasScore,
  NO_DATA_NOTE,
  providerStatusLabel,
  summaryRows,
} from "./enrichment";

describe("ENRICHMENT_META", () => {
  it("has a label and a shape for every state, and no state looks like a tick", () => {
    for (const state of ENRICHMENT_STATES) {
      const meta = ENRICHMENT_META[state];
      expect(meta.label).not.toBe("");
      expect(meta.glyph).not.toBe("");
      expect(meta.glyph).not.toBe("✓");
    }
    const glyphs = new Set(ENRICHMENT_STATES.map((state) => ENRICHMENT_META[state].glyph));
    expect(glyphs.size).toBeGreaterThanOrEqual(5);
  });
});

describe("enrichmentNote", () => {
  it("never reads no data as safe", () => {
    const note = enrichmentNote(makeCompletedEnrichment({ risk_score: null, classification: null }));
    expect(note).toBe(NO_DATA_NOTE);
    expect(note).toBe("No provider returned data. This is not evidence the address is safe.");
  });

  it("calls a score a signal, not a verdict", () => {
    expect(enrichmentNote(makeCompletedEnrichment())).toContain("not a verdict");
  });

  it("explains each other state", () => {
    expect(enrichmentNote(makeEnrichment({ status: "pending" }))).toContain("waiting");
    expect(enrichmentNote(makeEnrichment({ status: "skipped_budget" }))).toContain("limit on lookups");
    expect(enrichmentNote(makeEnrichment({ status: "disabled" }))).toContain("switched off");
    expect(enrichmentNote(makeEnrichment({ status: "not_applicable" }))).toContain("no public address");
    expect(enrichmentNote(makeEnrichment({ status: "not_looked_up" }))).toContain("Nothing was sent");
  });

  it("shows what the server said about a failure, else a plain sentence", () => {
    expect(enrichmentNote(makeEnrichment({ status: "failed", message: "A provider returned an error." }))).toBe(
      "A provider returned an error.",
    );
    expect(enrichmentNote(makeEnrichment({ status: "failed" }))).toBe("The lookup failed.");
    expect(enrichmentNote(makeEnrichment({ status: "unavailable" }))).toContain("No provider could be asked");
    expect(
      enrichmentNote(makeEnrichment({ status: "unavailable", message: "No provider is configured." })),
    ).toBe("No provider is configured.");
  });
});

describe("hasScore", () => {
  it("is true for a score of zero too, and false for none", () => {
    expect(hasScore({ risk_score: 0 })).toBe(true);
    expect(hasScore({ risk_score: 72 })).toBe(true);
    expect(hasScore({ risk_score: null })).toBe(false);
  });

  it("is false for a score the server says no provider stood behind", () => {
    expect(hasScore({ risk_score: 0, assessed: false })).toBe(false);
    expect(hasScore({ risk_score: 72, assessed: true })).toBe(true);
    expect(hasScore({ risk_score: 72, assessed: null })).toBe(true);
  });
});

describe("canLookUp", () => {
  it.each([
    ["not_looked_up", true, true],
    ["failed", true, true],
    ["unavailable", true, true],
    ["skipped_budget", true, true],
    ["pending", true, false],
    ["completed", true, false],
    ["not_applicable", true, false],
    ["disabled", true, false],
    ["not_looked_up", false, false],
    ["failed", false, false],
  ] as const)("a %s address, with enrichment on = %s: look up = %s", (status, enabled, expected) => {
    expect(canLookUp({ status }, enabled)).toBe(expected);
  });
});

describe("classificationMeta", () => {
  it("knows the bands and nothing else", () => {
    expect(classificationMeta("high")?.label).toBe("High");
    expect(classificationMeta("informational")?.label).toBe("Informational");
    expect(classificationMeta(null)).toBeNull();
    expect(classificationMeta("toString")).toBeNull();
    expect(classificationMeta("mystery")).toBeNull();
  });
});

describe("providers", () => {
  it("words each provider status, and an unknown one in plain language", () => {
    expect(providerStatusLabel("ok")).toBe("Answered");
    expect(providerStatusLabel("no_data")).toBe("No data");
    expect(providerStatusLabel("rate_limited")).toBe("Rate limited");
    expect(providerStatusLabel("brand_new")).toBe("Brand new");
    expect(providerStatusLabel("constructor")).toBe("Constructor");
  });

  it("gives the verdict as the provider's own word", () => {
    expect(
      describeProvider({ provider: "abuseipdb", display_name: "AbuseIPDB", status: "ok", verdict: "malicious" }),
    ).toBe("AbuseIPDB: Answered, verdict malicious");
    expect(
      describeProvider({ provider: "otx", display_name: "AlienVault OTX", status: "no_data", verdict: null }),
    ).toBe("AlienVault OTX: No data");
  });
});

describe("summaryRows", () => {
  it("lists the counts in reading order", () => {
    const rows = summaryRows({ enabled: true, total: 6, completed: 1, pending: 2, failed: 1, unavailable: 1, skipped: 1 });
    expect(rows.map((row) => [row.label, row.value])).toEqual([
      ["Public addresses", 6],
      ["Looked up", 1],
      ["Pending", 2],
      ["Failed", 1],
      ["Unavailable", 1],
      ["Skipped or not looked up", 1],
    ]);
  });
});
