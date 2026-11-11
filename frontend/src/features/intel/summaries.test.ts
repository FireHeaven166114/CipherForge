import { describe, expect, it } from "vitest";

import { readAbuseIpdbFacts, readNotes, readOtxFacts } from "./summaries";
import { makeAbuseIpdb, makeOtx } from "../../test/fixtures";

describe("readAbuseIpdbFacts", () => {
  it("reads the facts the adapter provides", () => {
    expect(readAbuseIpdbFacts(makeAbuseIpdb().summary)).toEqual({
      confidenceScore: 100,
      totalReports: 87,
      distinctReporters: 34,
      lastReportedAt: "2026-05-01T10:00:00Z",
      windowDays: 90,
      isWhitelisted: false,
      isTor: false,
      usageType: "Data Center/Web Hosting/Transit",
      isp: "Example Hosting Ltd",
      domain: "example-hosting.test",
      countryCode: "NL",
    });
  });

  it("ignores values of the wrong type instead of showing them", () => {
    const facts = readAbuseIpdbFacts({
      confidence_score: "100",
      total_reports: -4,
      distinct_reporters: Number.NaN,
      isp: { html: "<b>x</b>" },
      domain: "",
      is_tor: "true",
      is_whitelisted: 1,
    });

    expect(facts).toMatchObject({
      confidenceScore: null,
      totalReports: null,
      distinctReporters: null,
      isp: null,
      domain: null,
      isTor: null,
      isWhitelisted: null,
    });
  });

  it("caps the length of free text", () => {
    const facts = readAbuseIpdbFacts({ isp: "A".repeat(5000) });
    expect(facts.isp).toHaveLength(300);
  });
});

describe("readOtxFacts", () => {
  it("reads pulses, validation entries, families and technique ids", () => {
    const facts = readOtxFacts(
      makeOtx({
        summary: {
          ...makeOtx().summary,
          validation: [{ source: "whitelist", message: "Listed as a known good domain" }],
        },
      }).summary,
    );

    expect(facts.pulseCount).toBe(4);
    expect(facts.pulsesAnalyzed).toBe(4);
    expect(facts.pulses).toEqual([
      {
        id: "5f1a2b3c4d5e6f7a8b9c0d1e",
        name: "Example phishing campaign",
        created: "2026-03-01T00:00:00Z",
        modified: "2026-04-20T00:00:00Z",
      },
    ]);
    expect(facts.validation).toEqual([
      { source: "whitelist", message: "Listed as a known good domain" },
    ]);
    expect(facts.malwareFamilies).toEqual(["Examplebot"]);
    expect(facts.attackIds).toEqual(["T1566", "T1059.001"]);
  });

  it("survives a malformed summary", () => {
    const facts = readOtxFacts({
      top_pulses: ["x", null, 3, { id: 7, name: 9 }],
      validation: [{}, "x", { source: "", message: "" }],
      malware_families: "Examplebot",
      attack_ids: [1, null, "T1566"],
    });

    expect(facts.pulses).toEqual([{ id: null, name: "(unnamed pulse)", created: null, modified: null }]);
    expect(facts.validation).toEqual([]);
    expect(facts.malwareFamilies).toEqual([]);
    expect(facts.attackIds).toEqual(["T1566"]);
  });

  it("limits how many entries are kept", () => {
    const pulses = Array.from({ length: 50 }, (_, index) => ({ id: null, name: `pulse ${index}` }));
    expect(readOtxFacts({ top_pulses: pulses }).pulses).toHaveLength(10);
  });
});

describe("readNotes", () => {
  it("keeps only non-empty strings", () => {
    expect(readNotes({ notes: ["a", "", 3, null, "b"] })).toEqual(["a", "b"]);
    expect(readNotes({ notes: "a" })).toEqual([]);
    expect(readNotes({})).toEqual([]);
  });
});
