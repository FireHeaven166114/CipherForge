import { describe, expect, it } from "vitest";

import {
  readAbuseIpdbFacts,
  readNotes,
  readOtxFacts,
  readThreatFoxFacts,
  readVirusTotalFacts,
} from "./summaries";
import { makeAbuseIpdb, makeOtx, makeThreatFox, makeVirusTotal } from "../../test/fixtures";

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

describe("readVirusTotalFacts", () => {
  it("reads the engine counts, reputation, labels and the link the adapter provides", () => {
    expect(readVirusTotalFacts(makeVirusTotal().summary)).toEqual({
      analysisStatus: "completed",
      malicious: 7,
      suspicious: 1,
      harmless: 55,
      undetected: 12,
      timeout: 0,
      enginesTotal: 75,
      reputation: -14,
      timesSubmitted: 9,
      categories: ["phishing"],
      threatLabel: "trojan.examplebot",
      threatNames: ["examplebot"],
      fileName: null,
      fileType: null,
      countryCode: "NL",
      asn: 64500,
      asOwner: "Example Hosting Ltd",
      providerId: "203.0.113.9",
      providerLink: "https://www.virustotal.com/gui/ip-address/203.0.113.9",
      malwareFamilies: ["Examplebot"],
    });
  });

  it("keeps a negative reputation but drops negative counts", () => {
    const facts = readVirusTotalFacts({ reputation: -250, malicious: -1, harmless: -3, timeout: -1 });
    expect(facts.reputation).toBe(-250);
    expect(facts.malicious).toBeNull();
    expect(facts.harmless).toBeNull();
    expect(facts.timeout).toBeNull();
  });

  it("ignores values of the wrong type instead of showing them", () => {
    const facts = readVirusTotalFacts({
      analysis_status: 3,
      malicious: "7",
      reputation: 1.5,
      engines_total: Number.POSITIVE_INFINITY,
      categories: "phishing",
      threat_names: [{ html: "<b>x</b>" }, "", "ok"],
      threat_label: { nested: true },
      asn: "64500",
      provider_link: ["https://www.virustotal.com/gui/domain/example.net"],
      malware_families: null,
    });

    expect(facts).toMatchObject({
      analysisStatus: null,
      malicious: null,
      reputation: null,
      enginesTotal: null,
      categories: [],
      threatNames: ["ok"],
      threatLabel: null,
      asn: null,
      providerLink: null,
      malwareFamilies: [],
    });
  });

  it("limits the length of text and the number of entries", () => {
    const facts = readVirusTotalFacts({
      threat_label: "L".repeat(5000),
      categories: Array.from({ length: 50 }, (_, index) => `category ${index}`),
    });
    expect(facts.threatLabel).toHaveLength(300);
    expect(facts.categories).toHaveLength(10);
  });
});

describe("readThreatFoxFacts", () => {
  it("reads the records, the reporter's confidence and the association", () => {
    const facts = readThreatFoxFacts(makeThreatFox().summary);

    expect(facts).toMatchObject({
      matchCount: 2,
      highestConfidence: 90,
      association: "indicator",
      threatTypes: ["botnet_cc"],
      malwareFamilies: ["Examplebot"],
    });
    expect(facts.matches).toHaveLength(2);
    expect(facts.matches[0]).toEqual({
      id: "1234567",
      ioc: "203.0.113.9:443",
      iocType: "ip:port",
      threatType: "botnet_cc",
      malware: "Examplebot",
      malwareAliases: ["Samplebot"],
      confidence: 90,
      firstSeen: "2026-04-01T08:00:00Z",
      lastSeen: "2026-04-28T08:00:00Z",
      reporter: "example-reporter",
      reference: "https://reports.example.test/examplebot",
      malpediaUrl: "https://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot",
      tags: ["c2"],
    });
    expect(facts.matches[1]).toMatchObject({ id: "1234568", lastSeen: null, reference: null });
  });

  it("knows two associations and treats anything else as unknown", () => {
    expect(readThreatFoxFacts({ association: "file_hash" }).association).toBe("file_hash");
    expect(readThreatFoxFacts({ association: "indicator" }).association).toBe("indicator");
    expect(readThreatFoxFacts({ association: "guess" }).association).toBeNull();
    expect(readThreatFoxFacts({}).association).toBeNull();
  });

  it("drops a record without an indicator and survives a malformed summary", () => {
    const facts = readThreatFoxFacts({
      match_count: "many",
      highest_confidence: -5,
      matches: ["x", null, 3, {}, { ioc: "" }, { ioc: 7 }, { ioc: "198.51.100.1:80", confidence_level: "high" }],
      threat_types: "botnet_cc",
      malware_families: [1, null],
    });

    expect(facts.matchCount).toBeNull();
    expect(facts.highestConfidence).toBeNull();
    expect(facts.matches).toEqual([
      expect.objectContaining({ ioc: "198.51.100.1:80", confidence: null, id: null, tags: [] }),
    ]);
    expect(facts.threatTypes).toEqual([]);
    expect(facts.malwareFamilies).toEqual([]);
  });

  it("limits how many records are kept", () => {
    const matches = Array.from({ length: 40 }, (_, index) => ({ ioc: `198.51.100.${index}:80` }));
    expect(readThreatFoxFacts({ matches }).matches).toHaveLength(10);
  });
});

describe("readNotes", () => {
  it("keeps only non-empty strings", () => {
    expect(readNotes({ notes: ["a", "", 3, null, "b"] })).toEqual(["a", "b"]);
    expect(readNotes({ notes: "a" })).toEqual([]);
    expect(readNotes({})).toEqual([]);
  });
});
