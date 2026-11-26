import type {
  FacetEntry,
  Indicator,
  IndicatorPage,
  Investigation,
  Overview,
  ProviderInfo,
  ProviderView,
  SampleIndicator,
  Score,
  Stats,
} from "../types/intel";

// Example data only. Addresses are from the documentation ranges (RFC 5737) and names use the
// reserved ".test" TLD, so nothing here refers to a real host.

export const INDICATOR_ID = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";
export const PULSE_ID = "5f1a2b3c4d5e6f7a8b9c0d1e";

export function makeIndicator(overrides: Partial<Indicator> = {}): Indicator {
  return {
    indicator_id: INDICATOR_ID,
    indicator_type: "ipv4",
    indicator_value: "203.0.113.9",
    risk_score: 80,
    classification: "high",
    confidence: 90,
    first_seen: "2026-03-01T00:00:00Z",
    last_seen: "2026-05-01T10:00:00Z",
    source_count: 2,
    tags: ["scanner", "tor"],
    status: "active",
    created_at: "2026-05-01T11:00:00Z",
    scored_at: "2026-05-02T09:30:00Z",
    last_checked_at: "2026-05-02T09:30:00Z",
    ...overrides,
  };
}

export function makeAbuseIpdb(overrides: Partial<ProviderView> = {}): ProviderView {
  return {
    provider: "abuseipdb",
    display_name: "AbuseIPDB",
    status: "ok",
    freshness: "fresh",
    signal: 1,
    fetched_at: "2026-05-02T09:30:00Z",
    evidence_at: "2026-05-01T10:00:00Z",
    first_evidence_at: null,
    cache_expires_at: "2026-05-03T09:30:00Z",
    from_cache: false,
    summary: {
      confidence_score: 100,
      total_reports: 87,
      distinct_reporters: 34,
      last_reported_at: "2026-05-01T10:00:00Z",
      window_days: 90,
      is_whitelisted: false,
      is_tor: false,
      usage_type: "Data Center/Web Hosting/Transit",
      isp: "Example Hosting Ltd",
      domain: "example-hosting.test",
      country_code: "NL",
      notes: [],
    },
    tags: [],
    message: null,
    verdict: null,
    reason: null,
    ...overrides,
  };
}

export function makeOtx(overrides: Partial<ProviderView> = {}): ProviderView {
  return {
    provider: "otx",
    display_name: "AlienVault OTX",
    status: "ok",
    freshness: "fresh",
    signal: 0.55,
    fetched_at: "2026-05-02T09:30:00Z",
    evidence_at: "2026-04-20T00:00:00Z",
    first_evidence_at: "2026-03-01T00:00:00Z",
    cache_expires_at: "2026-05-03T09:30:00Z",
    from_cache: true,
    summary: {
      pulse_count: 4,
      pulses_analyzed: 4,
      top_pulses: [
        {
          id: PULSE_ID,
          name: "Example phishing campaign",
          created: "2026-03-01T00:00:00Z",
          modified: "2026-04-20T00:00:00Z",
        },
      ],
      validation: [],
      malware_families: ["Examplebot"],
      attack_ids: ["T1566", "T1059.001"],
      notes: ["OTX pulses are community-submitted reports; treat them as leads, not verdicts."],
    },
    tags: ["phishing", "c2"],
    message: null,
    verdict: null,
    reason: null,
    ...overrides,
  };
}

export function makeVirusTotal(overrides: Partial<ProviderView> = {}): ProviderView {
  return {
    provider: "virustotal",
    display_name: "VirusTotal",
    status: "ok",
    freshness: "fresh",
    signal: 0.7,
    fetched_at: "2026-05-02T09:30:00Z",
    evidence_at: "2026-05-02T06:00:00Z",
    first_evidence_at: "2026-03-01T00:00:00Z",
    cache_expires_at: "2026-05-03T09:30:00Z",
    from_cache: false,
    summary: {
      verdict: "malicious",
      analysis_status: "completed",
      malicious: 7,
      suspicious: 1,
      harmless: 55,
      undetected: 12,
      timeout: 0,
      engines_total: 75,
      reputation: -14,
      last_analysis_at: "2026-05-02T06:00:00Z",
      first_submission_at: "2026-03-01T00:00:00Z",
      times_submitted: 9,
      categories: ["phishing"],
      threat_label: "trojan.examplebot",
      threat_names: ["examplebot"],
      file_name: null,
      file_type: null,
      country_code: "NL",
      asn: 64500,
      as_owner: "Example Hosting Ltd",
      provider_id: "203.0.113.9",
      provider_link: "https://www.virustotal.com/gui/ip-address/203.0.113.9",
      malware_families: ["Examplebot"],
      notes: [],
    },
    tags: ["botnet"],
    message: null,
    verdict: "malicious",
    reason: null,
    ...overrides,
  };
}

export function makeThreatFox(overrides: Partial<ProviderView> = {}): ProviderView {
  return {
    provider: "threatfox",
    display_name: "ThreatFox",
    status: "ok",
    freshness: "fresh",
    signal: 0.9,
    fetched_at: "2026-05-02T09:30:00Z",
    evidence_at: "2026-04-28T08:00:00Z",
    first_evidence_at: "2026-04-01T08:00:00Z",
    cache_expires_at: "2026-05-02T15:30:00Z",
    from_cache: false,
    summary: {
      verdict: "malicious",
      match_count: 2,
      highest_confidence: 90,
      association: "indicator",
      matches: [
        {
          id: "1234567",
          ioc: "203.0.113.9:443",
          ioc_type: "ip:port",
          threat_type: "botnet_cc",
          malware: "Examplebot",
          malware_aliases: ["Samplebot"],
          confidence_level: 90,
          first_seen: "2026-04-01T08:00:00Z",
          last_seen: "2026-04-28T08:00:00Z",
          reporter: "example-reporter",
          reference: "https://reports.example.test/examplebot",
          malpedia_url: "https://malpedia.caad.fkie.fraunhofer.de/details/win.examplebot",
          tags: ["c2"],
        },
        {
          id: "1234568",
          ioc: "203.0.113.9:8080",
          ioc_type: "ip:port",
          threat_type: "botnet_cc",
          malware: "Examplebot",
          malware_aliases: [],
          confidence_level: 60,
          first_seen: "2026-04-10T08:00:00Z",
          last_seen: null,
          reporter: "another-reporter",
          reference: null,
          malpedia_url: null,
          tags: [],
        },
      ],
      threat_types: ["botnet_cc"],
      malware_families: ["Examplebot"],
      first_seen_at: "2026-04-01T08:00:00Z",
      last_seen_at: "2026-04-28T08:00:00Z",
      notes: ["ThreatFox records ip:port pairs; matches are made on the address alone."],
    },
    tags: ["c2"],
    message: null,
    verdict: "malicious",
    reason: null,
    ...overrides,
  };
}

/** A provider that gave no answer: `reason` says why, `status` how the card is headed. */
export function makeFailedProvider(
  provider: string,
  displayName: string,
  status: ProviderView["status"],
  reason: NonNullable<ProviderView["reason"]>,
  message: string,
): ProviderView {
  return {
    provider,
    display_name: displayName,
    status,
    freshness: null,
    signal: null,
    fetched_at: null,
    evidence_at: null,
    first_evidence_at: null,
    cache_expires_at: null,
    from_cache: false,
    summary: {},
    tags: [],
    message,
    verdict: null,
    reason,
  };
}

export function makeScore(overrides: Partial<Score> = {}): Score {
  return {
    methodology: "intel-risk-v1",
    score: 80,
    classification: "high",
    confidence: 90,
    answered_sources: 2,
    contributing_sources: 2,
    supporting_sources: 2,
    factors: [
      {
        code: "provider:abuseipdb",
        label: "AbuseIPDB evidence",
        points: 45,
        detail: "Evidence strength 1.00, recency weight 1.0 (latest activity 2026-05-01); up to 45 points.",
      },
      {
        code: "provider:otx",
        label: "AlienVault OTX evidence",
        points: 22,
        detail: "Evidence strength 0.55, recency weight 0.9 (latest activity 2026-04-20); up to 45 points.",
      },
      {
        code: "corroboration",
        label: "Independent corroboration",
        points: 8,
        detail: "2 sources independently support this indicator.",
      },
      {
        code: "malware_family",
        label: "Malware family association",
        points: 5,
        detail: "Supporting sources name 1 distinct malware family.",
      },
    ],
    uncertainty: [
      "No internal telemetry was available; this score reflects external provider evidence only.",
      "OTX pulses are community-submitted reports; treat them as leads, not verdicts.",
    ],
    recommended_actions: [
      "Prioritize investigation: search for past and present contact with this indicator.",
      "If you confirm activity, follow your incident process and consider containment (for example blocking or isolating hosts). That decision is yours; CipherForge never blocks anything automatically.",
      "Record your findings so they can be reviewed later.",
    ],
    scored_at: "2026-05-02T09:30:00Z",
    ...overrides,
  };
}

export function makeInvestigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    indicator: makeIndicator(),
    providers: [makeAbuseIpdb(), makeOtx()],
    score: makeScore(),
    internal_evidence: {
      available: false,
      message:
        "CipherForge has no internal telemetry (Sentinel, SOC, Case) connected yet, so no internal sightings are included.",
    },
    ...overrides,
  };
}

/** What the API returns when no provider is configured: every score is zero, nothing was assessed. */
export function makeNotAssessed(): Investigation {
  const notConfigured = (provider: string, displayName: string): ProviderView =>
    makeFailedProvider(
      provider,
      displayName,
      "not_configured",
      "not_configured",
      `${displayName} is not configured (no API key set).`,
    );
  return makeInvestigation({
    indicator: makeIndicator({
      indicator_value: "203.0.113.50",
      risk_score: 0,
      classification: "informational",
      confidence: 0,
      first_seen: null,
      last_seen: null,
      source_count: 0,
      tags: [],
      status: "stale",
    }),
    providers: [
      notConfigured("abuseipdb", "AbuseIPDB"),
      notConfigured("otx", "AlienVault OTX"),
      notConfigured("virustotal", "VirusTotal"),
      notConfigured("threatfox", "ThreatFox"),
    ],
    score: makeScore({
      score: 0,
      classification: "informational",
      confidence: 0,
      answered_sources: 0,
      contributing_sources: 0,
      supporting_sources: 0,
      factors: [],
      uncertainty: [
        "No internal telemetry was available; this score reflects external provider evidence only.",
        "No provider returned evidence for this indicator.",
        "AbuseIPDB is not configured, so it contributed no evidence.",
        "AlienVault OTX is not configured, so it contributed no evidence.",
        "VirusTotal is not configured, so it contributed no evidence.",
        "ThreatFox is not configured, so it contributed no evidence.",
        "Absence of reports is not proof that an indicator is safe; providers only know what has been reported to them.",
      ],
      recommended_actions: [
        "No provider answered, so CipherForge has no evidence about this indicator and cannot say whether it is safe.",
        "Configure a provider or investigate again later, and check your own telemetry in the meantime.",
      ],
    }),
  });
}

export function makePage(items: Indicator[], overrides: Partial<IndicatorPage> = {}): IndicatorPage {
  return { items, total: items.length, limit: 25, offset: 0, ...overrides };
}

export function makeStats(overrides: Partial<Stats> = {}): Stats {
  return {
    total_indicators: 12,
    by_classification: { informational: 4, low: 3, medium: 2, high: 2, critical: 1 },
    by_type: { ipv4: 6, ipv6: 1, domain: 3, url: 1, md5: 0, sha1: 0, sha256: 1 },
    lookups_last_24h: 9,
    providers: makeProviders(),
    ...overrides,
  };
}

export function makeProviders(simulated = false): ProviderInfo[] {
  return [
    {
      name: "abuseipdb",
      display_name: "AbuseIPDB",
      configured: true,
      supported_types: ["ipv4", "ipv6"],
      simulated,
    },
    {
      name: "otx",
      display_name: "AlienVault OTX",
      configured: false,
      supported_types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
      simulated,
    },
    {
      name: "virustotal",
      display_name: "VirusTotal",
      configured: false,
      supported_types: ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"],
      simulated,
    },
    {
      name: "threatfox",
      display_name: "ThreatFox",
      configured: false,
      supported_types: ["ipv4", "ipv6", "domain", "url", "md5", "sha256"],
      simulated,
    },
  ];
}

export function makeSample(overrides: Partial<SampleIndicator> = {}): SampleIndicator {
  return {
    indicator_id: INDICATOR_ID,
    indicator_type: "ipv4",
    indicator_value: "203.0.113.9",
    risk_score: 80,
    classification: "high",
    ...overrides,
  };
}

export function makeFacet(
  key: string,
  count: number,
  maxRisk: number,
  samples: SampleIndicator[] = [makeSample({ risk_score: maxRisk })],
): FacetEntry {
  return { key, count, max_risk: maxRisk, samples };
}

export const OVERVIEW_DAYS = [
  "2026-05-01",
  "2026-05-02",
  "2026-05-03",
  "2026-05-04",
  "2026-05-05",
  "2026-05-06",
  "2026-05-07",
  "2026-05-08",
  "2026-05-09",
  "2026-05-10",
  "2026-05-11",
  "2026-05-12",
  "2026-05-13",
  "2026-05-14",
] as const;

const LOOKUPS_PER_DAY = [0, 1, 0, 2, 3, 1, 4, 2, 5, 3, 6, 4, 7, 9];
const HIGH_RISK_PER_DAY = [0, 0, 0, 1, 1, 0, 2, 1, 2, 1, 2, 2, 3, 3];

/** A small, internally consistent overview: every breakdown adds up to the 12 tracked indicators. */
export function makeOverview(overrides: Partial<Overview> = {}): Overview {
  const hours = (peak: number): number[] =>
    Array.from({ length: 24 }, (_, hour) => (hour === 9 ? peak : hour === 14 ? 1 : 0));
  return {
    generated_at: "2026-05-14T12:00:00Z",
    kpis: {
      total_indicators: 12,
      new_indicators_24h: 3,
      new_indicators_prev_24h: 1,
      lookups_24h: 9,
      lookups_prev_24h: 4,
      high_risk_indicators: 3,
      critical_indicators: 1,
      not_assessed_indicators: 1,
    },
    by_classification: { informational: 4, low: 3, medium: 1, high: 2, critical: 1, not_assessed: 1 },
    by_type: { ipv4: 6, ipv6: 1, domain: 3, url: 1, md5: 0, sha1: 0, sha256: 1 },
    matrix: [
      {
        indicator_type: "ipv4",
        counts: { informational: 2, low: 1, medium: 0, high: 2, critical: 1, not_assessed: 0 },
      },
      {
        indicator_type: "ipv6",
        counts: { informational: 1, low: 0, medium: 0, high: 0, critical: 0, not_assessed: 0 },
      },
      {
        indicator_type: "domain",
        counts: { informational: 0, low: 1, medium: 1, high: 0, critical: 0, not_assessed: 1 },
      },
      {
        indicator_type: "url",
        counts: { informational: 0, low: 1, medium: 0, high: 0, critical: 0, not_assessed: 0 },
      },
      {
        indicator_type: "md5",
        counts: { informational: 0, low: 0, medium: 0, high: 0, critical: 0, not_assessed: 0 },
      },
      {
        indicator_type: "sha1",
        counts: { informational: 0, low: 0, medium: 0, high: 0, critical: 0, not_assessed: 0 },
      },
      {
        indicator_type: "sha256",
        counts: { informational: 1, low: 0, medium: 0, high: 0, critical: 0, not_assessed: 0 },
      },
    ],
    series: OVERVIEW_DAYS.map((day, index) => ({
      day,
      lookups: LOOKUPS_PER_DAY[index] ?? 0,
      high_risk_lookups: HIGH_RISK_PER_DAY[index] ?? 0,
      new_indicators: index === OVERVIEW_DAYS.length - 1 ? 3 : index % 3,
    })),
    activity: OVERVIEW_DAYS.slice(7).map((day, index) => ({ day, hours: hours(index + 2) })),
    countries: [
      makeFacet("NL", 4, 80),
      makeFacet("US", 3, 64, [
        makeSample({
          indicator_id: "7a1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
          indicator_value: "198.51.100.7",
          risk_score: 64,
          classification: "high",
        }),
      ]),
      makeFacet("DE", 1, 12),
    ],
    malware_families: [makeFacet("Examplebot", 2, 80), makeFacet("Sampleloader", 1, 45)],
    attack_techniques: [makeFacet("T1566", 2, 80), makeFacet("T1059.001", 1, 80)],
    tags: [makeFacet("scanner", 3, 80), makeFacet("tor", 2, 80), makeFacet("phishing", 1, 55)],
    top_risk: [
      makeIndicator(),
      makeIndicator({
        indicator_id: "7a1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e",
        indicator_value: "198.51.100.7",
        risk_score: 64,
        classification: "high",
        tags: ["scanner"],
      }),
    ],
    recent: [
      makeIndicator({
        indicator_id: "1b2c3d4e-5f6a-4b7c-8d9e-0a1b2c3d4e5f",
        indicator_type: "domain",
        indicator_value: "login.example.test",
        risk_score: 0,
        classification: "informational",
        confidence: 0,
        tags: [],
        status: "stale",
      }),
      makeIndicator(),
    ],
    providers: makeProviders(),
    scope: {
      series_days: 14,
      activity_days: 7,
      lookups_scanned: 38,
      lookups_truncated: false,
      answers_scanned: 12,
      answers_truncated: false,
    },
    ...overrides,
  };
}
