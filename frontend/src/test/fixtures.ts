import type {
  Indicator,
  IndicatorPage,
  Investigation,
  ProviderView,
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
    ...overrides,
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
  const notConfigured = (provider: string, displayName: string): ProviderView => ({
    provider,
    display_name: displayName,
    status: "not_configured",
    freshness: null,
    signal: null,
    fetched_at: null,
    evidence_at: null,
    first_evidence_at: null,
    cache_expires_at: null,
    from_cache: false,
    summary: {},
    tags: [],
    message: `${displayName} is not configured (no API key set).`,
  });
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
    providers: [notConfigured("abuseipdb", "AbuseIPDB"), notConfigured("otx", "AlienVault OTX")],
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
    by_type: { ipv4: 6, ipv6: 1, domain: 3, url: 1, sha256: 1 },
    lookups_last_24h: 9,
    providers: [
      {
        name: "abuseipdb",
        display_name: "AbuseIPDB",
        configured: true,
        supported_types: ["ipv4", "ipv6"],
      },
      {
        name: "otx",
        display_name: "AlienVault OTX",
        configured: false,
        supported_types: ["ipv4", "ipv6", "domain", "url", "sha256"],
      },
    ],
    ...overrides,
  };
}
