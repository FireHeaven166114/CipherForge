import { describe, expect, it } from "vitest";

import {
  makeIndicator,
  makeInvestigation,
  makeNotAssessed,
  makeOverview,
  makePage,
  makeStats,
} from "../test/fixtures";
import {
  isDeleteResult,
  isIndicator,
  isIndicatorPage,
  isInvestigation,
  isOverview,
  isStats,
} from "./intelGuards";

function without(value: object, key: string): unknown {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  delete copy[key];
  return copy;
}

describe("isDeleteResult", () => {
  it("accepts what the API reports and rejects anything else", () => {
    const valid = { deleted: ["a"], not_found: [], observations_removed: 3 };
    expect(isDeleteResult(valid)).toBe(true);
    expect(isDeleteResult({ ...valid, deleted: [], observations_removed: 0 })).toBe(true);
    for (const key of Object.keys(valid)) expect(isDeleteResult(without(valid, key))).toBe(false);
    expect(isDeleteResult({ ...valid, deleted: "a" })).toBe(false);
    expect(isDeleteResult({ ...valid, not_found: [1] })).toBe(false);
    expect(isDeleteResult({ ...valid, observations_removed: -1 })).toBe(false);
    expect(isDeleteResult({ ...valid, observations_removed: "3" })).toBe(false);
    expect(isDeleteResult(null)).toBe(false);
  });
});

describe("isInvestigation", () => {
  it("accepts an assessed and a not-assessed investigation", () => {
    expect(isInvestigation(makeInvestigation())).toBe(true);
    expect(isInvestigation(makeNotAssessed())).toBe(true);
  });

  it("rejects values that are not objects", () => {
    for (const value of [null, undefined, "text", 42, [], [makeInvestigation()]]) {
      expect(isInvestigation(value)).toBe(false);
    }
  });

  it("rejects a response with a missing or malformed part", () => {
    const valid = makeInvestigation();
    const broken: unknown[] = [
      without(valid, "score"),
      without(valid, "providers"),
      without(valid, "internal_evidence"),
      { ...valid, providers: "none" },
      { ...valid, providers: [{ provider: "otx" }] },
      { ...valid, score: { ...valid.score, classification: "severe" } },
      { ...valid, score: { ...valid.score, factors: [{ code: "x", points: "many" }] } },
      { ...valid, score: { ...valid.score, answered_sources: -1 } },
      { ...valid, indicator: { ...valid.indicator, indicator_type: "mac" } },
      { ...valid, indicator: { ...valid.indicator, tags: [1, 2] } },
      { ...valid, internal_evidence: { available: "no", message: "x" } },
    ];

    for (const value of broken) expect(isInvestigation(value)).toBe(false);
  });

  it("rejects a provider view whose summary or status is not what the UI expects", () => {
    const valid = makeInvestigation();
    const provider = valid.providers[0];
    expect(provider).toBeDefined();
    const broken = [
      { ...provider, status: "exploded" },
      { ...provider, summary: [1, 2, 3] },
      { ...provider, summary: null },
      { ...provider, signal: Number.NaN },
      { ...provider, signal: "0.5" },
      { ...provider, freshness: "old" },
      { ...provider, from_cache: "yes" },
    ];

    for (const value of broken) {
      expect(isInvestigation({ ...valid, providers: [value] })).toBe(false);
    }
  });
});

describe("isIndicator", () => {
  it("requires every field the table and detail views read", () => {
    const valid = makeIndicator();
    expect(isIndicator(valid)).toBe(true);
    for (const key of Object.keys(valid)) expect(isIndicator(without(valid, key))).toBe(false);
  });
});

describe("isIndicatorPage", () => {
  it("accepts a page and rejects one with an invalid item", () => {
    expect(isIndicatorPage(makePage([makeIndicator()]))).toBe(true);
    expect(isIndicatorPage(makePage([]))).toBe(true);
    expect(isIndicatorPage({ ...makePage([]), items: [{ indicator_id: "x" }] })).toBe(false);
    expect(isIndicatorPage({ ...makePage([]), total: "3" })).toBe(false);
    expect(isIndicatorPage({ ...makePage([]), offset: -1 })).toBe(false);
  });
});

describe("isStats", () => {
  it("accepts stats and rejects malformed counts or providers", () => {
    expect(isStats(makeStats())).toBe(true);
    expect(isStats({ ...makeStats(), by_type: { ipv4: "six" } })).toBe(false);
    expect(isStats({ ...makeStats(), by_classification: [] })).toBe(false);
    expect(isStats({ ...makeStats(), lookups_last_24h: -3 })).toBe(false);
    expect(isStats({ ...makeStats(), providers: [{ name: "otx" }] })).toBe(false);
    expect(
      isStats({
        ...makeStats(),
        providers: [
          {
            name: "otx",
            display_name: "OTX",
            configured: true,
            supported_types: ["mac"],
            simulated: false,
          },
        ],
      }),
    ).toBe(false);
  });

  it("requires every provider to say whether it is simulated", () => {
    const [provider] = makeStats().providers;
    expect(provider).toBeDefined();
    expect(isStats({ ...makeStats(), providers: [without(provider as object, "simulated")] })).toBe(
      false,
    );
    expect(isStats({ ...makeStats(), providers: [{ ...provider, simulated: "no" }] })).toBe(false);
  });
});

describe("isOverview", () => {
  it("accepts a complete overview, including an empty one", () => {
    expect(isOverview(makeOverview())).toBe(true);
    expect(
      isOverview(
        makeOverview({
          matrix: [],
          series: [],
          activity: [],
          countries: [],
          malware_families: [],
          attack_techniques: [],
          tags: [],
          top_risk: [],
          recent: [],
        }),
      ),
    ).toBe(true);
  });

  it("requires every section the dashboard reads", () => {
    const valid = makeOverview();
    for (const key of Object.keys(valid)) expect(isOverview(without(valid, key))).toBe(false);
  });

  it("rejects malformed sections", () => {
    const valid = makeOverview();
    const broken: unknown[] = [
      { ...valid, kpis: { ...valid.kpis, lookups_24h: -1 } },
      { ...valid, kpis: without(valid.kpis, "critical_indicators") },
      { ...valid, by_classification: { high: "many" } },
      { ...valid, matrix: [{ indicator_type: "mac", counts: {} }] },
      { ...valid, series: [{ day: "yesterday", lookups: 1, high_risk_lookups: 0, new_indicators: 0 }] },
      { ...valid, series: [{ day: "2026-05-01", lookups: 1.5, high_risk_lookups: 0, new_indicators: 0 }] },
      { ...valid, activity: [{ day: "2026-05-01", hours: [1, 2, 3] }] },
      { ...valid, activity: [{ day: "2026-05-01", hours: Array.from({ length: 24 }, () => "x") }] },
      { ...valid, countries: [{ key: "NL", count: 1, max_risk: 10 }] },
      { ...valid, countries: [{ key: "NL", count: 1, max_risk: 10, samples: [{ indicator_id: "x" }] }] },
      { ...valid, top_risk: [{ indicator_id: "x" }] },
      { ...valid, scope: { ...valid.scope, lookups_truncated: "no" } },
      { ...valid, providers: [{ name: "otx" }] },
    ];

    for (const value of broken) expect(isOverview(value)).toBe(false);
  });
});
