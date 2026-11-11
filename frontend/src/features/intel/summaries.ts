// Providers return free text and lists that anyone can influence (OTX pulse names, ISP names).
// These readers keep only the fields the UI knows about, check their types and cap their size.
// Everything they return is rendered as plain text.

type Summary = Record<string, unknown>;

const MAX_ITEMS = 10;
const MAX_TEXT_LENGTH = 300;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.slice(0, MAX_TEXT_LENGTH) : null;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** Null when the provider did not say, which is different from "no". */
function flag(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function texts(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => text(item))
    .filter((item): item is string => item !== null)
    .slice(0, MAX_ITEMS);
}

/** Caveats the provider adapter attached to its answer, such as "treat pulses as leads". */
export function readNotes(summary: Summary): string[] {
  return texts(summary.notes);
}

export interface AbuseIpdbFacts {
  confidenceScore: number | null;
  totalReports: number | null;
  distinctReporters: number | null;
  lastReportedAt: string | null;
  windowDays: number | null;
  isWhitelisted: boolean | null;
  isTor: boolean | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  countryCode: string | null;
}

export function readAbuseIpdbFacts(summary: Summary): AbuseIpdbFacts {
  return {
    confidenceScore: count(summary.confidence_score),
    totalReports: count(summary.total_reports),
    distinctReporters: count(summary.distinct_reporters),
    lastReportedAt: text(summary.last_reported_at),
    windowDays: count(summary.window_days),
    isWhitelisted: flag(summary.is_whitelisted),
    isTor: flag(summary.is_tor),
    usageType: text(summary.usage_type),
    isp: text(summary.isp),
    domain: text(summary.domain),
    countryCode: text(summary.country_code),
  };
}

export interface OtxPulse {
  /** Only present when the API validated it as a pulse id; see links.ts for the URL. */
  id: string | null;
  name: string;
  created: string | null;
  modified: string | null;
}

export interface OtxValidation {
  source: string | null;
  message: string | null;
}

export interface OtxFacts {
  pulseCount: number | null;
  pulsesAnalyzed: number | null;
  pulses: OtxPulse[];
  validation: OtxValidation[];
  malwareFamilies: string[];
  attackIds: string[];
}

export function readOtxFacts(summary: Summary): OtxFacts {
  const pulses = Array.isArray(summary.top_pulses) ? summary.top_pulses.filter(isRecord) : [];
  const validation = Array.isArray(summary.validation) ? summary.validation.filter(isRecord) : [];
  return {
    pulseCount: count(summary.pulse_count),
    pulsesAnalyzed: count(summary.pulses_analyzed),
    pulses: pulses.slice(0, MAX_ITEMS).map((pulse) => ({
      id: text(pulse.id),
      name: text(pulse.name) ?? "(unnamed pulse)",
      created: text(pulse.created),
      modified: text(pulse.modified),
    })),
    validation: validation
      .slice(0, MAX_ITEMS)
      .map((entry) => ({ source: text(entry.source), message: text(entry.message) }))
      .filter((entry) => entry.source !== null || entry.message !== null),
    malwareFamilies: texts(summary.malware_families),
    attackIds: texts(summary.attack_ids),
  };
}
