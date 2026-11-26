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

/** A whole number that may be negative, such as VirusTotal's community reputation. */
function whole(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
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

export interface VirusTotalFacts {
  /** "completed", "no_analysis" or "not_found". */
  analysisStatus: string | null;
  malicious: number | null;
  suspicious: number | null;
  harmless: number | null;
  undetected: number | null;
  timeout: number | null;
  enginesTotal: number | null;
  /** VirusTotal's community score. It can be negative. */
  reputation: number | null;
  timesSubmitted: number | null;
  categories: string[];
  threatLabel: string | null;
  threatNames: string[];
  fileName: string | null;
  fileType: string | null;
  countryCode: string | null;
  asn: number | null;
  asOwner: string | null;
  /** See links.ts: only a link of VirusTotal's own shape is ever drawn. */
  providerId: string | null;
  providerLink: string | null;
  malwareFamilies: string[];
}

export function readVirusTotalFacts(summary: Summary): VirusTotalFacts {
  return {
    analysisStatus: text(summary.analysis_status),
    malicious: count(summary.malicious),
    suspicious: count(summary.suspicious),
    harmless: count(summary.harmless),
    undetected: count(summary.undetected),
    timeout: count(summary.timeout),
    enginesTotal: count(summary.engines_total),
    reputation: whole(summary.reputation),
    timesSubmitted: count(summary.times_submitted),
    categories: texts(summary.categories),
    threatLabel: text(summary.threat_label),
    threatNames: texts(summary.threat_names),
    fileName: text(summary.file_name),
    fileType: text(summary.file_type),
    countryCode: text(summary.country_code),
    asn: count(summary.asn),
    asOwner: text(summary.as_owner),
    providerId: text(summary.provider_id),
    providerLink: text(summary.provider_link),
    malwareFamilies: texts(summary.malware_families),
  };
}

export interface ThreatFoxMatch {
  /** ThreatFox's own record number; see links.ts for the page it names. */
  id: string | null;
  ioc: string;
  iocType: string | null;
  threatType: string | null;
  malware: string | null;
  malwareAliases: string[];
  /** The reporter's own confidence, 0 to 100. It is not comparable to VirusTotal engine counts. */
  confidence: number | null;
  firstSeen: string | null;
  lastSeen: string | null;
  reporter: string | null;
  /** The reporter's address as supplied. It is shown as text and never linked. */
  reference: string | null;
  malpediaUrl: string | null;
  tags: string[];
}

export interface ThreatFoxFacts {
  matchCount: number | null;
  highestConfidence: number | null;
  /** "file_hash" when the records are IOCs tied to the hash, "indicator" for an exact match. */
  association: "file_hash" | "indicator" | null;
  matches: ThreatFoxMatch[];
  threatTypes: string[];
  malwareFamilies: string[];
}

export function readThreatFoxFacts(summary: Summary): ThreatFoxFacts {
  const matches = Array.isArray(summary.matches) ? summary.matches.filter(isRecord) : [];
  return {
    matchCount: count(summary.match_count),
    highestConfidence: count(summary.highest_confidence),
    association:
      summary.association === "file_hash" || summary.association === "indicator"
        ? summary.association
        : null,
    matches: matches.slice(0, MAX_ITEMS).flatMap((match) => {
      const ioc = text(match.ioc);
      if (ioc === null) return [];
      return [
        {
          id: text(match.id),
          ioc,
          iocType: text(match.ioc_type),
          threatType: text(match.threat_type),
          malware: text(match.malware),
          malwareAliases: texts(match.malware_aliases),
          confidence: count(match.confidence_level),
          firstSeen: text(match.first_seen),
          lastSeen: text(match.last_seen),
          reporter: text(match.reporter),
          reference: text(match.reference),
          malpediaUrl: text(match.malpedia_url),
          tags: texts(match.tags),
        },
      ];
    }),
    threatTypes: texts(summary.threat_types),
    malwareFamilies: texts(summary.malware_families),
  };
}
