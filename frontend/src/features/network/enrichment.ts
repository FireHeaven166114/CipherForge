import type {
  Enrichment,
  EnrichmentProvider,
  EnrichmentState,
  EnrichmentSummary,
} from "../../types/network";
import { CLASSIFICATION_META, type ClassificationMeta } from "../intel/classification";
import { humanize } from "./labels";

export interface EnrichmentMeta {
  label: string;
  /** A shape that tells the states apart without colour. None looks like a tick: a lookup is never a clean bill of health. */
  glyph: string;
  /** Tailwind classes, written out in full so the build can find them. */
  classes: string;
}

const NEUTRAL = "border-ink-500 bg-ink-800/70 text-ink-200";
const INFO = "border-cipher/60 cf-plate text-cipher";
const WARN = "border-warn/60 cf-plate text-warn";
const BAD = "border-bad/60 cf-plate text-bad";

export const ENRICHMENT_META: Readonly<Record<EnrichmentState, EnrichmentMeta>> = {
  not_looked_up: { label: "Not looked up", glyph: "○", classes: NEUTRAL },
  pending: { label: "Looking up", glyph: "…", classes: INFO },
  completed: { label: "Looked up", glyph: "●", classes: INFO },
  failed: { label: "Lookup failed", glyph: "✕", classes: BAD },
  unavailable: { label: "Lookup unavailable", glyph: "▲", classes: WARN },
  skipped_budget: { label: "Lookup limit reached", glyph: "▲", classes: WARN },
  disabled: { label: "Enrichment off", glyph: "–", classes: NEUTRAL },
  not_applicable: { label: "No public address", glyph: "–", classes: NEUTRAL },
};

export const NO_DATA_NOTE = "No provider returned data. This is not evidence the address is safe.";

/**
 * True only when a provider produced a score and the server does not say it rests on no evidence.
 * Without one there is nothing to show but "no data".
 */
export function hasScore(enrichment: Pick<Enrichment, "risk_score"> & { assessed?: boolean | null }): boolean {
  return enrichment.risk_score !== null && enrichment.assessed !== false;
}

/** One sentence on what the state means, in terms that never read as "safe". */
export function enrichmentNote(enrichment: Enrichment): string {
  switch (enrichment.status) {
    case "completed":
      return hasScore(enrichment)
        ? "Providers answered. The score summarises what they reported; it is a signal, not a verdict."
        : NO_DATA_NOTE;
    case "pending":
      return "The lookup is waiting for the providers.";
    case "failed":
      return enrichment.message ?? "The lookup failed.";
    case "unavailable":
      return enrichment.message ?? "No provider could be asked for this address right now.";
    case "skipped_budget":
      return "Not looked up: this session reached its limit on lookups.";
    case "disabled":
      return "External enrichment is switched off on this server.";
    case "not_applicable":
      return "The traffic involves no public address, so there is nothing to look up.";
    case "not_looked_up":
      return "This address has not been looked up. Nothing was sent to any provider.";
  }
}

const LOOKUP_STATES: readonly EnrichmentState[] = [
  "not_looked_up",
  "failed",
  "unavailable",
  "skipped_budget",
];

/** Whether "Look up address" makes sense: the server can do it, and it has not worked yet. */
export function canLookUp(enrichment: Pick<Enrichment, "status">, enrichmentEnabled: boolean): boolean {
  return enrichmentEnabled && LOOKUP_STATES.includes(enrichment.status);
}

/** The classification chip for a score, or null when the API's word is not one this console knows. */
export function classificationMeta(classification: string | null): ClassificationMeta | null {
  if (classification === null || !Object.hasOwn(CLASSIFICATION_META, classification)) return null;
  return CLASSIFICATION_META[classification as keyof typeof CLASSIFICATION_META];
}

const PROVIDER_STATUSES: Readonly<Record<string, string>> = {
  ok: "Answered",
  no_data: "No data",
  not_configured: "Not configured",
  unsupported: "Not supported",
  rate_limited: "Rate limited",
  error: "Error",
  not_queried: "Not queried",
};

export function providerStatusLabel(status: string): string {
  return Object.hasOwn(PROVIDER_STATUSES, status)
    ? (PROVIDER_STATUSES[status] ?? humanize(status))
    : humanize(status);
}

/** "AbuseIPDB: Answered, verdict malicious". The verdict is the provider's word, not ours. */
export function describeProvider(provider: EnrichmentProvider): string {
  const status = providerStatusLabel(provider.status);
  return provider.verdict === null || provider.verdict === ""
    ? `${provider.display_name}: ${status}`
    : `${provider.display_name}: ${status}, verdict ${provider.verdict}`;
}

export interface SummaryRow {
  key: string;
  label: string;
  value: number;
}

/** The counts of the enrichment summary, in the order an analyst reads them. */
export function summaryRows(summary: EnrichmentSummary): SummaryRow[] {
  return [
    { key: "total", label: "Public addresses", value: summary.total },
    { key: "completed", label: "Looked up", value: summary.completed },
    { key: "pending", label: "Pending", value: summary.pending },
    { key: "failed", label: "Failed", value: summary.failed },
    { key: "unavailable", label: "Unavailable", value: summary.unavailable },
    { key: "skipped", label: "Skipped or not looked up", value: summary.skipped },
  ];
}
