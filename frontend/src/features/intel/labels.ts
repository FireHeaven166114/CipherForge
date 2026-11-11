import type { Tone } from "../../components/StatusBadge";
import type { IndicatorStatus, IndicatorType, ProviderStatus } from "../../types/intel";

export const INDICATOR_TYPE_LABELS: Record<IndicatorType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  sha256: "SHA-256",
};

export const INDICATOR_STATUS_LABELS: Record<IndicatorStatus, { label: string; detail: string }> = {
  active: { label: "Active", detail: "At least one provider answer is still fresh." },
  stale: { label: "Stale", detail: "No provider answer is fresh; investigate again to refresh." },
};

export interface ProviderStatusMeta {
  label: string;
  tone: Tone;
  /** Used when the API sends no message of its own. */
  explanation: string;
}

export const PROVIDER_STATUS_META: Record<ProviderStatus, ProviderStatusMeta> = {
  ok: {
    label: "Answered",
    tone: "ok",
    explanation: "The provider returned evidence about this indicator.",
  },
  no_data: {
    label: "No data",
    tone: "neutral",
    explanation:
      "The provider answered but holds no reports about this indicator. That is not proof it is safe.",
  },
  not_configured: {
    label: "Not configured",
    tone: "warn",
    explanation: "No API key is set on the server for this provider, so it was not asked.",
  },
  unsupported: {
    label: "Not supported",
    tone: "neutral",
    explanation: "This provider does not handle this type of indicator.",
  },
  rate_limited: {
    label: "Rate limited",
    tone: "warn",
    explanation: "The provider refused the request because its quota was reached. Try again later.",
  },
  error: {
    label: "Error",
    tone: "bad",
    explanation: "The provider could not be queried or returned something unusable.",
  },
  not_queried: {
    label: "Not queried",
    tone: "neutral",
    explanation: "No stored answer exists. Investigate the indicator again to ask this provider.",
  },
};

/** Whether the provider actually answered, as opposed to being skipped or failing. */
export function hasAnswer(status: ProviderStatus): boolean {
  return status === "ok" || status === "no_data";
}
