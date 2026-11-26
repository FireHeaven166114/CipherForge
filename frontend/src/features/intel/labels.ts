import type { Tone } from "../../components/StatusBadge";
import type {
  IndicatorStatus,
  IndicatorType,
  ProviderReason,
  ProviderStatus,
  ProviderVerdict,
  ProviderView,
} from "../../types/intel";

export const INDICATOR_TYPE_LABELS: Record<IndicatorType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  md5: "MD5",
  sha1: "SHA-1",
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

export interface ProviderVerdictMeta {
  label: string;
  tone: Tone;
  /** What the provider's word means, and what it does not. */
  explanation: string;
}

/**
 * The providers' own conclusions. Only a malicious or suspicious verdict gets a warning colour;
 * a harmless, unknown or not-found answer is never drawn as a green "safe" mark, because it only
 * says what the provider knows.
 */
export const PROVIDER_VERDICT_META: Record<ProviderVerdict, ProviderVerdictMeta> = {
  malicious: {
    label: "Malicious",
    tone: "bad",
    explanation: "The provider's own data rates this indicator malicious.",
  },
  suspicious: {
    label: "Suspicious",
    tone: "warn",
    explanation: "The provider's own data points to this indicator, with less certainty.",
  },
  harmless: {
    label: "Harmless",
    tone: "neutral",
    explanation:
      "The provider found nothing against this indicator. That is its opinion at the time of the analysis, not proof that the indicator is safe.",
  },
  unknown: {
    label: "Unknown",
    tone: "neutral",
    explanation: "The provider holds a record but has no verdict for this indicator yet.",
  },
  not_found: {
    label: "Not found",
    tone: "neutral",
    explanation:
      "The provider has no record of this indicator. That is not proof that the indicator is safe.",
  },
};

export interface ProviderReasonMeta {
  label: string;
  tone: Tone;
  /** Used when the API sends no message of its own. */
  explanation: string;
  /** Whether asking again can help. A missing or rejected key needs an administrator instead. */
  retryable: boolean;
}

export const PROVIDER_REASON_META: Record<ProviderReason, ProviderReasonMeta> = {
  not_configured: {
    label: "Not configured",
    tone: "warn",
    explanation: "No API key is set on the server for this provider, so it was not asked.",
    retryable: false,
  },
  invalid_input: {
    label: "Invalid input",
    tone: "bad",
    explanation: "The provider rejected this indicator as malformed.",
    retryable: false,
  },
  auth_failed: {
    label: "Authentication failure",
    tone: "bad",
    explanation:
      "The provider rejected the API key set on the server. An administrator needs to check it.",
    retryable: false,
  },
  rate_limited: {
    label: "Rate limited",
    tone: "warn",
    explanation: "The provider's request quota was reached. Try again later.",
    retryable: true,
  },
  timeout: {
    label: "Timeout",
    tone: "warn",
    explanation: "The provider did not answer in time.",
    retryable: true,
  },
  unavailable: {
    label: "Provider unavailable",
    tone: "warn",
    explanation: "The provider could not be reached or reported a temporary failure.",
    retryable: true,
  },
  malformed_response: {
    label: "Malformed response",
    tone: "bad",
    explanation: "The provider answered with data CipherForge could not read.",
    retryable: true,
  },
};

/** A failed lookup that asking again could fix. */
export function canRetry(provider: Pick<ProviderView, "reason">): boolean {
  return provider.reason !== null && PROVIDER_REASON_META[provider.reason].retryable;
}
