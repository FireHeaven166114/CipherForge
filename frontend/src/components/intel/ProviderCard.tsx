import type { ReactNode } from "react";

import { formatStrength, plural } from "../../features/intel/format";
import {
  PROVIDER_REASON_META,
  PROVIDER_STATUS_META,
  PROVIDER_VERDICT_META,
  canRetry,
  hasAnswer,
} from "../../features/intel/labels";
import {
  attackTechniqueUrl,
  defang,
  malpediaUrl,
  otxPulseUrl,
  threatFoxIocUrl,
  virusTotalUrl,
} from "../../features/intel/links";
import {
  type AbuseIpdbFacts,
  type OtxFacts,
  type ThreatFoxFacts,
  type VirusTotalFacts,
  readAbuseIpdbFacts,
  readNotes,
  readOtxFacts,
  readThreatFoxFacts,
  readVirusTotalFacts,
} from "../../features/intel/summaries";
import type { ProviderView } from "../../types/intel";
import BarMeter from "../BarMeter";
import Card from "../Card";
import ChipList from "../ChipList";
import DateTime from "../DateTime";
import FactList, { type Fact } from "../FactList";
import StatusBadge from "../StatusBadge";
import { BUTTON, LINK } from "../styles";

const FRESHNESS_TEXT = {
  fresh: "Fresh (inside the provider's cache window)",
  stale: "Stale (older than the cache window; investigate again to refresh)",
} as const;

// At least 24 px tall: two of these that wrap onto separate rows are otherwise closer than the
// minimum target size and spacing (WCAG 2.5.8) allow. An inline block, not a flex box, so that a
// very long name still wraps inside the link.
function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`${LINK} inline-block min-h-6 max-w-full py-1 wrap-anywhere`}
    >
      {children}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

function yesNo(value: boolean | null): string | null {
  if (value === null) return null;
  return value ? "Yes" : "No";
}

function StrengthMeter({ signal }: { signal: number | null }) {
  if (signal === null) return <>{formatStrength(null)}</>;
  return (
    <div>
      <div className="flex items-center gap-3">
        <div className="w-28 min-w-0 shrink">
          <BarMeter percent={signal * 100} fillClass="fill-cipher" />
        </div>
        <span className="tabular-nums">{formatStrength(signal)}</span>
      </div>
      <p className="mt-0.5 text-xs text-ink-300">
        0 to 1: how strongly this provider's data points to malicious activity. It is not a
        probability.
      </p>
    </div>
  );
}

/** What each provider calls the first and the latest sign of activity. */
const ACTIVITY_LABELS: Record<string, { latest: string; first: string }> = {
  virustotal: { latest: "Last analysed", first: "First submitted" },
  threatfox: { latest: "Last seen", first: "First seen" },
};
const DEFAULT_ACTIVITY_LABELS = { latest: "Latest activity", first: "First activity" };

function commonFacts(provider: ProviderView): Fact[] {
  const hasEvidence = provider.status === "ok";
  const activity = ACTIVITY_LABELS[provider.provider] ?? DEFAULT_ACTIVITY_LABELS;
  return [
    {
      label: "Freshness",
      value: provider.freshness ? FRESHNESS_TEXT[provider.freshness] : null,
    },
    {
      label: "Evidence strength",
      value: hasEvidence ? <StrengthMeter signal={provider.signal} /> : null,
    },
    {
      label: activity.latest,
      value: hasEvidence ? <DateTime value={provider.evidence_at} fallback="Not reported" /> : null,
    },
    {
      label: activity.first,
      value: provider.first_evidence_at ? <DateTime value={provider.first_evidence_at} /> : null,
    },
    { label: "Checked", value: <DateTime value={provider.fetched_at} fallback="Unknown" /> },
    {
      label: "Source",
      value: provider.from_cache
        ? "Stored answer from an earlier lookup"
        : "Queried live for this lookup",
    },
    {
      label: "Answer valid until",
      value: provider.cache_expires_at ? <DateTime value={provider.cache_expires_at} /> : null,
    },
  ];
}

function abuseIpdbFacts(facts: AbuseIpdbFacts): Fact[] {
  return [
    {
      label: "Abuse confidence",
      value:
        facts.confidenceScore === null
          ? null
          : `${facts.confidenceScore} / 100 (AbuseIPDB's own measure, separate from the CipherForge score)`,
    },
    { label: "Reports", value: facts.totalReports },
    { label: "Distinct reporters", value: facts.distinctReporters },
    {
      label: "Report window",
      value: facts.windowDays === null ? null : `Last ${facts.windowDays} days`,
    },
    {
      label: "Last reported",
      value: facts.lastReportedAt ? <DateTime value={facts.lastReportedAt} /> : null,
    },
    { label: "Whitelisted", value: yesNo(facts.isWhitelisted) },
    { label: "Tor exit node", value: yesNo(facts.isTor) },
    { label: "Usage type", value: facts.usageType },
    { label: "ISP", value: facts.isp },
    { label: "Domain", value: facts.domain },
    {
      label: "IP geolocation",
      value: facts.countryCode
        ? `${facts.countryCode} (approximate; it does not show who is behind the traffic)`
        : null,
    },
  ];
}

function otxFacts(facts: OtxFacts): Fact[] {
  const analysed =
    facts.pulsesAnalyzed !== null && facts.pulsesAnalyzed !== facts.pulseCount
      ? `, ${facts.pulsesAnalyzed} analysed`
      : "";
  return [
    {
      label: "Pulses",
      value: facts.pulseCount === null ? null : `${facts.pulseCount} reference this indicator${analysed}`,
    },
    {
      label: "Top pulses",
      value:
        facts.pulses.length === 0 ? null : (
          <ul role="list" className="space-y-1">
            {facts.pulses.map((pulse, index) => {
              const href = otxPulseUrl(pulse.id);
              const updated = pulse.modified ?? pulse.created;
              return (
                <li key={`${pulse.id ?? pulse.name}:${index}`}>
                  {href ? <ExternalLink href={href}>{pulse.name}</ExternalLink> : pulse.name}
                  {updated ? (
                    <span className="block text-xs text-ink-300">
                      Updated <DateTime value={updated} />
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        ),
    },
    {
      label: "Validation",
      value:
        facts.validation.length === 0 ? null : (
          <ul role="list" className="space-y-1">
            {facts.validation.map((entry, index) => (
              <li key={`${entry.source ?? ""}:${index}`}>
                {[entry.source, entry.message].filter(Boolean).join(": ")}
              </li>
            ))}
          </ul>
        ),
    },
    {
      label: "Malware families",
      value:
        facts.malwareFamilies.length === 0 ? null : (
          <ChipList items={facts.malwareFamilies} label="Malware families named by OTX pulses" />
        ),
    },
    {
      label: "ATT&CK techniques",
      value:
        facts.attackIds.length === 0 ? null : (
          <ul role="list" aria-label="ATT&CK techniques named by OTX pulses" className="flex flex-wrap gap-x-3 gap-y-1">
            {facts.attackIds.map((id) => {
              const href = attackTechniqueUrl(id);
              return (
                <li key={id} className="min-w-0 max-w-full wrap-anywhere">
                  {href ? <ExternalLink href={href}>{id}</ExternalLink> : id}
                </li>
              );
            })}
          </ul>
        ),
    },
  ];
}

const VIRUSTOTAL_ANALYSIS_TEXT: Record<string, string> = {
  completed: "Completed: antivirus and security engines have examined it",
  no_analysis: "VirusTotal holds a record but no engine results for it yet",
  not_found: "VirusTotal has no record of it",
};

/** "24 malicious, 2 suspicious, 40 harmless, 4 undetected (70 engines)". */
function engineResults(facts: VirusTotalFacts): string | null {
  if (facts.malicious === null && facts.suspicious === null) return null;
  const parts = [
    `${facts.malicious ?? 0} malicious`,
    `${facts.suspicious ?? 0} suspicious`,
    `${facts.harmless ?? 0} harmless`,
    `${facts.undetected ?? 0} undetected`,
  ];
  if (facts.timeout !== null && facts.timeout > 0) parts.push(`${facts.timeout} timed out`);
  const total = facts.enginesTotal === null ? "" : ` (${plural(facts.enginesTotal, "engine")})`;
  return `${parts.join(", ")}${total}`;
}

function virusTotalFacts(facts: VirusTotalFacts): Fact[] {
  const link = virusTotalUrl(facts.providerLink);
  const file = [facts.fileName, facts.fileType].filter(Boolean).join(" · ");
  const network = [
    facts.asn === null ? null : `AS${facts.asn}`,
    facts.asOwner,
    facts.countryCode,
  ]
    .filter(Boolean)
    .join(" · ");
  return [
    { label: "Engine results", value: engineResults(facts) },
    {
      label: "Analysis",
      value: facts.analysisStatus ? (VIRUSTOTAL_ANALYSIS_TEXT[facts.analysisStatus] ?? null) : null,
    },
    {
      label: "Reputation",
      value:
        facts.reputation === null
          ? null
          : `${facts.reputation} (VirusTotal community score; below zero is worse)`,
    },
    { label: "Threat label", value: facts.threatLabel },
    {
      label: "Threat names",
      value:
        facts.threatNames.length === 0 ? null : (
          <ChipList items={facts.threatNames} label="Threat names reported by VirusTotal" />
        ),
    },
    {
      label: "Malware families",
      value:
        facts.malwareFamilies.length === 0 ? null : (
          <ChipList items={facts.malwareFamilies} label="Malware families named by VirusTotal" />
        ),
    },
    {
      label: "Categories",
      value:
        facts.categories.length === 0 ? null : (
          <ChipList items={facts.categories} label="Categories assigned by VirusTotal engines" />
        ),
    },
    { label: "File", value: file || null },
    { label: "Times submitted", value: facts.timesSubmitted },
    { label: "Network", value: network || null },
    { label: "Record ID", value: facts.providerId },
    {
      label: "VirusTotal page",
      value: link ? <ExternalLink href={link}>Open the VirusTotal report</ExternalLink> : null,
    },
  ];
}

function threatFoxMatches(facts: ThreatFoxFacts): ReactNode {
  if (facts.matches.length === 0) return null;
  return (
    <ul role="list" className="space-y-2">
      {facts.matches.map((match, index) => {
        const recordUrl = threatFoxIocUrl(match.id);
        const malpedia = malpediaUrl(match.malpediaUrl);
        const family = [match.malware, ...match.malwareAliases.map((alias) => `aka ${alias}`)]
          .filter(Boolean)
          .join(", ");
        return (
          <li
            key={`${match.id ?? match.ioc}:${index}`}
            className="space-y-1 rounded-control border border-white/10 bg-ink-900/40 p-2.5"
          >
            <p className="font-mono text-xs text-ink-50 wrap-anywhere">{match.ioc}</p>
            <p className="text-xs text-ink-200">
              {[match.iocType, match.threatType, family || null].filter(Boolean).join(" · ")}
            </p>
            {match.confidence === null ? null : (
              <p className="text-xs">
                Confidence {match.confidence} / 100{" "}
                <span className="text-ink-300">(assigned by the reporter)</span>
              </p>
            )}
            {match.firstSeen ? (
              <p className="text-xs">
                First seen <DateTime value={match.firstSeen} />
              </p>
            ) : null}
            {match.lastSeen ? (
              <p className="text-xs">
                Last seen <DateTime value={match.lastSeen} />
              </p>
            ) : null}
            {match.reporter ? <p className="text-xs">Reported by {match.reporter}</p> : null}
            {match.reference ? (
              <p className="text-xs wrap-anywhere">
                Reference: <span className="font-mono">{defang(match.reference)}</span>{" "}
                <span className="text-ink-300">(shown as text; the reporter chose it)</span>
              </p>
            ) : null}
            <ChipList items={match.tags} label={`Tags on the record for ${match.ioc}`} />
            {recordUrl || malpedia ? (
              <p className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
                {recordUrl ? <ExternalLink href={recordUrl}>ThreatFox record</ExternalLink> : null}
                {malpedia ? <ExternalLink href={malpedia}>Malpedia entry</ExternalLink> : null}
              </p>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

function threatFoxFacts(facts: ThreatFoxFacts): Fact[] {
  const relation = facts.association === "file_hash" ? "linked to this file hash" : "matching this indicator";
  return [
    {
      label: "Records",
      value: facts.matchCount === null ? null : `${plural(facts.matchCount, "record")} ${relation}`,
    },
    {
      label: "Reporter confidence",
      value:
        facts.highestConfidence === null
          ? null
          : `${facts.highestConfidence} / 100 (the highest across the records). Reporters assign this themselves. It is not a detection count and cannot be compared with VirusTotal's engine counts.`,
    },
    {
      label: "Threat types",
      value:
        facts.threatTypes.length === 0 ? null : (
          <ChipList items={facts.threatTypes} label="Threat types in the ThreatFox records" />
        ),
    },
    {
      label: "Malware families",
      value:
        facts.malwareFamilies.length === 0 ? null : (
          <ChipList items={facts.malwareFamilies} label="Malware families named by ThreatFox" />
        ),
    },
    { label: "Matches", value: threatFoxMatches(facts) },
  ];
}

function specificFacts(provider: ProviderView): Fact[] {
  switch (provider.provider) {
    case "abuseipdb":
      return abuseIpdbFacts(readAbuseIpdbFacts(provider.summary));
    case "otx":
      return otxFacts(readOtxFacts(provider.summary));
    case "virustotal":
      return virusTotalFacts(readVirusTotalFacts(provider.summary));
    case "threatfox":
      return threatFoxFacts(readThreatFoxFacts(provider.summary));
    default:
      return [];
  }
}

/** The status, the provider's own verdict when it gives one, and why a lookup failed. */
function Badges({ provider }: { provider: ProviderView }) {
  const status = PROVIDER_STATUS_META[provider.status];
  const verdict = provider.verdict === null ? null : PROVIDER_VERDICT_META[provider.verdict];
  const reason = provider.reason === null ? null : PROVIDER_REASON_META[provider.reason];
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {verdict ? <StatusBadge tone={verdict.tone}>{verdict.label}</StatusBadge> : null}
      <StatusBadge tone={status.tone}>{status.label}</StatusBadge>
      {reason && reason.label !== status.label ? (
        <StatusBadge tone={reason.tone}>{reason.label}</StatusBadge>
      ) : null}
    </span>
  );
}

interface ProviderCardProps {
  provider: ProviderView;
  /** When the lookup ran, shown beside a failure because a failed lookup stores no answer. */
  attemptedAt?: string | null;
  /** Asks the providers again. Offered only for a failure that asking again could fix. */
  onRetry?: () => void;
  retrying?: boolean;
}

function Attempt({ provider, attemptedAt }: { provider: ProviderView; attemptedAt: string | null }) {
  // A provider that was never asked has no attempt to date.
  if (provider.reason === null || provider.reason === "not_configured" || !attemptedAt) return null;
  return (
    <p className="text-xs text-ink-300">
      Lookup attempted <DateTime value={attemptedAt} />
    </p>
  );
}

function RetryButton({
  provider,
  onRetry,
  retrying,
}: {
  provider: ProviderView;
  onRetry: (() => void) | undefined;
  retrying: boolean;
}) {
  if (!onRetry || !canRetry(provider)) return null;
  return (
    <div>
      <button
        type="button"
        aria-disabled={retrying || undefined}
        onClick={retrying ? undefined : onRetry}
        className={`${BUTTON} max-w-full text-left wrap-anywhere`}
      >
        {retrying ? "Retrying…" : `Retry ${provider.display_name}`}
      </button>
      <p className="mt-1 text-xs text-ink-300">
        Providers that already have a fresh answer are not asked again.
      </p>
    </div>
  );
}

/** One provider's answer on its own, before CipherForge combines it with the others. */
export default function ProviderCard({
  provider,
  attemptedAt = null,
  onRetry,
  retrying = false,
}: ProviderCardProps) {
  const meta = PROVIDER_STATUS_META[provider.status];
  const badge = <Badges provider={provider} />;

  if (!hasAnswer(provider.status)) {
    const reason = provider.reason === null ? null : PROVIDER_REASON_META[provider.reason];
    return (
      <Card as="h3" title={provider.display_name} badge={badge}>
        <div className="space-y-3">
          <p>{provider.message ?? reason?.explanation ?? meta.explanation}</p>
          <Attempt provider={provider} attemptedAt={attemptedAt} />
          <RetryButton provider={provider} onRetry={onRetry} retrying={retrying} />
        </div>
      </Card>
    );
  }

  const notes = readNotes(provider.summary);
  const verdict = provider.verdict === null ? null : PROVIDER_VERDICT_META[provider.verdict];
  return (
    <Card as="h3" title={provider.display_name} badge={badge}>
      <div className="space-y-3">
        {provider.message ? <p className="text-warn">{provider.message}</p> : null}
        {verdict ? <p>{verdict.explanation}</p> : null}
        {provider.status === "no_data" && !verdict ? <p>{meta.explanation}</p> : null}
        <FactList facts={[...commonFacts(provider), ...specificFacts(provider)]} />
        <ChipList items={provider.tags} label={`Tags from ${provider.display_name}`} />
        {notes.length > 0 ? (
          <ul role="list" className="list-disc space-y-1 pl-5 text-ink-200 marker:text-cipher">
            {notes.map((note, index) => (
              <li key={`${index}:${note}`}>{note}</li>
            ))}
          </ul>
        ) : null}
        <Attempt provider={provider} attemptedAt={attemptedAt} />
        <RetryButton provider={provider} onRetry={onRetry} retrying={retrying} />
      </div>
    </Card>
  );
}
