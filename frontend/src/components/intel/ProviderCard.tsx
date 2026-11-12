import type { ReactNode } from "react";

import { formatStrength } from "../../features/intel/format";
import { PROVIDER_STATUS_META, hasAnswer } from "../../features/intel/labels";
import { attackTechniqueUrl, otxPulseUrl } from "../../features/intel/links";
import {
  type AbuseIpdbFacts,
  type OtxFacts,
  readAbuseIpdbFacts,
  readNotes,
  readOtxFacts,
} from "../../features/intel/summaries";
import type { ProviderView } from "../../types/intel";
import BarMeter from "../BarMeter";
import Card from "../Card";
import ChipList from "../ChipList";
import DateTime from "../DateTime";
import FactList, { type Fact } from "../FactList";
import StatusBadge from "../StatusBadge";
import { LINK } from "../styles";

const FRESHNESS_TEXT = {
  fresh: "Fresh (inside the provider's cache window)",
  stale: "Stale (older than the cache window; investigate again to refresh)",
} as const;

function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={LINK}>
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

function commonFacts(provider: ProviderView): Fact[] {
  const hasEvidence = provider.status === "ok";
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
      label: "Latest activity",
      value: hasEvidence ? <DateTime value={provider.evidence_at} fallback="Not reported" /> : null,
    },
    {
      label: "First activity",
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

function specificFacts(provider: ProviderView): Fact[] {
  if (provider.provider === "abuseipdb") return abuseIpdbFacts(readAbuseIpdbFacts(provider.summary));
  if (provider.provider === "otx") return otxFacts(readOtxFacts(provider.summary));
  return [];
}

/** One provider's answer on its own, before CipherForge combines it with the others. */
export default function ProviderCard({ provider }: { provider: ProviderView }) {
  const meta = PROVIDER_STATUS_META[provider.status];
  const badge = <StatusBadge tone={meta.tone}>{meta.label}</StatusBadge>;

  if (!hasAnswer(provider.status)) {
    return (
      <Card as="h3" title={provider.display_name} badge={badge}>
        <p>{provider.message ?? meta.explanation}</p>
      </Card>
    );
  }

  const notes = readNotes(provider.summary);
  return (
    <Card as="h3" title={provider.display_name} badge={badge}>
      <div className="space-y-3">
        {provider.message ? <p className="text-warn">{provider.message}</p> : null}
        {provider.status === "no_data" ? <p>{meta.explanation}</p> : null}
        <FactList facts={[...commonFacts(provider), ...specificFacts(provider)]} />
        <ChipList items={provider.tags} label={`Tags from ${provider.display_name}`} />
        {notes.length > 0 ? (
          <ul role="list" className="list-disc space-y-1 pl-5 text-ink-200 marker:text-cipher">
            {notes.map((note, index) => (
              <li key={`${index}:${note}`}>{note}</li>
            ))}
          </ul>
        ) : null}
      </div>
    </Card>
  );
}
