import { classificationMeta, describeProvider, enrichmentNote, hasScore } from "../../features/network/enrichment";
import { humanize } from "../../features/network/labels";
import type { Enrichment } from "../../types/network";
import DateTime from "../DateTime";
import EnrichmentBadge from "./EnrichmentBadge";

interface EnrichmentDetailProps {
  enrichment: Enrichment;
  /** Leave the address out when the surrounding row already names it. */
  showAddress?: boolean;
}

function Classification({ value }: { value: string | null }) {
  if (value === null) return null;
  const meta = classificationMeta(value);
  if (meta === null) {
    return (
      <span className="max-w-full break-words rounded-chip border border-ink-500 bg-ink-800/70 px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-ink-200">
        {humanize(value)}
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-chip border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${meta.badge}`}
    >
      <span aria-hidden="true">{meta.symbol}</span>
      {meta.label}
    </span>
  );
}

/**
 * What the providers said about one public address. A score and a classification are shown only
 * when a provider produced a score: an answer of "no data" is never turned into "safe".
 */
export default function EnrichmentDetail({ enrichment, showAddress = true }: EnrichmentDetailProps) {
  const scored = hasScore(enrichment);
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <EnrichmentBadge state={enrichment.status} />
        {showAddress && enrichment.address !== null ? (
          <span className="break-all font-mono text-xs text-ink-100">{enrichment.address}</span>
        ) : null}
        {scored ? (
          <>
            <span className="font-mono text-sm tabular-nums text-ink-50">Risk score {enrichment.risk_score} of 100</span>
            <span className="flex items-center gap-2 text-xs text-ink-300">
              Classification
              <Classification value={enrichment.classification} />
            </span>
          </>
        ) : null}
      </div>
      <p className="break-words text-xs text-ink-200">{enrichmentNote(enrichment)}</p>
      {enrichment.providers.length > 0 ? (
        <ul aria-label="Provider answers" className="space-y-0.5 break-words text-xs text-ink-100">
          {enrichment.providers.map((provider) => (
            <li key={provider.provider}>{describeProvider(provider)}</li>
          ))}
        </ul>
      ) : null}
      {enrichment.completed_at !== null ? (
        <p className="text-xs text-ink-300">
          Looked up <DateTime value={enrichment.completed_at} />
        </p>
      ) : null}
    </div>
  );
}
