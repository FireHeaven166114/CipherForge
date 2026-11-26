import { ENRICHMENT_META } from "../../features/network/enrichment";
import type { EnrichmentState } from "../../types/network";

/** Where an address stands with the threat-intelligence providers. None of the states reads as "clean". */
export default function EnrichmentBadge({ state }: { state: EnrichmentState }) {
  const meta = ENRICHMENT_META[state];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-chip border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${meta.classes}`}
    >
      <span aria-hidden="true">{meta.glyph}</span>
      {meta.label}
    </span>
  );
}
