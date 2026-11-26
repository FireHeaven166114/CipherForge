import { Fragment } from "react";

import { flattenEvidence } from "../../features/network/evidence";

interface EvidenceListProps {
  evidence: Record<string, unknown>;
  id?: string;
}

/**
 * What a detection rule recorded when it fired, as plain text. The evidence is data from the
 * server, so it is only ever shown as text and never read as markup.
 */
export default function EvidenceList({ evidence, id }: EvidenceListProps) {
  const { rows, truncated } = flattenEvidence(evidence);
  if (rows.length === 0) {
    return (
      <p id={id} className="text-xs text-ink-300">
        This alert recorded no further evidence.
      </p>
    );
  }
  return (
    <div id={id}>
      <dl className="grid grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
        {rows.map((row) => (
          <Fragment key={row.key}>
            <dt className="text-ink-300">{row.label}</dt>
            <dd className="break-words font-mono text-xs text-ink-100">{row.value}</dd>
          </Fragment>
        ))}
      </dl>
      {truncated ? (
        <p className="mt-2 text-xs text-ink-300">More evidence was recorded than is listed here.</p>
      ) : null}
    </div>
  );
}
