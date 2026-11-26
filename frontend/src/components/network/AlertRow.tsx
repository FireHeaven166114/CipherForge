import { useId, useState } from "react";

import { describeObservation, describeTraffic } from "../../features/network/alerts";
import { canLookUp } from "../../features/network/enrichment";
import { useNetworkEnrich } from "../../hooks/useNetworkEnrich";
import type { NetworkAlert } from "../../types/network";
import DateTime from "../DateTime";
import FactList from "../FactList";
import { BUTTON, LABEL } from "../styles";
import EnrichmentDetail from "./EnrichmentDetail";
import EvidenceList from "./EvidenceList";
import NetworkErrorNotice from "./NetworkErrorNotice";
import SeverityBadge from "./SeverityBadge";

interface AlertRowProps {
  alert: NetworkAlert;
  /** Whether this server can look addresses up at all. */
  enrichmentEnabled: boolean;
  /** An address was looked up from this row, so the list around it can ask again. */
  onEnriched: (alert: NetworkAlert) => void;
}

function Mono({ children }: { children: string }) {
  return <span className="break-all font-mono text-xs text-ink-50">{children}</span>;
}

/** One alert: what fired, on which traffic, the evidence behind it and what is known of its public address. */
export default function AlertRow({ alert, enrichmentEnabled, onEnriched }: AlertRowProps) {
  const evidenceId = useId();
  const [open, setOpen] = useState(false);
  // The answer to a lookup holds until the list is read again and replaces this alert.
  const [looked, setLooked] = useState<{ basedOn: NetworkAlert; alert: NetworkAlert } | null>(null);
  const lookup = useNetworkEnrich();

  const shown = looked !== null && looked.basedOn === alert ? looked.alert : alert;
  const traffic = describeTraffic(shown);
  const lookable = canLookUp(shown.enrichment, enrichmentEnabled);

  async function lookUp() {
    if (lookup.busy) return;
    const updated = await lookup.lookUp(shown.id);
    if (updated === null) return;
    setLooked({ basedOn: alert, alert: updated });
    onEnriched(updated);
  }

  return (
    <li className="space-y-3 rounded-control border border-white/10 bg-ink-900/50 p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <SeverityBadge severity={shown.severity} />
        <span className="font-mono text-xs text-ink-200">{shown.rule_id}</span>
        <h3 className="min-w-0 text-base font-semibold text-ink-50 wrap-anywhere">{shown.title}</h3>
      </div>

      <p className="text-sm text-ink-100">{shown.explanation}</p>
      <p className="text-sm text-ink-200">{describeObservation(shown)}</p>

      <FactList
        facts={[
          { label: "Source", value: traffic.source === null ? null : <Mono>{traffic.source}</Mono> },
          {
            label: "Destination",
            value: traffic.destination === null ? null : <Mono>{traffic.destination}</Mono>,
          },
          { label: "Protocol", value: traffic.protocol },
          { label: "First observed", value: <DateTime value={shown.first_observed} /> },
          { label: "Last observed", value: <DateTime value={shown.last_observed} /> },
        ]}
      />

      <div>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={evidenceId}
          aria-label={`Evidence for rule ${shown.rule_id}`}
          onClick={() => setOpen((value) => !value)}
          className={BUTTON}
        >
          <span aria-hidden="true">{open ? "▾" : "▸"}</span>
          Evidence
        </button>
        <div id={evidenceId} hidden={!open} className="mt-3">
          {open ? <EvidenceList evidence={shown.evidence} /> : null}
        </div>
      </div>

      <div className="space-y-2 rounded-control border border-white/10 bg-ink-950/40 p-3" aria-live="polite">
        <p className={LABEL}>Address lookup</p>
        <EnrichmentDetail enrichment={shown.enrichment} />
        {lookable ? (
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <button
              type="button"
              onClick={() => void lookUp()}
              aria-disabled={lookup.busy || undefined}
              aria-label={`${lookup.busy ? "Looking up…" : "Look up address"} for rule ${shown.rule_id}`}
              className={BUTTON}
            >
              {lookup.busy ? "Looking up…" : "Look up address"}
            </button>
            <span className="text-xs text-ink-300">
              Only the public address is sent to the providers, never the traffic.
            </span>
          </div>
        ) : null}
      </div>
      {lookup.error !== null ? <NetworkErrorNotice error={lookup.error} /> : null}
    </li>
  );
}
