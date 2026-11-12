import { useId } from "react";
import { Link } from "react-router";

import { CLASSIFICATION_META, classificationForScore } from "../../features/intel/classification";
import { INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import { plural } from "../../features/intel/format";
import { attackTechniqueUrl } from "../../features/intel/links";
import { countryLabel } from "../../features/overview/countries";
import type { FacetEntry } from "../../types/intel";
import Count from "../Count";
import ClassificationBadge from "../intel/ClassificationBadge";
import { BUTTON, LABEL, LINK } from "../styles";
import { CloseIcon, ExternalIcon } from "../hud/Icons";
import Overlay from "../hud/Overlay";

export type FocusKind = "country" | "malware" | "technique" | "tag";

/** What the drawer is showing: one value of a grouped field, with the indicators behind it. */
export interface Focus {
  kind: FocusKind;
  entry: FacetEntry;
}

const KIND_LABELS: Record<FocusKind, string> = {
  country: "Provider-reported country",
  malware: "Malware family",
  technique: "ATT&CK technique",
  tag: "Provider tag",
};

function displayName({ kind, entry }: Focus): string {
  return kind === "country" ? countryLabel(entry.key) : entry.key;
}

function DrawerBody({ focus, onClose }: { focus: Focus; onClose: () => void }) {
  const samplesId = useId();
  const { kind, entry } = focus;
  const attackUrl = kind === "technique" ? attackTechniqueUrl(entry.key) : null;
  const band = classificationForScore(entry.max_risk);

  return (
    <div className="hud-panel flex min-h-full flex-col rounded-l-ui border-l border-cipher/40 bg-ink-950/95">
      <header className="flex items-start justify-between gap-3 border-b border-white/10 p-4">
        <div className="min-w-0">
          <p className={LABEL}>{KIND_LABELS[kind]}</p>
          <h2 className="mt-1 break-words text-xl font-semibold text-ink-50">{displayName(focus)}</h2>
        </div>
        <button type="button" onClick={onClose} className={`${BUTTON} shrink-0 !px-2`}>
          <CloseIcon className="size-4" />
          <span className="sr-only">Close details</span>
        </button>
      </header>

      <div className="space-y-5 p-4">
        <dl className="grid grid-cols-2 gap-3">
          <div className="rounded-ui border border-white/10 bg-ink-900/60 p-3">
            <dt className={LABEL}>Indicators</dt>
            <dd className="mt-1 text-2xl font-semibold text-ink-50">
              <Count value={entry.count} className="font-mono" />
            </dd>
          </div>
          <div className="rounded-ui border border-white/10 bg-ink-900/60 p-3">
            <dt className={LABEL}>Highest risk</dt>
            <dd className="mt-1.5 flex flex-wrap items-center gap-2">
              <ClassificationBadge classification={band} />
              <span className={`font-mono text-sm ${CLASSIFICATION_META[band].text}`}>{entry.max_risk}</span>
            </dd>
          </div>
        </dl>

        {kind === "country" ? (
          <p className="text-xs text-ink-300">
            This is the country the threat-intelligence providers report for an IP address. It is not
            where an attacker is, and it says nothing about domains, URLs or file hashes.
          </p>
        ) : null}

        <section aria-labelledby={samplesId}>
          <h3 id={samplesId} className={LABEL}>
            Highest-risk indicators
          </h3>
          {entry.samples.length === 0 ? (
            <p className="mt-2 text-sm text-ink-300">No indicator is listed for this value.</p>
          ) : (
            <ul className="mt-2 space-y-2">
              {entry.samples.map((sample) => (
                <li
                  key={sample.indicator_id}
                  className="flex items-center justify-between gap-3 rounded-ui border border-white/10 bg-ink-900/60 p-3"
                >
                  <div className="min-w-0">
                    <Link
                      to={`/indicators/${encodeURIComponent(sample.indicator_id)}`}
                      onClick={onClose}
                      className={`${LINK} break-all font-mono text-sm`}
                    >
                      {sample.indicator_value}
                    </Link>
                    <p className="mt-0.5 text-xs text-ink-300">
                      {INDICATOR_TYPE_LABELS[sample.indicator_type]} · score {sample.risk_score}
                    </p>
                  </div>
                  <ClassificationBadge classification={sample.classification} />
                </li>
              ))}
            </ul>
          )}
          {entry.count > entry.samples.length ? (
            <p className="mt-2 text-xs text-ink-300">
              Showing {entry.samples.length} of {plural(entry.count, "indicator")}.
            </p>
          ) : null}
        </section>

        {attackUrl !== null ? (
          <a href={attackUrl} target="_blank" rel="noopener noreferrer" className={`${LINK} inline-flex items-center gap-1.5 text-sm`}>
            Read about {entry.key} on MITRE ATT&amp;CK
            <ExternalIcon className="size-3.5" />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        ) : null}
      </div>
    </div>
  );
}

/** A side drawer with the detail behind a chart or map click. Escape and the close button dismiss it. */
export default function FocusDrawer({ focus, onClose }: { focus: Focus | null; onClose: () => void }) {
  const label = focus === null ? "Details" : `${KIND_LABELS[focus.kind]}: ${displayName(focus)}`;
  return (
    <Overlay open={focus !== null} onClose={onClose} label={label} placement="right">
      {focus !== null ? <DrawerBody focus={focus} onClose={onClose} /> : null}
    </Overlay>
  );
}
