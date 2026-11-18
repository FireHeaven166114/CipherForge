import { Link } from "react-router";

import { CLASSIFICATION_META, isIndicatorAssessed } from "../../features/intel/classification";
import { INDICATOR_STATUS_LABELS, INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { PageSelection } from "../../features/intel/selection";
import type { Indicator } from "../../types/intel";
import BarMeter from "../BarMeter";
import Checkbox from "../Checkbox";
import DateTime from "../DateTime";
import { TrashIcon } from "../hud/Icons";
import { BUTTON, LABEL, LINK } from "../styles";
import ClassificationBadge from "./ClassificationBadge";

const NOT_ASSESSED = <span className="text-ink-300">&mdash;</span>;

const HEADER = `px-4 py-3 ${LABEL}`;

/** Ticking rows. Without it the table has no tick boxes. */
export interface TableSelection {
  isSelected: (indicatorId: string) => boolean;
  /** Whether none, some or all of the rows shown are ticked. */
  overall: PageSelection;
  /** `range` is true when Shift was held: tick every row from the last one clicked to this one. */
  onToggle: (indicatorId: string, ticked: boolean, range: boolean) => void;
  onToggleAll: (ticked: boolean) => void;
}

interface IndicatorTableProps {
  indicators: readonly Indicator[];
  /** Read by screen readers as the table's name. */
  caption: string;
  selection?: TableSelection;
  /** Adds a delete button to each row. */
  onDelete?: (indicator: Indicator) => void;
}

export default function IndicatorTable({
  indicators,
  caption,
  selection,
  onDelete,
}: IndicatorTableProps) {
  return (
    // Positioned, so the hidden labels in the header cells (placed absolutely) stay inside this box
    // when it scrolls, instead of escaping it and widening the whole page.
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[48rem] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-b border-ink-600 bg-ink-900/70">
          <tr>
            {selection ? (
              <th scope="col" className="w-12 py-2 pl-3 pr-0">
                <span className="sr-only">Select</span>
                <Checkbox
                  label="Select all indicators on this page"
                  checked={selection.overall === "all"}
                  mixed={selection.overall === "some"}
                  onToggle={(ticked) => selection.onToggleAll(ticked)}
                />
              </th>
            ) : null}
            <th scope="col" className={HEADER}>
              Indicator
            </th>
            <th scope="col" className={HEADER}>
              Type
            </th>
            <th scope="col" className={HEADER}>
              Classification
            </th>
            <th scope="col" className={`${HEADER} text-right`}>
              Score
            </th>
            <th scope="col" className={`${HEADER} text-right`}>
              Confidence
            </th>
            <th scope="col" className={`${HEADER} text-right`}>
              Sources
            </th>
            <th scope="col" className={HEADER}>
              Status
            </th>
            <th scope="col" className={HEADER}>
              Last checked
            </th>
            {onDelete ? (
              <th scope="col" className="w-12 py-3 pl-0 pr-3">
                <span className="sr-only">Actions</span>
              </th>
            ) : null}
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {indicators.map((indicator) => {
            const assessed = isIndicatorAssessed(indicator);
            const meta = CLASSIFICATION_META[indicator.classification];
            const ticked = selection?.isSelected(indicator.indicator_id) ?? false;
            // The coloured bar marks the start of the row, so it sits in whichever cell comes first.
            const bar = (
              <span
                aria-hidden="true"
                className={`absolute inset-y-2 left-0 w-0.5 rounded-full ${assessed ? meta.swatch : "bg-ink-500"}`}
              />
            );
            return (
              <tr
                key={indicator.indicator_id}
                className={`align-top transition hover:bg-cipher/5 ${ticked ? "bg-cipher/10" : ""}`}
              >
                {selection ? (
                  <td className="relative py-2 pl-3 pr-0">
                    {bar}
                    <Checkbox
                      label={`Select ${indicator.indicator_value}`}
                      checked={ticked}
                      onToggle={(next, range) => selection.onToggle(indicator.indicator_id, next, range)}
                    />
                  </td>
                ) : null}
                <th
                  scope="row"
                  className={`relative max-w-xs py-3 pr-4 font-normal ${selection ? "pl-3" : "pl-5"}`}
                >
                  {selection ? null : bar}
                  <Link
                    to={`/indicators/${encodeURIComponent(indicator.indicator_id)}`}
                    className={`${LINK} break-all font-mono`}
                  >
                    {indicator.indicator_value}
                  </Link>
                </th>
                <td className="px-4 py-3">{INDICATOR_TYPE_LABELS[indicator.indicator_type]}</td>
                <td className="px-4 py-3">
                  <ClassificationBadge
                    classification={indicator.classification}
                    assessed={assessed}
                  />
                </td>
                <td className="px-4 py-3 text-right tabular-nums">
                  {assessed ? (
                    <>
                      <span className="font-mono text-ink-50">{indicator.risk_score}</span>
                      <span className="ml-auto mt-1 block w-14">
                        <BarMeter percent={indicator.risk_score} fillClass={meta.bar} />
                      </span>
                    </>
                  ) : (
                    NOT_ASSESSED
                  )}
                </td>
                <td className="px-4 py-3 text-right font-mono tabular-nums">
                  {assessed ? indicator.confidence : NOT_ASSESSED}
                </td>
                <td className="px-4 py-3 text-right font-mono tabular-nums">{indicator.source_count}</td>
                <td className="px-4 py-3">{INDICATOR_STATUS_LABELS[indicator.status].label}</td>
                <td className="px-4 py-3">
                  <DateTime value={indicator.last_checked_at} stacked />
                </td>
                {onDelete ? (
                  <td className="py-2 pl-0 pr-3">
                    <button
                      type="button"
                      title="Delete this indicator"
                      onClick={() => onDelete(indicator)}
                      className={`${BUTTON} !px-2 hover:!border-crit/60 hover:!text-crit`}
                    >
                      <TrashIcon className="size-4" />
                      <span className="sr-only">Delete {indicator.indicator_value}</span>
                    </button>
                  </td>
                ) : null}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
