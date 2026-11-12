import { Link } from "react-router";

import { CLASSIFICATION_META, isIndicatorAssessed } from "../../features/intel/classification";
import { INDICATOR_STATUS_LABELS, INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { Indicator } from "../../types/intel";
import BarMeter from "../BarMeter";
import DateTime from "../DateTime";
import { LABEL, LINK } from "../styles";
import ClassificationBadge from "./ClassificationBadge";

const NOT_ASSESSED = <span className="text-ink-300">&mdash;</span>;

const HEADER = `px-4 py-3 ${LABEL}`;

interface IndicatorTableProps {
  indicators: readonly Indicator[];
  /** Read by screen readers as the table's name. */
  caption: string;
}

export default function IndicatorTable({ indicators, caption }: IndicatorTableProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[48rem] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-b border-ink-600 bg-ink-900/70">
          <tr>
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
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {indicators.map((indicator) => {
            const assessed = isIndicatorAssessed(indicator);
            const meta = CLASSIFICATION_META[indicator.classification];
            return (
              <tr key={indicator.indicator_id} className="align-top transition hover:bg-cipher/5">
                <th scope="row" className="relative max-w-xs py-3 pl-5 pr-4 font-normal">
                  <span
                    aria-hidden="true"
                    className={`absolute inset-y-2 left-0 w-0.5 rounded-full ${assessed ? meta.swatch : "bg-ink-500"}`}
                  />
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
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
