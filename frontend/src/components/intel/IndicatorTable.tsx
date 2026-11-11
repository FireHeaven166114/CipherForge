import { Link } from "react-router";

import { isIndicatorAssessed } from "../../features/intel/classification";
import { INDICATOR_STATUS_LABELS, INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { Indicator } from "../../types/intel";
import DateTime from "../DateTime";
import { LINK } from "../styles";
import ClassificationBadge from "./ClassificationBadge";

const NOT_ASSESSED = <span className="text-slate-400">&mdash;</span>;

interface IndicatorTableProps {
  indicators: readonly Indicator[];
  /** Read by screen readers as the table's name. */
  caption: string;
}

export default function IndicatorTable({ indicators, caption }: IndicatorTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="w-full min-w-[48rem] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="bg-slate-900 text-xs uppercase tracking-wide text-slate-400">
          <tr>
            <th scope="col" className="px-4 py-3 font-medium">
              Indicator
            </th>
            <th scope="col" className="px-4 py-3 font-medium">
              Type
            </th>
            <th scope="col" className="px-4 py-3 font-medium">
              Classification
            </th>
            <th scope="col" className="px-4 py-3 text-right font-medium">
              Score
            </th>
            <th scope="col" className="px-4 py-3 text-right font-medium">
              Confidence
            </th>
            <th scope="col" className="px-4 py-3 text-right font-medium">
              Sources
            </th>
            <th scope="col" className="px-4 py-3 font-medium">
              Status
            </th>
            <th scope="col" className="px-4 py-3 font-medium">
              Last checked
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {indicators.map((indicator) => {
            const assessed = isIndicatorAssessed(indicator);
            return (
              <tr key={indicator.indicator_id} className="align-top">
                <th scope="row" className="max-w-xs px-4 py-3 font-normal">
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
                  {assessed ? indicator.risk_score : NOT_ASSESSED}
                </td>
                <td className="px-4 py-3 text-right tabular-nums">
                  {assessed ? indicator.confidence : NOT_ASSESSED}
                </td>
                <td className="px-4 py-3 text-right tabular-nums">{indicator.source_count}</td>
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
