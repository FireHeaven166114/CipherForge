import { isScoreAssessed } from "../../features/intel/classification";
import { INDICATOR_STATUS_LABELS, INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { Indicator, Score } from "../../types/intel";
import Card from "../Card";
import ChipList from "../ChipList";
import DateTime from "../DateTime";
import FactList from "../FactList";
import ClassificationBadge from "./ClassificationBadge";

interface VerdictCardProps {
  indicator: Indicator;
  score: Score;
}

function Figure({ label, value }: { label: string; value: number }) {
  return (
    <p className="text-slate-300">
      {label} <span className="text-xl font-semibold tabular-nums text-slate-50">{value}</span>
      <span className="text-slate-400"> / 100</span>
    </p>
  );
}

/** The CipherForge assessment: what the indicator is, how it is classified, and how sure we are. */
export default function VerdictCard({ indicator, score }: VerdictCardProps) {
  const assessed = isScoreAssessed(score);
  const status = INDICATOR_STATUS_LABELS[indicator.status];
  const activityWindow =
    indicator.first_seen || indicator.last_seen ? (
      <>
        <DateTime value={indicator.first_seen} fallback="Unknown" /> to{" "}
        <DateTime value={indicator.last_seen} fallback="Unknown" />
      </>
    ) : null;

  return (
    <Card title="CipherForge assessment">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
          <span className="rounded border border-slate-600 px-2 py-0.5 text-xs font-medium uppercase tracking-wide text-slate-200">
            {INDICATOR_TYPE_LABELS[indicator.indicator_type]}
          </span>
          <p className="min-w-0 break-all font-mono text-base text-slate-50">
            {indicator.indicator_value}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
          <ClassificationBadge classification={score.classification} assessed={assessed} />
          {assessed ? (
            <>
              <Figure label="Score" value={score.score} />
              <Figure label="Confidence" value={score.confidence} />
            </>
          ) : null}
        </div>

        {assessed ? null : (
          <p className="rounded-md border border-slate-700 bg-slate-950 p-3">
            No provider answered, so CipherForge has no evidence about this indicator. This is not a
            clean result: it only means nothing was checked.
          </p>
        )}

        <FactList
          facts={[
            { label: "Status", value: `${status.label}. ${status.detail}` },
            { label: "Last checked", value: <DateTime value={indicator.last_checked_at} /> },
            { label: "Activity window", value: activityWindow },
            {
              label: "Sources with evidence",
              value: assessed ? indicator.source_count : null,
            },
          ]}
        />

        <ChipList items={indicator.tags} label="Tags from providers" />
      </div>
    </Card>
  );
}
