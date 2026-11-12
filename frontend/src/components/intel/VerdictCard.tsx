import { isScoreAssessed } from "../../features/intel/classification";
import { INDICATOR_STATUS_LABELS, INDICATOR_TYPE_LABELS } from "../../features/intel/labels";
import type { Indicator, Score } from "../../types/intel";
import BarMeter from "../BarMeter";
import Card from "../Card";
import ChipList from "../ChipList";
import DateTime from "../DateTime";
import FactList from "../FactList";
import GaugeRing from "../charts/GaugeRing";
import AnimatedNumber from "../hud/AnimatedNumber";
import { LABEL } from "../styles";

interface VerdictCardProps {
  indicator: Indicator;
  score: Score;
}

function Confidence({ value }: { value: number }) {
  return (
    <div className="max-w-sm">
      <p className={LABEL}>Confidence</p>
      <p className="mt-1 flex items-baseline gap-1.5">
        <AnimatedNumber value={value} className="font-mono text-2xl font-semibold tabular-nums text-ink-50" />
        <span className="text-ink-300">/ 100</span>
      </p>
      <div className="mt-1.5">
        <BarMeter percent={value} fillClass="fill-cipher" />
      </div>
      <p className="mt-1.5 text-xs text-ink-300">
        How much fresh evidence stands behind the score. It is not the probability that the
        indicator is malicious.
      </p>
    </div>
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
    <Card title="CipherForge assessment" code="ASM">
      <div className="flex flex-col items-center gap-6 @lg:flex-row @lg:items-start">
        <GaugeRing
          score={assessed ? score.score : null}
          band={assessed ? score.classification : null}
          className="size-48"
        />
        <div className="w-full min-w-0 flex-1 space-y-4">
          <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
            <span className="rounded-chip border border-cipher/50 bg-cipher/10 px-2 py-0.5 text-xs font-semibold uppercase tracking-[0.14em] text-cipher">
              {INDICATOR_TYPE_LABELS[indicator.indicator_type]}
            </span>
            <p className="min-w-0 break-all font-mono text-lg text-ink-50">{indicator.indicator_value}</p>
          </div>

          {assessed ? (
            <Confidence value={score.confidence} />
          ) : (
            <p className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-ink-100">
              <span aria-hidden="true" className="mr-2 text-warn">
                ▲
              </span>
              No provider answered, so CipherForge has no evidence about this indicator. This is not a
              clean result: it only means nothing was checked.
            </p>
          )}
        </div>
      </div>

      <div className="mt-5 space-y-4 border-t border-white/10 pt-4">
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
