import type { ReactNode } from "react";

import { CLASSIFICATION_META, isScoreAssessed } from "../../features/intel/classification";
import { formatPoints, plural } from "../../features/intel/format";
import { buildWaterfall } from "../../features/intel/waterfall";
import type { Score } from "../../types/intel";
import Card from "../Card";
import { LABEL } from "../styles";
import ScoreTrack from "./ScoreTrack";

const KNOWN_METHODOLOGY = "intel-risk-v1";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className={LABEL}>{title}</h3>
      <div className="mt-2">{children}</div>
    </div>
  );
}

function Bullets({ items }: { items: readonly string[] }) {
  return (
    <ul role="list" className="list-disc space-y-1 pl-5 marker:text-cipher">
      {items.map((item, index) => (
        <li key={`${index}:${item}`}>{item}</li>
      ))}
    </ul>
  );
}

function FactorTable({ score }: { score: Score }) {
  if (score.factors.length === 0) {
    return (
      <p>
        Providers answered but reported nothing malicious, so no factor added any points. That is
        not proof the indicator is safe.
      </p>
    );
  }
  const { steps, end, limit } = buildWaterfall(score.factors.map((factor) => factor.points));
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left">
        <caption className="sr-only">Points that make up the score</caption>
        <thead className={LABEL}>
          <tr>
            <th scope="col" className="pb-2 pr-4 font-semibold">
              Factor
            </th>
            <th scope="col" className="pb-2 text-right font-semibold">
              Points
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {score.factors.map((factor, index) => {
            const step = steps[index];
            return (
              <tr key={`${factor.code}:${index}`}>
                <th scope="row" className="py-2.5 pr-4 align-top font-medium text-ink-50 wrap-anywhere">
                  {factor.label}
                  <span className="block text-xs font-normal text-ink-300">{factor.detail}</span>
                  {step ? (
                    <span className="mt-1.5 block">
                      <ScoreTrack step={step} limit={limit} index={index} />
                    </span>
                  ) : null}
                </th>
                <td className="py-2.5 text-right align-top font-mono tabular-nums text-ink-50">
                  {formatPoints(factor.points)}
                </td>
              </tr>
            );
          })}
        </tbody>
        <tfoot>
          <tr className="border-t border-ink-500">
            <th scope="row" className="pr-4 pt-2.5 text-left font-semibold text-ink-50">
              Score (out of 100)
              <span className="mt-1.5 block">
                <ScoreTrack
                  step={{ from: 0, to: end, kind: "add" }}
                  limit={limit}
                  fillClass={CLASSIFICATION_META[score.classification].bar}
                  index={score.factors.length}
                />
              </span>
            </th>
            <td className="pt-2.5 text-right align-top font-mono font-semibold tabular-nums text-ink-50">
              {score.score}
            </td>
          </tr>
        </tfoot>
      </table>
    </div>
  );
}

/** The rules of intel-risk-v1, in words. Only shown for that methodology, so it cannot go stale. */
function Methodology() {
  return (
    <details className="rounded-ui border border-white/10 bg-ink-900/50 p-3 open:border-cipher/40">
      <summary className="cursor-pointer rounded-chip font-medium text-ink-50 marker:text-cipher">
        How scores are calculated ({KNOWN_METHODOLOGY})
      </summary>
      <ul role="list" className="mt-3 list-disc space-y-1.5 pl-5 marker:text-cipher">
        <li>
          Each provider that answers can add up to 45 points: its evidence strength (0 to 1) times
          a recency weight.
        </li>
        <li>
          Recency weight is 1.0 for activity in the last 7 days, 0.9 within 30 days, 0.7 within 90
          days, 0.5 within 180 days and 0.3 for anything older. It is 0.6 when the provider does
          not say when the activity happened.
        </li>
        <li>
          A provider supports the indicator when its strength times recency is at least 0.4. Two
          supporting providers add 8 points and three or more add 16.
        </li>
        <li>
          Each malware family named by supporting providers adds 5 points, up to 10 in total.
        </li>
        <li>
          Fewer than two supporting providers caps the score at 60 (Medium), so nothing is rated
          High or Critical on one source's word. No score exceeds 100.
        </li>
        <li>
          Bands: 0 to 20 Informational, 21 to 40 Low, 41 to 60 Medium, 61 to 80 High, 81 to 100
          Critical.
        </li>
        <li>
          Confidence adds 35 for each fresh answer and 15 for each stale one, plus 20 when two or
          more providers support the indicator, up to 90.
        </li>
      </ul>
    </details>
  );
}

/** Explains where the CipherForge score comes from, what is unknown, and what to do next. */
export default function ScorePanel({ score }: { score: Score }) {
  const assessed = isScoreAssessed(score);
  return (
    <Card title="How the score was built" code="ANA">
      <div className="space-y-5">
        {assessed ? (
          <>
            <Section title="Points">
              <FactorTable score={score} />
            </Section>
            <p>
              {plural(score.answered_sources, "provider")} answered;{" "}
              {score.contributing_sources} reported malicious activity; {score.supporting_sources}{" "}
              had evidence strong and recent enough to count as independent support.
            </p>
            <p>
              Confidence is {score.confidence} out of 100. It reflects how much fresh evidence stands
              behind the score. It is not the probability that the indicator is malicious.
            </p>
          </>
        ) : (
          <p>
            No provider answered, so there is no score to break down. The 0 stored for this
            indicator means &ldquo;nothing was assessed&rdquo;, not &ldquo;nothing was found&rdquo;.
          </p>
        )}

        {score.uncertainty.length > 0 ? (
          <Section title="What is not known">
            <Bullets items={score.uncertainty} />
          </Section>
        ) : null}

        {score.recommended_actions.length > 0 ? (
          <Section title="Recommended next steps">
            <Bullets items={score.recommended_actions} />
            <p className="mt-2 text-ink-300">
              CipherForge only recommends. It never blocks, isolates or changes anything on its own.
            </p>
          </Section>
        ) : null}

        {score.methodology === KNOWN_METHODOLOGY ? (
          <Methodology />
        ) : (
          <p className="text-ink-300">Scoring method: {score.methodology}</p>
        )}
      </div>
    </Card>
  );
}
