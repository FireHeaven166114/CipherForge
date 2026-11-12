import { useId } from "react";

import type { Investigation } from "../../types/intel";
import InternalEvidenceCard from "./InternalEvidenceCard";
import ProviderCard from "./ProviderCard";
import ScorePanel from "./ScorePanel";
import VerdictCard from "./VerdictCard";

/**
 * Everything known about one indicator: the verdict first, then each provider's own answer,
 * how the score was built, and (separately) internal evidence.
 */
export default function InvestigationView({ investigation }: { investigation: Investigation }) {
  const headingId = useId();
  const { indicator, providers, score, internal_evidence: internalEvidence } = investigation;

  return (
    <div className="space-y-6">
      <VerdictCard indicator={indicator} score={score} />

      <section aria-labelledby={headingId}>
        <h2
          id={headingId}
          className="flex items-center gap-2 text-[0.8rem] font-semibold uppercase tracking-[0.14em] text-ink-100"
        >
          <span aria-hidden="true" className="size-1.5 shrink-0 rotate-45 bg-cipher" />
          <span aria-hidden="true" className="font-mono text-[0.68rem] font-normal text-ink-300">
            SRC
          </span>
          Provider answers
        </h2>
        <p className="mt-1 text-sm text-ink-300">
          Each provider is shown on its own, before CipherForge combines them.
        </p>
        <div className="mt-3 grid grid-cols-1 gap-4 @split:grid-cols-2">
          {providers.map((provider) => (
            <ProviderCard key={provider.provider} provider={provider} />
          ))}
        </div>
      </section>

      <ScorePanel score={score} />
      <InternalEvidenceCard evidence={internalEvidence} />
    </div>
  );
}
