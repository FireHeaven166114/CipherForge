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
        <h2 id={headingId} className="text-lg font-semibold tracking-tight">
          Provider answers
        </h2>
        <p className="mt-1 text-sm text-slate-400">
          Each provider is shown on its own, before CipherForge combines them.
        </p>
        <div className="mt-3 grid gap-4 lg:grid-cols-2">
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
