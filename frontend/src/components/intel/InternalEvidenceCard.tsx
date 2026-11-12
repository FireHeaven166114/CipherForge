import type { InternalEvidence } from "../../types/intel";
import Card from "../Card";
import StatusBadge from "../StatusBadge";

/** Internal telemetry is kept separate from provider evidence so the two are never confused. */
export default function InternalEvidenceCard({ evidence }: { evidence: InternalEvidence }) {
  return (
    <Card
      title="Internal evidence"
      code="INT"
      badge={
        <StatusBadge tone={evidence.available ? "ok" : "neutral"}>
          {evidence.available ? "Available" : "Not available"}
        </StatusBadge>
      }
    >
      <p>{evidence.message}</p>
    </Card>
  );
}
