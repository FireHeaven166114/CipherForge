import { severityMeta } from "../../features/network/alerts";
import type { Severity } from "../../types/network";

/** An alert's severity as a shape and a word as well as a colour. */
export default function SeverityBadge({ severity }: { severity: Severity }) {
  const { label, symbol, badge } = severityMeta(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-chip border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${badge}`}
    >
      <span aria-hidden="true">{symbol}</span>
      {label}
    </span>
  );
}
