import { formatMeasure, formatWindow } from "../../features/network/alerts";
import type { ResourceState } from "../../hooks/useApiResource";
import type { DetectionRule } from "../../types/network";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import StatusBadge from "../StatusBadge";
import NetworkErrorNotice from "./NetworkErrorNotice";
import Notice from "./Notice";
import SeverityBadge from "./SeverityBadge";

interface RulesPanelProps {
  state: ResourceState<DetectionRule[]>;
  onRetry: () => void;
  enrichmentEnabled: boolean;
  className?: string;
}

const MULTIPLES = ["1×", "3×", "10×"] as const;

function inactiveReason(enrichmentEnabled: boolean): string {
  return enrichmentEnabled
    ? "This rule cannot fire in the current configuration."
    : "This rule needs external enrichment, which is switched off on this server, so it cannot fire.";
}

function RuleCard({ rule, enrichmentEnabled }: { rule: DetectionRule; enrichmentEnabled: boolean }) {
  return (
    <li className="space-y-3 rounded-control border border-white/10 bg-ink-900/50 p-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="font-mono text-xs text-ink-200">{rule.rule_id}</span>
        <h3 className="min-w-0 text-base font-semibold text-ink-50 wrap-anywhere">{rule.title}</h3>
        <StatusBadge tone={rule.active ? "ok" : "warn"}>{rule.active ? "Active" : "Inactive"}</StatusBadge>
      </div>
      <p className="text-sm text-ink-100">{rule.description}</p>
      <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)]">
        <dt className="text-ink-300">Threshold</dt>
        <dd>{formatMeasure(rule.threshold, rule.unit)}</dd>
        <dt className="text-ink-300">Time window</dt>
        <dd>{formatWindow(rule.window_seconds)}</dd>
        <dt className="text-ink-300">Severity</dt>
        <dd>
          <ol aria-label={`Severity of ${rule.rule_id} by multiple of the threshold`} className="flex flex-wrap gap-x-4 gap-y-2">
            {rule.severities.map((severity, index) => (
              <li key={`${MULTIPLES[index] ?? index}`} className="flex items-center gap-2">
                <span className="font-mono text-xs text-ink-300">At {MULTIPLES[index] ?? `step ${index + 1}`}</span>
                <SeverityBadge severity={severity} />
              </li>
            ))}
          </ol>
        </dd>
      </dl>
      {rule.detail !== null ? <p className="text-xs text-ink-300">{rule.detail}</p> : null}
      {!rule.active ? (
        <Notice tone="warn" title="Inactive">
          <p>{inactiveReason(enrichmentEnabled)}</p>
        </Notice>
      ) : null}
    </li>
  );
}

/** What the monitor looks for, and how serious each finding is. */
export default function RulesPanel({ state, onRetry, enrichmentEnabled, className }: RulesPanelProps) {
  return (
    <Panel title="Detection rules" code="RUL-01" className={className}>
      <div className="space-y-4">
        <p className="text-xs text-ink-300">
          Each rule raises an alert when what the monitor sees reaches a threshold, and a higher multiple of
          the threshold raises the severity. The rules are heuristics: an alert is a lead to look into, not
          proof of an attack, and no alert is not proof that traffic is safe.
        </p>
        {state.status === "loading" ? <LoadingNote>Loading detection rules…</LoadingNote> : null}
        {state.status === "error" ? <NetworkErrorNotice error={state.error} onRetry={onRetry} /> : null}
        {state.status === "success" ? (
          state.data.length === 0 ? (
            <p className="py-4 text-center text-sm text-ink-200">The server reported no detection rules.</p>
          ) : (
            <ul aria-label="Detection rules" className="grid gap-3 @split:grid-cols-2">
              {state.data.map((rule) => (
                <RuleCard key={rule.rule_id} rule={rule} enrichmentEnabled={enrichmentEnabled} />
              ))}
            </ul>
          )
        ) : null}
      </div>
    </Panel>
  );
}
