import { useCallback, useId, useState } from "react";

import { severityMeta, toggleSeverity } from "../../features/network/alerts";
import { ALERTS_PAGE_SIZE } from "../../features/network/paging";
import { formatIstTime } from "../../features/time/ist";
import type { ResourceState } from "../../hooks/useApiResource";
import { useLiveResource } from "../../hooks/useLiveResource";
import { useNetworkRefreshOn } from "../../hooks/useNetworkRefreshOn";
import { listAlerts } from "../../services/networkService";
import { type DetectionRule, SEVERITIES, type SessionDetail, type Severity } from "../../types/network";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import Pagination from "../Pagination";
import { BUTTON, FIELD, LABEL } from "../styles";
import AlertRow from "./AlertRow";
import NetworkErrorNotice from "./NetworkErrorNotice";

interface AlertsPanelProps {
  session: Pick<SessionDetail, "id" | "status" | "alerts_total">;
  /** How often to read the list again: quickly while the session changes. */
  intervalMs: number;
  /** Changes when the page asks for fresh data. */
  version: number;
  rules: ResourceState<DetectionRule[]>;
  enrichmentEnabled: boolean;
  /** An address was looked up from an alert, so the session's own figures changed too. */
  onEnriched: () => void;
  className?: string;
}

interface SeverityFilterProps {
  selected: readonly Severity[];
  onToggle: (severity: Severity) => void;
}

function SeverityFilter({ selected, onToggle }: SeverityFilterProps) {
  const labelId = useId();
  return (
    <div role="group" aria-labelledby={labelId}>
      <p id={labelId} className={LABEL}>
        Severity
      </p>
      <div className="mt-1.5 flex flex-wrap gap-2">
        {SEVERITIES.map((severity) => {
          const { label, symbol } = severityMeta(severity);
          const pressed = selected.includes(severity);
          return (
            <button
              key={severity}
              type="button"
              aria-pressed={pressed}
              onClick={() => onToggle(severity)}
              className={`${BUTTON} ${pressed ? "border-cipher/70 bg-cipher/15 text-ink-50" : ""}`}
            >
              <span aria-hidden="true">{pressed ? "✓" : symbol}</span>
              {label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default function AlertsPanel({
  session,
  intervalMs,
  version,
  rules,
  enrichmentEnabled,
  onEnriched,
  className,
}: AlertsPanelProps) {
  const ruleId = useId();
  const [severity, setSeverity] = useState<readonly Severity[]>([]);
  const [rule, setRule] = useState("");
  const [page, setPage] = useState(1);

  const sessionId = session.id;
  const load = useCallback(
    (signal: AbortSignal) =>
      listAlerts(
        sessionId,
        {
          severity,
          rule: rule === "" ? undefined : rule,
          limit: ALERTS_PAGE_SIZE,
          offset: (page - 1) * ALERTS_PAGE_SIZE,
        },
        signal,
      ),
    [sessionId, severity, rule, page],
  );
  const { state, refresh } = useLiveResource(load, intervalMs);

  useNetworkRefreshOn(version, refresh);
  // New alerts, or the session settling, are read at once rather than at the next tick.
  useNetworkRefreshOn(`${session.status}:${session.alerts_total}`, refresh);

  const known = rules.status === "success" ? rules.data : [];
  const filtered = severity.length > 0 || rule !== "";

  function changeSeverity(next: Severity) {
    setSeverity((current) => toggleSeverity(current, next));
    setPage(1);
  }

  function clearFilters() {
    setSeverity([]);
    setRule("");
    setPage(1);
  }

  return (
    <Panel title="Alerts" code="SES-04" className={className}>
      <div className="space-y-4">
        <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
          <SeverityFilter selected={severity} onToggle={changeSeverity} />
          <div className="min-w-0 basis-64">
            <label htmlFor={ruleId} className={LABEL}>
              Rule
            </label>
            <select
              id={ruleId}
              value={rule}
              onChange={(event) => {
                setRule(event.target.value);
                setPage(1);
              }}
              className={`${FIELD} mt-1.5`}
            >
              <option value="">All rules</option>
              {rule !== "" && !known.some((entry) => entry.rule_id === rule) ? (
                <option value={rule}>{rule}</option>
              ) : null}
              {known.map((entry) => (
                <option key={entry.rule_id} value={entry.rule_id}>
                  {entry.rule_id} - {entry.title}
                </option>
              ))}
            </select>
          </div>
          {filtered ? (
            <button type="button" onClick={clearFilters} className={BUTTON}>
              Clear filters
            </button>
          ) : null}
        </div>

        {state.status === "loading" ? <LoadingNote>Loading alerts…</LoadingNote> : null}
        {state.status === "error" ? <NetworkErrorNotice error={state.error} onRetry={refresh} /> : null}
        {state.status === "ready" ? (
          <>
            {state.refreshError !== null ? (
              <p role="alert" className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
                <span aria-hidden="true">▲ </span>
                The alerts could not be refreshed. The list below is from {formatIstTime(new Date(state.updatedAt))}.
              </p>
            ) : null}
            {state.data.items.length === 0 ? (
              <p className="py-6 text-center text-sm text-ink-200">
                {filtered
                  ? "No alerts match these filters."
                  : "No alerts were raised in this session. That says only that no rule fired: it is not a statement that the traffic is safe."}
              </p>
            ) : (
              <ul aria-label="Alerts" className="space-y-3">
                {state.data.items.map((alert) => (
                  <AlertRow
                    key={alert.id}
                    alert={alert}
                    enrichmentEnabled={enrichmentEnabled}
                    onEnriched={() => {
                      refresh();
                      onEnriched();
                    }}
                  />
                ))}
              </ul>
            )}
            <Pagination
              page={page}
              pageSize={ALERTS_PAGE_SIZE}
              total={state.data.total}
              label="Alerts pagination"
              onPageChange={setPage}
            />
          </>
        ) : null}
      </div>
    </Panel>
  );
}
