import Card from "../components/Card";
import StatusBadge, { type Tone } from "../components/StatusBadge";
import { BUTTON } from "../components/styles";
import type { CheckResult, OverallStatus } from "../features/status/overallStatus";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useServiceStatus } from "../hooks/useServiceStatus";
import type { ApiError } from "../services/apiClient";
import type { HealthResponse, ReadinessResponse } from "../types/api";

const OVERALL: Record<OverallStatus, { tone: Tone; label: string; detail: string }> = {
  checking: { tone: "neutral", label: "Checking", detail: "Contacting the API…" },
  operational: { tone: "ok", label: "Operational", detail: "The API is up and its database is reachable." },
  degraded: { tone: "warn", label: "Degraded", detail: "The API is up, but a dependency is not healthy." },
  down: { tone: "bad", label: "Down", detail: "The API cannot be reached." },
};

function ErrorDetail({ error }: { error: ApiError }) {
  return (
    <p>
      {error.message}
      {error.correlationId ? (
        <span className="mt-1 block text-slate-400">Reference: {error.correlationId}</span>
      ) : null}
    </p>
  );
}

function LivenessCard({ result }: { result: CheckResult<HealthResponse> }) {
  if (result.state === "idle") {
    return <Card title="API" badge={<StatusBadge tone="neutral">Checking</StatusBadge>}>Waiting for a response…</Card>;
  }
  if (result.state === "error") {
    return (
      <Card title="API" badge={<StatusBadge tone="bad">Unreachable</StatusBadge>}>
        <ErrorDetail error={result.error} />
      </Card>
    );
  }
  return (
    <Card title="API" badge={<StatusBadge tone="ok">Up</StatusBadge>}>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        <dt className="text-slate-400">Service</dt>
        <dd>{result.data.service}</dd>
        <dt className="text-slate-400">Version</dt>
        <dd>{result.data.version}</dd>
      </dl>
    </Card>
  );
}

function ReadinessCard({ result }: { result: CheckResult<ReadinessResponse> }) {
  if (result.state === "idle") {
    return <Card title="Database" badge={<StatusBadge tone="neutral">Checking</StatusBadge>}>Waiting for a response…</Card>;
  }
  if (result.state === "error") {
    return (
      <Card title="Database" badge={<StatusBadge tone="warn">Unknown</StatusBadge>}>
        <ErrorDetail error={result.error} />
      </Card>
    );
  }
  const database = result.data.checks.database;
  return database === "ok" ? (
    <Card title="Database" badge={<StatusBadge tone="ok">Reachable</StatusBadge>}>
      The API can run queries against the database.
    </Card>
  ) : (
    <Card title="Database" badge={<StatusBadge tone="bad">Unavailable</StatusBadge>}>
      The API is running but cannot reach the database.
    </Card>
  );
}

export default function StatusPage() {
  useDocumentTitle("System status");
  const { health, readiness, overall, checkedAt, isRefreshing, refresh } = useServiceStatus();
  const summary = OVERALL[overall];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">System status</h1>
          <p className="mt-1 text-sm text-slate-400" aria-live="polite">
            {summary.detail}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge tone={summary.tone}>{summary.label}</StatusBadge>
          <button type="button" onClick={refresh} disabled={isRefreshing} className={BUTTON}>
            {isRefreshing ? "Checking…" : "Refresh"}
          </button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <LivenessCard result={health} />
        <ReadinessCard result={readiness} />
      </div>

      <p className="text-xs text-slate-400">
        {checkedAt ? `Last checked ${checkedAt.toLocaleTimeString()}.` : "Not checked yet."} This
        page refreshes automatically every 30 seconds.
      </p>
    </div>
  );
}
