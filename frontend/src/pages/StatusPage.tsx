import Card from "../components/Card";
import PageHeader from "../components/hud/PageHeader";
import Panel from "../components/hud/Panel";
import StatusReactor from "../components/status/StatusReactor";
import StatusBadge, { type Tone } from "../components/StatusBadge";
import { BUTTON, LABEL } from "../components/styles";
import type { CheckResult, OverallStatus } from "../features/status/overallStatus";
import { formatIstTime } from "../features/time/ist";
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

const TONE_TEXT: Record<Tone, string> = {
  ok: "text-ok",
  warn: "text-warn",
  bad: "text-bad",
  neutral: "text-ink-100",
};

function ErrorDetail({ error }: { error: ApiError }) {
  return (
    <p>
      {error.message}
      {error.correlationId ? (
        <span className="mt-1 block font-mono text-xs text-ink-300">Reference: {error.correlationId}</span>
      ) : null}
    </p>
  );
}

function LivenessCard({ result }: { result: CheckResult<HealthResponse> }) {
  if (result.state === "idle") {
    return (
      <Card title="API" code="SYS-01" badge={<StatusBadge tone="neutral">Checking</StatusBadge>}>
        Waiting for a response…
      </Card>
    );
  }
  if (result.state === "error") {
    return (
      <Card title="API" code="SYS-01" badge={<StatusBadge tone="bad">Unreachable</StatusBadge>}>
        <ErrorDetail error={result.error} />
      </Card>
    );
  }
  return (
    <Card title="API" code="SYS-01" badge={<StatusBadge tone="ok">Up</StatusBadge>}>
      <dl className="grid grid-cols-[auto_1fr] items-baseline gap-x-6 gap-y-2">
        <dt className={LABEL}>Service</dt>
        <dd className="font-mono text-ink-50">{result.data.service}</dd>
        <dt className={LABEL}>Version</dt>
        <dd className="font-mono text-ink-50">{result.data.version}</dd>
      </dl>
    </Card>
  );
}

function ReadinessCard({ result }: { result: CheckResult<ReadinessResponse> }) {
  if (result.state === "idle") {
    return (
      <Card title="Database" code="SYS-02" badge={<StatusBadge tone="neutral">Checking</StatusBadge>}>
        Waiting for a response…
      </Card>
    );
  }
  if (result.state === "error") {
    return (
      <Card title="Database" code="SYS-02" badge={<StatusBadge tone="warn">Unknown</StatusBadge>}>
        <ErrorDetail error={result.error} />
      </Card>
    );
  }
  const database = result.data.checks.database;
  return database === "ok" ? (
    <Card title="Database" code="SYS-02" badge={<StatusBadge tone="ok">Reachable</StatusBadge>}>
      The API can run queries against the database.
    </Card>
  ) : (
    <Card title="Database" code="SYS-02" badge={<StatusBadge tone="bad">Unavailable</StatusBadge>}>
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
      <PageHeader code="MOD-04 · SYSTEM CORE" title="System status" />

      <Panel bodyClassName="p-6">
        <div className="flex flex-wrap items-center justify-center gap-x-10 gap-y-6">
          <StatusReactor
            tone={summary.tone}
            spinning={overall === "checking" || overall === "operational"}
          />
          {/* A basis, not flex-1: with no basis the text column never wraps, it is squeezed beside the ring. */}
          <div className="min-w-0 grow basis-56 space-y-3">
            <p className={LABEL}>Overall status</p>
            <p className={`text-4xl font-semibold tracking-tight ${TONE_TEXT[summary.tone]}`}>
              {summary.label}
            </p>
            <p className="text-sm text-ink-200" aria-live="polite">
              {summary.detail}
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 pt-1">
              <button
                type="button"
                onClick={isRefreshing ? undefined : refresh}
                aria-disabled={isRefreshing || undefined}
                className={BUTTON}
              >
                {isRefreshing ? "Checking…" : "Refresh"}
              </button>
              <p className="font-mono text-xs text-ink-300">
                {checkedAt ? `Last checked ${formatIstTime(checkedAt)}.` : "Not checked yet."} This
                page refreshes automatically every 30 seconds.
              </p>
            </div>
          </div>
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 @lg:grid-cols-2">
        <LivenessCard result={health} />
        <ReadinessCard result={readiness} />
      </div>
    </div>
  );
}
