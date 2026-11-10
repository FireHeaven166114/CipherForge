import type { ReactNode } from "react";

import StatusBadge, { type Tone } from "../components/StatusBadge";
import type { CheckResult, OverallStatus } from "../features/status/overallStatus";
import { useServiceStatus } from "../hooks/useServiceStatus";
import type { ApiError } from "../services/apiClient";
import type { HealthResponse, ReadinessResponse } from "../types/api";

const OVERALL: Record<OverallStatus, { tone: Tone; label: string; detail: string }> = {
  checking: { tone: "neutral", label: "Checking", detail: "Contacting the API…" },
  operational: { tone: "ok", label: "Operational", detail: "The API is up and its database is reachable." },
  degraded: { tone: "warn", label: "Degraded", detail: "The API is up, but a dependency is not healthy." },
  down: { tone: "bad", label: "Down", detail: "The API cannot be reached." },
};

function Card({ title, badge, children }: { title: string; badge: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <div className="flex items-start justify-between gap-4">
        <h2 className="text-base font-semibold">{title}</h2>
        {badge}
      </div>
      <div className="mt-3 text-sm text-slate-300">{children}</div>
    </section>
  );
}

function ErrorDetail({ error }: { error: ApiError }) {
  return (
    <p>
      {error.message}
      {error.correlationId ? (
        <span className="mt-1 block text-slate-500">Reference: {error.correlationId}</span>
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
        <dt className="text-slate-500">Service</dt>
        <dd>{result.data.service}</dd>
        <dt className="text-slate-500">Version</dt>
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
          <button
            type="button"
            onClick={refresh}
            disabled={isRefreshing}
            className="rounded-md border border-slate-600 px-3 py-1.5 text-sm font-medium hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isRefreshing ? "Checking…" : "Refresh"}
          </button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <LivenessCard result={health} />
        <ReadinessCard result={readiness} />
      </div>

      <p className="text-xs text-slate-500">
        {checkedAt ? `Last checked ${checkedAt.toLocaleTimeString()}.` : "Not checked yet."} This
        page refreshes automatically every 30 seconds.
      </p>
    </div>
  );
}
