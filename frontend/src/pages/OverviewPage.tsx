import type { ReactNode } from "react";
import { Link } from "react-router";

import Card from "../components/Card";
import DistributionChart, { type DistributionRow } from "../components/DistributionChart";
import ErrorNotice from "../components/ErrorNotice";
import IndicatorTable from "../components/intel/IndicatorTable";
import LoadingNote from "../components/LoadingNote";
import StatusBadge from "../components/StatusBadge";
import { LINK, PRIMARY_BUTTON } from "../components/styles";
import { CLASSIFICATIONS_BY_SEVERITY, CLASSIFICATION_META } from "../features/intel/classification";
import { INDICATOR_TYPE_LABELS } from "../features/intel/labels";
import { useApiResource } from "../hooks/useApiResource";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { getStats, listIndicators } from "../services/intelService";
import { INDICATOR_TYPES, type Stats } from "../types/intel";

const RECENT_COUNT = 5;

// Module-level so their identity is stable between renders.
const loadStats = (signal: AbortSignal) => getStats(signal);
const loadRecent = (signal: AbortSignal) =>
  listIndicators({ sort: "recent", limit: RECENT_COUNT }, signal);

function classificationRows(stats: Stats): DistributionRow[] {
  return CLASSIFICATIONS_BY_SEVERITY.map((classification) => {
    const meta = CLASSIFICATION_META[classification];
    return {
      id: classification,
      label: meta.label,
      marker: meta.symbol,
      count: stats.by_classification[classification] ?? 0,
      fillClass: meta.bar,
    };
  });
}

function typeRows(stats: Stats): DistributionRow[] {
  return INDICATOR_TYPES.map((type) => ({
    id: type,
    label: INDICATOR_TYPE_LABELS[type],
    count: stats.by_type[type] ?? 0,
    fillClass: "fill-cyan-500",
  }));
}

function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-5">
      <dt className="text-sm text-slate-400">{label}</dt>
      <dd className="mt-1">
        <span className="block text-3xl font-semibold tabular-nums text-slate-50">{value}</span>
        {hint ? <span className="mt-1 block text-xs text-slate-400">{hint}</span> : null}
      </dd>
    </div>
  );
}

function StatsView({ stats }: { stats: Stats }) {
  const configured = stats.providers.filter((provider) => provider.configured);
  const unconfigured = stats.providers.filter((provider) => !provider.configured);

  return (
    <div className="space-y-6">
      {configured.length === 0 ? (
        <div role="note" className="rounded-lg border border-amber-700 bg-amber-950 p-4 text-sm text-amber-100">
          <p className="flex items-center gap-2 font-semibold">
            <span aria-hidden="true">▲</span>
            No threat-intelligence provider is configured
          </p>
          <p className="mt-1">
            Every investigation will come back as &ldquo;Not assessed&rdquo; until an administrator
            adds a provider API key on the server.
          </p>
        </div>
      ) : null}

      <dl className="grid gap-4 sm:grid-cols-3">
        <Stat label="Indicators stored" value={stats.total_indicators} />
        <Stat label="Lookups in the last 24 hours" value={stats.lookups_last_24h} />
        <Stat
          label="Providers configured"
          value={`${configured.length} of ${stats.providers.length}`}
          hint={
            unconfigured.length > 0
              ? `Not configured: ${unconfigured.map((provider) => provider.display_name).join(", ")}`
              : undefined
          }
        />
      </dl>

      {stats.total_indicators === 0 ? (
        <Card title="Indicators">
          <p>No indicators have been investigated yet.</p>
          <Link to="/investigate" className={`${LINK} mt-2 inline-block`}>
            Investigate the first one
          </Link>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card title="Indicators by classification">
            <DistributionChart rows={classificationRows(stats)} total={stats.total_indicators} />
            <p className="mt-3 text-xs text-slate-400">
              Informational includes indicators that no provider has assessed yet, because those
              score 0.
            </p>
          </Card>
          <Card title="Indicators by type">
            <DistributionChart rows={typeRows(stats)} total={stats.total_indicators} />
          </Card>
        </div>
      )}

      <Card title="Threat-intelligence providers">
        <ul role="list" className="divide-y divide-slate-800">
          {stats.providers.map((provider) => (
            <li
              key={provider.name}
              className="flex flex-wrap items-center justify-between gap-2 py-2 first:pt-0 last:pb-0"
            >
              <div>
                <p className="font-medium text-slate-100">{provider.display_name}</p>
                <p className="text-xs text-slate-400">
                  Handles {provider.supported_types.map((type) => INDICATOR_TYPE_LABELS[type]).join(", ")}
                </p>
              </div>
              <StatusBadge tone={provider.configured ? "ok" : "warn"}>
                {provider.configured ? "Configured" : "Not configured"}
              </StatusBadge>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-xs text-slate-400">
          Configured providers receive the indicators you investigate.
        </p>
      </Card>
    </div>
  );
}

export default function OverviewPage() {
  useDocumentTitle("Overview");
  const stats = useApiResource(loadStats);
  const recent = useApiResource(loadRecent);

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="mt-1 text-sm text-slate-400">
            The indicators your team has investigated, and what CipherForge knows about them.
          </p>
        </div>
        <Link to="/investigate" className={PRIMARY_BUTTON}>
          Investigate an indicator
        </Link>
      </div>

      {stats.state.status === "loading" ? <LoadingNote>Loading statistics…</LoadingNote> : null}
      {stats.state.status === "error" ? (
        <ErrorNotice error={stats.state.error} onRetry={stats.reload} />
      ) : null}
      {stats.state.status === "success" ? <StatsView stats={stats.state.data} /> : null}

      <section aria-labelledby="recent-heading">
        <div className="flex flex-wrap items-baseline justify-between gap-4">
          <h2 id="recent-heading" className="text-lg font-semibold tracking-tight">
            Recently investigated
          </h2>
          <Link to="/indicators" className={LINK}>
            View all indicators
          </Link>
        </div>
        <div className="mt-3">
          {recent.state.status === "loading" ? (
            <LoadingNote>Loading recent indicators…</LoadingNote>
          ) : null}
          {recent.state.status === "error" ? (
            <ErrorNotice error={recent.state.error} onRetry={recent.reload} />
          ) : null}
          {recent.state.status === "success" ? (
            recent.state.data.items.length === 0 ? (
              <p className="text-sm text-slate-300">Nothing has been investigated yet.</p>
            ) : (
              <IndicatorTable
                indicators={recent.state.data.items}
                caption="The most recently investigated indicators"
              />
            )
          ) : null}
        </div>
      </section>
    </div>
  );
}
