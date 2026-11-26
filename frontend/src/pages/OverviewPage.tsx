import { useState } from "react";
import { Link } from "react-router";

import ActivityHeatmap from "../components/charts/ActivityHeatmap";
import AreaChart from "../components/charts/AreaChart";
import Donut from "../components/charts/Donut";
import DotMap from "../components/charts/DotMap";
import HBarList from "../components/charts/HBarList";
import MatrixHeatmap from "../components/charts/MatrixHeatmap";
import Radar from "../components/charts/Radar";
import ErrorNotice from "../components/ErrorNotice";
import { RefreshIcon } from "../components/hud/Icons";
import PageHeader from "../components/hud/PageHeader";
import Panel from "../components/hud/Panel";
import StatusLed from "../components/hud/StatusLed";
import LoadingNote from "../components/LoadingNote";
import { facetItems, mapMarkers, riskSlices, threatSeries, typeAxes } from "../components/overview/chartData";
import FocusDrawer, { type Focus, type FocusKind } from "../components/overview/FocusDrawer";
import IndicatorList from "../components/overview/IndicatorList";
import KpiTile from "../components/overview/KpiTile";
import ModulesPanel from "../components/overview/ModulesPanel";
import ProvidersPanel from "../components/overview/ProvidersPanel";
import { BUTTON, LINK, PRIMARY_BUTTON } from "../components/styles";
import { indicatorsHref } from "../features/intel/filters";
import { countryLabel } from "../features/overview/countries";
import { longDay, shortDay } from "../features/overview/dates";
import { describeTrend } from "../features/overview/trend";
import { formatIstTime } from "../features/time/ist";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useLiveResource } from "../hooks/useLiveResource";
import { getOverview } from "../services/intelService";
import type { FacetEntry, Overview } from "../types/intel";

// Module-level so its identity is stable between renders.
const loadOverview = (signal: AbortSignal) => getOverview(signal);

const CAPTION = "mb-3 text-xs text-ink-300";

function SkeletonTiles() {
  return (
    <div aria-hidden="true" className="grid grid-cols-1 gap-3 @lg:grid-cols-2 @deck:grid-cols-5">
      {[0, 1, 2, 3, 4].map((tile) => (
        <div key={tile} className="hud-panel h-32 animate-pulse rounded-ui" />
      ))}
    </div>
  );
}

function ScopeNote({ overview }: { overview: Overview }) {
  const { scope } = overview;
  return (
    <div className="space-y-1 text-xs text-ink-300">
      <p>
        Counts and risk bands cover every stored indicator. Trends cover the last {scope.series_days} days and
        hourly activity the last {scope.activity_days}, all in IST.
      </p>
      {scope.lookups_truncated ? (
        <p role="note" className="text-warn">
          <span aria-hidden="true">▲ </span>
          Trends use only the {scope.lookups_scanned.toLocaleString("en-US")} most recent lookups, so the oldest
          days may be undercounted.
        </p>
      ) : null}
      {scope.answers_truncated ? (
        <p role="note" className="text-warn">
          <span aria-hidden="true">▲ </span>
          Countries, malware families, techniques and tags use only the{" "}
          {scope.answers_scanned.toLocaleString("en-US")} most recent provider answers.
        </p>
      ) : null}
    </div>
  );
}

interface DeckProps {
  overview: Overview;
  focus: Focus | null;
  onFocus: (focus: Focus) => void;
}

function Deck({ overview, focus, onFocus }: DeckProps) {
  const { kpis, series } = overview;
  const { categories, series: lines } = threatSeries(overview);
  const selectedCountry = focus?.kind === "country" ? focus.entry.key : null;

  const open = (kind: FocusKind, entries: readonly FacetEntry[]) => (key: string) => {
    const entry = entries.find((candidate) => candidate.key === key);
    if (entry !== undefined) onFocus({ kind, entry });
  };

  return (
    <div className="space-y-4">
      <section aria-label="Key figures">
        <ul role="list" className="grid grid-cols-1 gap-3 @lg:grid-cols-2 @deck:grid-cols-5">
          <KpiTile
            code="KPI-01"
            label="Indicators tracked"
            value={kpis.total_indicators}
            note={`${kpis.new_indicators_24h} new in the last 24 hours`}
            trend={describeTrend(kpis.new_indicators_24h, kpis.new_indicators_prev_24h)}
            spark={series.map((point) => point.new_indicators)}
            to={indicatorsHref()}
          />
          <KpiTile
            code="KPI-02"
            label="Lookups, last 24 hours"
            value={kpis.lookups_24h}
            trend={describeTrend(kpis.lookups_24h, kpis.lookups_prev_24h)}
            spark={series.map((point) => point.lookups)}
            to={indicatorsHref()}
          />
          <KpiTile
            code="KPI-03"
            label="High-risk indicators"
            value={kpis.high_risk_indicators}
            tone="high"
            note="High and critical together"
            to={indicatorsHref({ classification: "high_risk", sort: "risk" })}
          />
          <KpiTile
            code="KPI-04"
            label="Critical indicators"
            value={kpis.critical_indicators}
            tone="crit"
            pulsing={kpis.critical_indicators > 0}
            note="Score above 80"
            to={indicatorsHref({ classification: "critical", sort: "risk" })}
          />
          <KpiTile
            code="KPI-05"
            label="Not assessed"
            value={kpis.not_assessed_indicators}
            tone="muted"
            note="No provider answered. That is not the same as clean."
            to={indicatorsHref({ classification: "not_assessed" })}
          />
        </ul>
      </section>

      {kpis.total_indicators === 0 ? (
        <Panel title="Nothing here yet" code="NIL">
          <p>No indicators have been investigated yet.</p>
          <Link to="/investigate" className={`${LINK} mt-2 inline-block`}>
            Investigate the first one
          </Link>
        </Panel>
      ) : (
        <div className="grid grid-cols-1 gap-4 @deck:grid-cols-12">
          <Panel title="Threat pulse" code="TRD" className="@deck:col-span-8">
            <p className={CAPTION}>Lookups per IST day, and how many of them ended High or Critical.</p>
            <AreaChart
              categories={categories}
              axisLabel={shortDay}
              titleOf={longDay}
              series={lines}
              label="Lookups and high-risk lookups per day"
              categoryName="Day"
              emptyText="No lookups yet."
            />
          </Panel>

          <Panel title="Risk posture" code="RSK" className="@deck:col-span-4">
            <Donut
              slices={riskSlices(overview)}
              noun="indicator"
              label="Indicators by risk band"
              centerCaption="indicators"
              emptyText="No indicators have been investigated yet."
            />
            <p className="mt-3 text-xs text-ink-300">
              Not assessed means no provider answered. It is not the same as clean.
            </p>
          </Panel>

          <Panel title="Provider-reported countries" code="GEO" className="@deck:col-span-8">
            <p className={CAPTION}>
              The country the providers report for an IP address. It is not where an attacker is, and domains,
              URLs and hashes have none.
            </p>
            <DotMap
              markers={mapMarkers(overview.countries)}
              selected={selectedCountry}
              onSelect={open("country", overview.countries)}
              noun="indicator"
              label="Provider-reported countries"
            />
          </Panel>

          <Panel title="Top countries" code="GEO" className="@deck:col-span-4">
            <HBarList
              items={facetItems(overview.countries, countryLabel)}
              label="Top provider-reported countries"
              noun="indicator"
              emptyText="No provider has reported a country yet."
              limit={8}
              onSelect={open("country", overview.countries)}
            />
          </Panel>

          <Panel title="Malware families" code="MAL" className="@deck:col-span-4">
            <HBarList
              items={facetItems(overview.malware_families)}
              label="Malware families"
              noun="indicator"
              emptyText="No malware family has been reported yet."
              onSelect={open("malware", overview.malware_families)}
            />
          </Panel>

          <Panel title="ATT&CK techniques" code="TTP" className="@deck:col-span-4">
            <HBarList
              items={facetItems(overview.attack_techniques)}
              label="ATT&CK techniques"
              noun="indicator"
              emptyText="No ATT&CK technique has been reported yet."
              onSelect={open("technique", overview.attack_techniques)}
            />
          </Panel>

          <Panel title="Provider tags" code="TAG" className="@deck:col-span-4">
            <HBarList
              items={facetItems(overview.tags)}
              label="Provider tags"
              noun="indicator"
              emptyText="No provider tag has been reported yet."
              onSelect={open("tag", overview.tags)}
            />
          </Panel>

          <Panel title="Indicator types by risk" code="MTX" className="@deck:col-span-7">
            <p className={CAPTION}>How many indicators of each type sit in each risk band.</p>
            <MatrixHeatmap rows={overview.matrix} />
          </Panel>

          <Panel title="Indicator mix" code="MIX" className="@deck:col-span-5">
            <Radar axes={typeAxes(overview)} noun="indicator" label="Indicators by type" />
          </Panel>

          <Panel title="Lookup activity" code="ACT" className="@deck:col-span-8">
            <p className={CAPTION}>Lookups per hour of the day (IST) over the last {overview.activity.length} days.</p>
            <ActivityHeatmap rows={overview.activity} />
          </Panel>

          <div className="@deck:col-span-4">
            <ProvidersPanel providers={overview.providers} />
          </div>

          <Panel
            title="Highest risk"
            code="TOP"
            className="@deck:col-span-6"
            actions={
              <Link to={indicatorsHref({ sort: "risk" })} className={`${LINK} text-xs`}>
                View all by risk
              </Link>
            }
          >
            <IndicatorList
              indicators={overview.top_risk}
              label="Highest-risk indicators"
              emptyText="No indicator has a risk score above zero yet."
            />
          </Panel>

          <Panel
            title="Latest investigations"
            code="NEW"
            className="@deck:col-span-6"
            actions={
              <Link to={indicatorsHref()} className={`${LINK} text-xs`}>
                View all indicators
              </Link>
            }
          >
            <IndicatorList
              indicators={overview.recent}
              label="Latest investigations"
              emptyText="Nothing has been investigated yet."
            />
          </Panel>
        </div>
      )}

      {kpis.total_indicators === 0 ? <ProvidersPanel providers={overview.providers} /> : null}
      <ModulesPanel />
      <ScopeNote overview={overview} />
    </div>
  );
}

export default function OverviewPage() {
  useDocumentTitle("Overview");
  const { state, refresh } = useLiveResource(loadOverview);
  const [focus, setFocus] = useState<Focus | null>(null);

  const ready = state.status === "ready" ? state : null;
  const refreshedAt = ready === null ? null : formatIstTime(new Date(ready.updatedAt));

  return (
    <div className="space-y-4">
      <PageHeader
        code="MOD-01 · COMMAND DECK"
        title="Overview"
        description="The indicators your team has investigated, and what the threat-intelligence providers said about them."
        actions={
          <>
            {ready !== null ? (
              <>
                <span
                  className="flex items-center gap-2 font-mono text-xs text-ink-200"
                  title="The figures update every minute"
                >
                  <StatusLed tone={ready.refreshError === null ? "cipher" : "warn"} pulsing={ready.refreshError === null} />
                  {ready.refreshError === null ? "Live" : "Stale"} · refreshed {refreshedAt}
                </span>
                <button
                  type="button"
                  onClick={ready.refreshing ? undefined : refresh}
                  aria-disabled={ready.refreshing || undefined}
                  className={BUTTON}
                >
                  <RefreshIcon className="size-4" />
                  {ready.refreshing ? "Refreshing…" : "Refresh"}
                </button>
              </>
            ) : null}
            <Link to="/investigate" className={PRIMARY_BUTTON}>
              Investigate an indicator
            </Link>
          </>
        }
      />

      {state.status === "loading" ? (
        <>
          <LoadingNote>Loading the overview…</LoadingNote>
          <SkeletonTiles />
        </>
      ) : null}
      {state.status === "error" ? <ErrorNotice error={state.error} onRetry={refresh} /> : null}
      {ready !== null && ready.refreshError !== null ? (
        <div role="alert" className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
          <span aria-hidden="true">▲ </span>
          The overview could not be refreshed. The figures below are from {refreshedAt}.
        </div>
      ) : null}
      {ready !== null ? <Deck overview={ready.data} focus={focus} onFocus={setFocus} /> : null}

      <FocusDrawer focus={focus} onClose={() => setFocus(null)} />
    </div>
  );
}
