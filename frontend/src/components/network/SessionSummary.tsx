import { formatCount } from "../../features/intel/format";
import { sessionCounters } from "../../features/network/counters";
import { describeSource, isSessionActive } from "../../features/network/labels";
import { describeErrorCode } from "../../features/network/messages";
import { formatBytes, formatDuration } from "../../features/units";
import type { CaptureSession, SessionDetail } from "../../types/network";
import ChipList from "../ChipList";
import DateTime from "../DateTime";
import FactList from "../FactList";
import Panel from "../hud/Panel";
import DeleteSessionButton from "./DeleteSessionButton";
import Notice from "./Notice";
import { SessionStatusBadge } from "./StateBadges";

interface SessionSummaryProps {
  session: SessionDetail;
  onDelete: (session: CaptureSession) => void;
  className?: string;
}

interface Tile {
  label: string;
  value: string;
  /** A short word under the figure when it needs attention. */
  note?: string;
}

function tiles(session: SessionDetail): Tile[] {
  const dropped = session.packets_dropped;
  return [
    { label: "Duration", value: formatDuration(session.duration_seconds) },
    { label: "Packets", value: formatCount(session.packets_total) },
    { label: "Data", value: formatBytes(session.bytes_total) },
    { label: "Active flows", value: formatCount(session.active_flows) },
    { label: "Flows seen", value: formatCount(session.flows_total) },
    { label: "Alerts", value: formatCount(session.alerts_total) },
    {
      label: "Packets dropped",
      value: formatCount(dropped),
      note: dropped > 0 ? "Some traffic was not analysed" : undefined,
    },
  ];
}

function ruleCounts(alertsByRule: Record<string, number>): string[] {
  return Object.entries(alertsByRule)
    .filter(([, count]) => count > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([rule, count]) => `${rule}: ${formatCount(count)}`);
}

function EndedNote({ session }: { session: SessionDetail }) {
  const mapped = describeErrorCode(session.error_code);
  if (mapped === null && session.message === null) return null;
  const failed = session.status === "failed" || session.status === "permission_denied";
  const extra = session.message !== null && session.message !== mapped?.message ? session.message : null;
  return (
    <Notice tone={failed ? "bad" : "warn"} title={mapped?.title ?? "This session reported a problem"}>
      {mapped !== null ? <p>{mapped.message}</p> : null}
      {extra !== null ? <p>{extra}</p> : null}
    </Notice>
  );
}

export default function SessionSummary({ session, onDelete, className }: SessionSummaryProps) {
  const source = describeSource(session);
  const active = isSessionActive(session.status);
  const byRule = ruleCounts(session.alerts_by_rule);
  const counters = sessionCounters(session);

  return (
    <Panel
      title="Session summary"
      code="SES-01"
      className={className}
      actions={
        <span className="flex flex-wrap items-center gap-2">
          <SessionStatusBadge status={session.status} />
          <DeleteSessionButton session={session} onDelete={() => onDelete(session)} />
        </span>
      }
    >
      <div className="space-y-4">
        <EndedNote session={session} />

        <dl className="grid grid-cols-[repeat(auto-fit,minmax(9.5rem,1fr))] gap-3">
          {tiles(session).map((tile) => (
            <div key={tile.label} className="rounded-control border border-white/10 bg-ink-900/60 p-3">
              <dt className="text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-ink-300">{tile.label}</dt>
              <dd className="mt-1 font-mono text-xl tabular-nums text-ink-50">{tile.value}</dd>
              {tile.note !== undefined ? (
                <dd className="mt-0.5 text-xs text-warn">
                  <span aria-hidden="true">▲ </span>
                  {tile.note}
                </dd>
              ) : null}
            </div>
          ))}
        </dl>

        <FactList
          facts={[
            {
              label: "Source",
              value: (
                <>
                  {source.kind}: <span className="break-all font-mono">{source.name}</span>
                </>
              ),
            },
            { label: "Capture started", value: <DateTime value={session.started_at} /> },
            {
              label: "Capture ended",
              value: <DateTime value={session.ended_at} fallback={active ? "Still running" : "Not recorded"} />,
            },
            { label: "First packet", value: <DateTime value={session.first_packet_at} fallback="No packet yet" /> },
            { label: "Last packet", value: <DateTime value={session.last_packet_at} fallback="No packet yet" /> },
            {
              label: "Alerts by rule",
              value: byRule.length === 0 ? null : <ChipList items={byRule} label="Alerts by rule" />,
            },
          ]}
        />

        <section aria-labelledby={`counters-${session.id}`}>
          <h3 id={`counters-${session.id}`} className="text-xs font-semibold uppercase tracking-[0.14em] text-ink-100">
            What the totals leave out
          </h3>
          <p className="mt-1 text-xs text-ink-300">
            These counters say how much of the traffic is not in the figures above. A zero is only
            what the monitor itself could see.
          </p>
          <dl className="mt-3 grid gap-x-6 gap-y-3 @split:grid-cols-2">
            {counters.map((counter) => (
              <div key={counter.key}>
                <dt className="flex items-baseline justify-between gap-3 text-ink-100">
                  <span>{counter.label}</span>
                  <span className={`font-mono tabular-nums ${counter.attention ? "text-warn" : "text-ink-50"}`}>
                    {counter.attention ? <span aria-hidden="true">▲ </span> : null}
                    {counter.display}
                  </span>
                </dt>
                <dd className="mt-0.5 text-xs text-ink-300">{counter.explanation}</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
    </Panel>
  );
}
