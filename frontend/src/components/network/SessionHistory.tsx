import { useCallback, useState } from "react";

import { formatCount } from "../../features/intel/format";
import { describeSource } from "../../features/network/labels";
import { SESSIONS_PAGE_SIZE } from "../../features/network/paging";
import { formatIstTime } from "../../features/time/ist";
import { formatDuration } from "../../features/units";
import { useLiveResource } from "../../hooks/useLiveResource";
import { useNetworkRefreshOn } from "../../hooks/useNetworkRefreshOn";
import { listSessions } from "../../services/networkService";
import type { CaptureSession } from "../../types/network";
import DateTime from "../DateTime";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import Pagination from "../Pagination";
import { BUTTON, LABEL } from "../styles";
import DeleteSessionButton from "./DeleteSessionButton";
import NetworkErrorNotice from "./NetworkErrorNotice";
import { SessionStatusBadge } from "./StateBadges";

interface SessionHistoryProps {
  /** The session the page shows, so its row can say so. */
  selectedId: string | null;
  /** How often to read the list again: quickly while a session is changing. */
  intervalMs: number;
  /** Changes when the page asks for fresh data. */
  version: number;
  onSelect: (sessionId: string) => void;
  onDelete: (session: CaptureSession) => void;
  className?: string;
}

const COLUMNS = ["Source", "Status", "Started", "Duration", "Packets", "Alerts", "Actions"] as const;

interface RowProps {
  session: CaptureSession;
  selected: boolean;
  onSelect: (sessionId: string) => void;
  onDelete: (session: CaptureSession) => void;
}

function HistoryRow({ session, selected, onSelect, onDelete }: RowProps) {
  const source = describeSource(session);
  return (
    <tr className={`align-top transition hover:bg-cipher/5 ${selected ? "bg-cipher/10" : ""}`}>
      <th scope="row" className="px-4 py-3 text-left font-normal">
        <span className="block text-xs text-ink-300">{source.kind}</span>
        <span className="break-all font-mono text-xs text-ink-50">{source.name}</span>
      </th>
      <td className="px-4 py-3">
        <SessionStatusBadge status={session.status} />
      </td>
      <td className="px-4 py-3">
        <DateTime value={session.started_at} stacked />
      </td>
      <td className="px-4 py-3 font-mono text-xs tabular-nums">{formatDuration(session.duration_seconds)}</td>
      <td className="px-4 py-3 font-mono text-xs tabular-nums">{formatCount(session.packets_total)}</td>
      <td className="px-4 py-3 font-mono text-xs tabular-nums">{formatCount(session.alerts_total)}</td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            aria-label={`${selected ? "Viewing" : "View"} session ${source.name}`}
            aria-current={selected ? "true" : undefined}
            onClick={selected ? undefined : () => onSelect(session.id)}
            className={BUTTON}
          >
            {selected ? "Viewing" : "View"}
          </button>
          <DeleteSessionButton session={session} name={source.name} compact onDelete={() => onDelete(session)} />
        </div>
      </td>
    </tr>
  );
}

/** Every session of the signed-in analyst, newest first: pick one to look at, or delete it. */
export default function SessionHistory({
  selectedId,
  intervalMs,
  version,
  onSelect,
  onDelete,
  className,
}: SessionHistoryProps) {
  const [page, setPage] = useState(1);
  const load = useCallback(
    (signal: AbortSignal) =>
      listSessions({ limit: SESSIONS_PAGE_SIZE, offset: (page - 1) * SESSIONS_PAGE_SIZE }, signal),
    [page],
  );
  const { state, refresh } = useLiveResource(load, intervalMs);

  useNetworkRefreshOn(version, refresh);

  // Deleting the last session of the last page leaves that page empty: go back to the new last one.
  if (state.status === "ready" && state.data.items.length === 0 && state.data.total > 0 && page > 1) {
    setPage(Math.max(1, Math.ceil(state.data.total / SESSIONS_PAGE_SIZE)));
  }

  return (
    <Panel title="Session history" code="HIS-01" className={className}>
      <div className="space-y-4">
        {state.status === "loading" ? <LoadingNote>Loading sessions…</LoadingNote> : null}
        {state.status === "error" ? <NetworkErrorNotice error={state.error} onRetry={refresh} /> : null}
        {state.status === "ready" ? (
          <>
            {state.refreshError !== null ? (
              <p role="alert" className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
                <span aria-hidden="true">▲ </span>
                The session list could not be refreshed. It is from {formatIstTime(new Date(state.updatedAt))}.
              </p>
            ) : null}
            {state.data.items.length === 0 ? (
              <p className="py-6 text-center text-sm text-ink-200">
                No sessions yet. Start a live capture or analyse a PCAP file, and it will be listed here.
              </p>
            ) : (
              <div className="relative overflow-x-auto">
                <table className="w-full min-w-[46rem] text-left text-sm text-ink-100">
                  <caption className="sr-only">Capture sessions, newest first</caption>
                  <thead className="border-b border-ink-600 bg-ink-900/70">
                    <tr>
                      {COLUMNS.map((column) => (
                        <th key={column} scope="col" className={`px-4 py-3 ${LABEL}`}>
                          {column}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-700/60">
                    {state.data.items.map((session) => (
                      <HistoryRow
                        key={session.id}
                        session={session}
                        selected={session.id === selectedId}
                        onSelect={onSelect}
                        onDelete={onDelete}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pagination
              page={page}
              pageSize={SESSIONS_PAGE_SIZE}
              total={state.data.total}
              label="Session history pagination"
              onPageChange={setPage}
            />
          </>
        ) : null}
      </div>
    </Panel>
  );
}
