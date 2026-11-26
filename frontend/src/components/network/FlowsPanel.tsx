import { useCallback, useState } from "react";

import { formatCount } from "../../features/intel/format";
import {
  closeReasonLabel,
  countOf,
  formatEndpoint,
  formatFlags,
  protocolLabel,
} from "../../features/network/labels";
import { FLOWS_PAGE_SIZE } from "../../features/network/paging";
import { formatIstTime } from "../../features/time/ist";
import { formatBytes, formatDuration } from "../../features/units";
import { useLiveResource } from "../../hooks/useLiveResource";
import { useNetworkRefreshOn } from "../../hooks/useNetworkRefreshOn";
import { listFlows } from "../../services/networkService";
import type { Flow, SessionDetail } from "../../types/network";
import DateTime from "../DateTime";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import Pagination from "../Pagination";
import { LABEL } from "../styles";
import NetworkErrorNotice from "./NetworkErrorNotice";
import Notice from "./Notice";

interface FlowsPanelProps {
  session: Pick<SessionDetail, "id" | "status" | "flows_stored" | "flows_not_stored">;
  /** How often to read the list again: quickly while the session changes. */
  intervalMs: number;
  /** Changes when the page asks for fresh data. */
  version: number;
  className?: string;
}

const COLUMNS = [
  "Flow",
  "Protocol",
  "First seen",
  "Last seen",
  "Duration",
  "Packets out / in",
  "Data out / in",
  "TCP flags",
  "Ended by",
] as const;

function FlowRow({ flow }: { flow: Flow }) {
  return (
    <tr className="align-top transition hover:bg-cipher/5">
      <th scope="row" className="px-4 py-3 text-left font-normal text-ink-50">
        <span className="break-all font-mono text-xs">{formatEndpoint(flow.src_ip, flow.src_port)}</span>
        <span aria-hidden="true"> → </span>
        <span className="sr-only"> to </span>
        <span className="break-all font-mono text-xs">{formatEndpoint(flow.dst_ip, flow.dst_port)}</span>
      </th>
      <td className="px-4 py-3">{protocolLabel(flow.protocol)}</td>
      <td className="px-4 py-3">
        <DateTime value={flow.first_seen} stacked />
      </td>
      <td className="px-4 py-3">
        <DateTime value={flow.last_seen} stacked />
      </td>
      <td className="px-4 py-3 font-mono text-xs tabular-nums">{formatDuration(flow.duration_seconds)}</td>
      <td className="px-4 py-3 font-mono text-xs tabular-nums">
        {formatCount(flow.packets_out)} / {formatCount(flow.packets_in)}
      </td>
      <td className="px-4 py-3 font-mono text-xs tabular-nums">
        {formatBytes(flow.bytes_out)} / {formatBytes(flow.bytes_in)}
      </td>
      <td className="px-4 py-3 font-mono text-xs">{formatFlags(flow)}</td>
      <td className="px-4 py-3">{closeReasonLabel(flow.close_reason)}</td>
    </tr>
  );
}

/** The session's finished flows, a page at a time. */
export default function FlowsPanel({ session, intervalMs, version, className }: FlowsPanelProps) {
  const [page, setPage] = useState(1);
  const sessionId = session.id;
  const load = useCallback(
    (signal: AbortSignal) =>
      listFlows(sessionId, { limit: FLOWS_PAGE_SIZE, offset: (page - 1) * FLOWS_PAGE_SIZE }, signal),
    [sessionId, page],
  );
  const { state, refresh } = useLiveResource(load, intervalMs);

  useNetworkRefreshOn(version, refresh);
  // Flows are listed as they finish, so a change in how many are stored means there is more to read.
  useNetworkRefreshOn(`${session.status}:${session.flows_stored}`, refresh);

  return (
    <Panel title="Flows" code="SES-06" className={className}>
      <div className="space-y-4">
        <p className="text-xs text-ink-300">
          A flow is the packets of one conversation between two endpoints. It is listed once it ends: when a
          connection closes, goes quiet for too long, is closed early to make room, or is still open when
          the session ends. Flows still open are counted under Active flows but not listed yet. Out is from
          the source to the destination; in is the way back.
        </p>
        {session.flows_not_stored > 0 ? (
          <Notice tone="warn" title="Some finished flows are not listed">
            <p>
              {countOf(session.flows_not_stored, "finished flow")} went over the limit kept for one session.{" "}
              {session.flows_not_stored === 1 ? "It is" : "They are"} counted in the totals but not stored, so
              this table is incomplete.
            </p>
          </Notice>
        ) : null}

        {state.status === "loading" ? <LoadingNote>Loading flows…</LoadingNote> : null}
        {state.status === "error" ? <NetworkErrorNotice error={state.error} onRetry={refresh} /> : null}
        {state.status === "ready" ? (
          <>
            {state.refreshError !== null ? (
              <p role="alert" className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
                <span aria-hidden="true">▲ </span>
                The flows could not be refreshed. The table below is from {formatIstTime(new Date(state.updatedAt))}.
              </p>
            ) : null}
            {state.data.items.length === 0 ? (
              <p className="py-6 text-center text-sm text-ink-200">
                No finished flows to list yet.
              </p>
            ) : (
              <div
                className="relative overflow-x-auto"
                role="region"
                aria-label="Finished flows, scrolls sideways"
                tabIndex={0}
              >
                <table className="w-full min-w-[72rem] text-left text-sm text-ink-100">
                  <caption className="sr-only">Finished flows of this session</caption>
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
                    {state.data.items.map((flow) => (
                      <FlowRow key={flow.id} flow={flow} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <Pagination
              page={page}
              pageSize={FLOWS_PAGE_SIZE}
              total={state.data.total}
              label="Flows pagination"
              onPageChange={setPage}
            />
          </>
        ) : null}
      </div>
    </Panel>
  );
}
