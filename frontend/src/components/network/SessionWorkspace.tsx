import { formatIstTime } from "../../features/time/ist";
import type { ResourceState } from "../../hooks/useApiResource";
import { useNetworkRefreshOn } from "../../hooks/useNetworkRefreshOn";
import { useNetworkSession } from "../../hooks/useNetworkStatus";
import type { CaptureSession, DetectionRule } from "../../types/network";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import { BUTTON } from "../styles";
import AlertsPanel from "./AlertsPanel";
import ExternalIpsPanel from "./ExternalIpsPanel";
import FlowsPanel from "./FlowsPanel";
import NetworkErrorNotice from "./NetworkErrorNotice";
import ProtocolPanel from "./ProtocolPanel";
import SessionSummary from "./SessionSummary";
import TopTalkers from "./TopTalkers";

interface SessionWorkspaceProps {
  sessionId: string;
  /** Changes when the page asks for fresh data. */
  version: number;
  rules: ResourceState<DetectionRule[]>;
  enrichmentEnabled: boolean;
  onDelete: (session: CaptureSession) => void;
  /** Lets the analyst leave a session that cannot be shown (it does not exist, or is not theirs). */
  onClear: () => void;
}

function SkeletonPanels() {
  return (
    <div aria-hidden="true" className="grid grid-cols-1 gap-4 @deck:grid-cols-12">
      <div className="hud-panel h-40 animate-pulse rounded-ui @deck:col-span-12" />
      <div className="hud-panel h-56 animate-pulse rounded-ui @deck:col-span-5" />
      <div className="hud-panel h-56 animate-pulse rounded-ui @deck:col-span-7" />
    </div>
  );
}

/**
 * Everything the console knows about one session: the summary, the traffic mix, the alerts, the
 * public addresses and the flows. Mount it with the session id as its key, so a different session
 * starts from a clean slate.
 */
export default function SessionWorkspace({
  sessionId,
  version,
  rules,
  enrichmentEnabled,
  onDelete,
  onClear,
}: SessionWorkspaceProps) {
  const { resource, intervalMs } = useNetworkSession(sessionId);
  const { state, refresh } = resource;

  useNetworkRefreshOn(version, refresh);

  if (state.status === "loading") {
    return (
      <div className="space-y-4">
        <LoadingNote>Loading the session…</LoadingNote>
        <SkeletonPanels />
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <Panel title="Session" code="SES-01">
        <div className="space-y-3">
          <NetworkErrorNotice error={state.error} onRetry={refresh} />
          <button type="button" onClick={onClear} className={BUTTON}>
            Clear selection
          </button>
        </div>
      </Panel>
    );
  }

  const session = state.data;
  return (
    <div className="space-y-4">
      {state.refreshError !== null ? (
        <div role="alert" className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
          <span aria-hidden="true">▲ </span>
          The session could not be refreshed. The figures below are from {formatIstTime(new Date(state.updatedAt))}.
        </div>
      ) : null}
      <div className="grid grid-cols-1 gap-4 @deck:grid-cols-12">
        <SessionSummary session={session} onDelete={onDelete} className="@deck:col-span-12" />
        <ProtocolPanel protocols={session.protocols} className="@deck:col-span-5" />
        <TopTalkers
          sources={session.top_sources}
          destinations={session.top_destinations}
          truncated={session.talkers_truncated}
          className="@deck:col-span-7"
        />
        <AlertsPanel
          session={session}
          intervalMs={intervalMs}
          version={version}
          rules={rules}
          enrichmentEnabled={enrichmentEnabled}
          onEnriched={refresh}
          className="@deck:col-span-12"
        />
        <ExternalIpsPanel session={session} className="@deck:col-span-12" />
        <FlowsPanel session={session} intervalMs={intervalMs} version={version} className="@deck:col-span-12" />
      </div>
    </div>
  );
}
