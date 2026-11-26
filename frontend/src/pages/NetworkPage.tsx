import { useCallback, useState } from "react";

import { RefreshIcon } from "../components/hud/Icons";
import PageHeader from "../components/hud/PageHeader";
import StatusLed from "../components/hud/StatusLed";
import LoadingNote from "../components/LoadingNote";
import NetworkConsole from "../components/network/NetworkConsole";
import NetworkErrorNotice from "../components/network/NetworkErrorNotice";
import { BUTTON } from "../components/styles";
import { formatIstTime } from "../features/time/ist";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useNetworkStatus } from "../hooks/useNetworkStatus";

function SkeletonPanels() {
  return (
    <div aria-hidden="true" className="grid grid-cols-1 gap-4 @deck:grid-cols-12">
      <div className="hud-panel h-72 animate-pulse rounded-ui @deck:col-span-7" />
      <div className="hud-panel h-72 animate-pulse rounded-ui @deck:col-span-5" />
    </div>
  );
}

export default function NetworkPage() {
  useDocumentTitle("Network");
  const { state, refresh } = useNetworkStatus();
  // Counts the times fresh data was asked for, so every list on the page reads again.
  const [version, setVersion] = useState(0);

  const refreshAll = useCallback(() => {
    setVersion((value) => value + 1);
    refresh();
  }, [refresh]);

  const ready = state.status === "ready" ? state : null;
  const refreshedAt = ready === null ? null : formatIstTime(new Date(ready.updatedAt));

  return (
    <div className="space-y-4">
      <PageHeader
        code="MOD-05 · NETWORK MONITOR"
        title="Network"
        description="Watch the traffic of one network interface, or analyse a capture file, and see what the detection rules flagged. Packet contents are never stored."
        actions={
          ready !== null ? (
            <>
              <span
                className="flex items-center gap-2 font-mono text-xs text-ink-200"
                title="The capture status updates every two seconds while something is running, and every fifteen otherwise"
              >
                <StatusLed tone={ready.refreshError === null ? "cipher" : "warn"} pulsing={ready.refreshError === null} />
                {ready.refreshError === null ? "Live" : "Stale"} · refreshed {refreshedAt}
              </span>
              <button
                type="button"
                onClick={ready.refreshing ? undefined : refreshAll}
                aria-disabled={ready.refreshing || undefined}
                className={BUTTON}
              >
                <RefreshIcon className="size-4" />
                {ready.refreshing ? "Refreshing…" : "Refresh"}
              </button>
            </>
          ) : undefined
        }
      />

      {state.status === "loading" ? (
        <>
          <LoadingNote>Loading the network monitor…</LoadingNote>
          <SkeletonPanels />
        </>
      ) : null}
      {state.status === "error" ? <NetworkErrorNotice error={state.error} onRetry={refresh} /> : null}
      {ready !== null && ready.refreshError !== null ? (
        <div role="alert" className="rounded-ui border border-warn/50 bg-warn/10 p-3 text-sm text-warn">
          <span aria-hidden="true">▲ </span>
          The capture status could not be refreshed. What is shown is from {refreshedAt}.
        </div>
      ) : null}
      {ready !== null ? <NetworkConsole status={ready.data} version={version} onChanged={refreshAll} /> : null}
    </div>
  );
}
