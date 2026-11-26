import { useState } from "react";
import { useSearchParams } from "react-router";

import { statusPollInterval } from "../../features/network/polling";
import { parseSessionParam, resolveSessionId } from "../../features/network/session";
import { useApiResource } from "../../hooks/useApiResource";
import { useNetworkDelete } from "../../hooks/useNetworkDelete";
import { listRules } from "../../services/networkService";
import type { CaptureSession, NetworkStatus, SessionDetail } from "../../types/network";
import Panel from "../hud/Panel";
import { BUTTON } from "../styles";
import CaptureControl, { type CaptureOutcome } from "./CaptureControl";
import DeleteSessionDialog from "./DeleteSessionDialog";
import Notice from "./Notice";
import PcapUpload from "./PcapUpload";
import RulesPanel from "./RulesPanel";
import SessionHistory from "./SessionHistory";
import SessionWorkspace from "./SessionWorkspace";

interface NetworkConsoleProps {
  status: NetworkStatus;
  /** Changes when the page asks for fresh data. */
  version: number;
  /** Something changed on the server (a capture, an upload, a deletion): read everything again. */
  onChanged: () => void;
}

// Module-level so its identity is stable between renders.
const loadRules = (signal: AbortSignal) => listRules(signal);

function EmptyWorkspace() {
  return (
    <Panel title="Session" code="SES-01">
      <div className="space-y-2 py-2 text-sm text-ink-100">
        <p>No session is open yet.</p>
        <p className="text-ink-200">
          Start a live capture on one of the interfaces above, or analyse a PCAP or PCAPNG file. You can also
          open an earlier session from the history. The session&apos;s packets, flows, alerts and public
          addresses are shown here.
        </p>
      </div>
    </Panel>
  );
}

interface SelectionBarProps {
  live: boolean;
  onClear: () => void;
}

/** Says that the session on screen was picked, and offers the way back. */
function SelectionBar({ live, onClear }: SelectionBarProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-ui border border-cipher/30 bg-ink-900/60 px-4 py-3">
      <p className="text-sm text-ink-100">
        {live
          ? "You are looking at a session you picked, not at your live capture."
          : "You are looking at a session you picked."}
      </p>
      <button type="button" onClick={onClear} className={BUTTON}>
        {live ? "Back to the live capture" : "Clear selection"}
      </button>
    </div>
  );
}

/**
 * The console once the capture status is known: the controls, the session history, the session
 * on show and the rules. Which session is on show lives in the address (`?session=`), so a link
 * opens it directly and the back button steps through what the analyst looked at.
 */
export default function NetworkConsole({ status, version, onChanged }: NetworkConsoleProps) {
  const [params, setParams] = useSearchParams();
  // Sessions deleted here: status may name one for a moment longer, and it must not be loaded.
  const [removed, setRemoved] = useState<readonly string[]>([]);
  const [target, setTarget] = useState<CaptureSession | null>(null);
  const deletion = useNetworkDelete();
  const { state: rules, reload: reloadRules } = useApiResource(loadRules);

  const link = params.get("session");
  const requested = parseSessionParam(link);
  const live = status.session_id !== null && !removed.includes(status.session_id) ? status.session_id : null;
  const sessionId = resolveSessionId(requested, live);

  function showSession(id: string | null, replace: boolean) {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (id === null) next.delete("session");
        else next.set("session", id);
        return next;
      },
      { replace },
    );
  }

  function select(id: string) {
    if (id !== requested) showSession(id, false);
  }

  function handleCapture(outcome: CaptureOutcome) {
    // A capture that has just started is what to watch, not a session opened from the history.
    if (outcome === "started") showSession(null, true);
    onChanged();
  }

  function handleUploadFinished(session: SessionDetail) {
    if (session.status === "completed") select(session.id);
    onChanged();
  }

  function handleUploadStarted(session: SessionDetail) {
    select(session.id);
    onChanged();
  }

  function askDelete(session: CaptureSession) {
    deletion.reset();
    setTarget(session);
  }

  function cancelDelete() {
    deletion.reset();
    setTarget(null);
  }

  async function confirmDelete() {
    if (target === null) return;
    const gone = target.id;
    const done = await deletion.remove(gone);
    if (done === null) {
      // The answer may be that the session is still running, or already gone: show what is true.
      onChanged();
      return;
    }
    setTarget(null);
    setRemoved((ids) => [...ids, gone]);
    if (gone === requested) showSession(null, true);
    onChanged();
  }

  function clearSelection() {
    if (requested !== null) showSession(null, false);
    // Nothing was picked, so the live session itself cannot be shown: leave it out until status changes.
    else if (live !== null) setRemoved((ids) => [...ids, live]);
    onChanged();
  }

  const intervalMs = statusPollInterval(status);

  return (
    <div className="space-y-4">
      {link !== null && requested === null ? (
        <Notice tone="warn" title="That session link was not understood">
          <p>The address names a session in a form this page does not know, so it was ignored.</p>
        </Notice>
      ) : null}

      <div className="grid grid-cols-1 gap-4 @deck:grid-cols-12">
        <CaptureControl status={status} onSettled={handleCapture} className="@deck:col-span-7" />
        <PcapUpload
          analysis={status.analysis}
          onStarted={handleUploadStarted}
          onFinished={handleUploadFinished}
          onRefused={onChanged}
          onOpen={select}
          className="@deck:col-span-5"
        />
      </div>

      <SessionHistory
        selectedId={sessionId}
        intervalMs={intervalMs}
        version={version}
        onSelect={select}
        onDelete={askDelete}
      />

      {requested !== null && requested !== live ? (
        <SelectionBar live={live !== null} onClear={() => showSession(null, false)} />
      ) : null}

      {sessionId === null ? (
        <EmptyWorkspace />
      ) : (
        <SessionWorkspace
          key={sessionId}
          sessionId={sessionId}
          version={version}
          rules={rules}
          enrichmentEnabled={status.enrichment_enabled}
          onDelete={askDelete}
          onClear={clearSelection}
        />
      )}

      <RulesPanel state={rules} onRetry={reloadRules} enrichmentEnabled={status.enrichment_enabled} />

      <DeleteSessionDialog
        target={target}
        busy={deletion.busy}
        error={deletion.error}
        onConfirm={() => void confirmDelete()}
        onCancel={cancelDelete}
      />
    </div>
  );
}
